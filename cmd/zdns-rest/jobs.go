package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns/v2/src/zdns"
)

// Job metrics
var (
	jobsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_jobs_total",
			Help: "Total number of jobs created",
		},
		[]string{"status"},
	)

	jobDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "zdns_job_duration_seconds",
			Help:    "Job processing duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"module"},
	)

	jobsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "zdns_jobs_active",
			Help: "Number of currently active jobs",
		},
	)
)

// JobStatus represents the status of a job
type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
	JobCancelled JobStatus = "cancelled"
)

// jobRetention is how long finished jobs are kept before being cleaned up
const jobRetention = time.Hour

// jobCleanupInterval is how often old finished jobs are removed
const jobCleanupInterval = 10 * time.Minute

// Job represents an async DNS lookup job
type Job struct {
	ID          string                 `json:"id"`
	Status      JobStatus              `json:"status"`
	Module      string                 `json:"module"`
	Queries     []string               `json:"queries"`
	Results     []string               `json:"results,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Progress    int                    `json:"progress"`
	Total       int                    `json:"total"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Nameserver  string                 `json:"nameserver,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// Internal fields
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// JobManager manages async DNS lookup jobs
type JobManager struct {
	mu          sync.RWMutex
	jobs        map[string]*Job
	workerCount int
	jobQueue    chan *Job
	wg          sync.WaitGroup
	shutdown    chan struct{}
	stopOnce    sync.Once

	// cfg points at the server's immutable config snapshot; cb is the
	// server's circuit breaker (nil when the feature is disabled).
	cfg    *GlobalConf
	cb     *CircuitBreaker
	engine *lookupEngine
}

// NewJobManager creates a new job manager with the specified worker count.
// cfg must be a stable config snapshot that outlives the manager.
func NewJobManager(workerCount int, cfg *GlobalConf, cb *CircuitBreaker, engine *lookupEngine) *JobManager {
	if workerCount <= 0 {
		workerCount = 10
	}
	if cfg == nil {
		cfg = &GlobalConf{}
	}

	jm := &JobManager{
		jobs:        make(map[string]*Job),
		workerCount: workerCount,
		jobQueue:    make(chan *Job, 1000),
		shutdown:    make(chan struct{}),
		cfg:         cfg,
		cb:          cb,
		engine:      engine,
	}

	// Start workers
	for i := 0; i < workerCount; i++ {
		jm.wg.Add(1)
		go jm.worker(i)
	}

	// Periodically remove finished jobs so the job map does not grow forever
	go func() {
		ticker := time.NewTicker(jobCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-jm.shutdown:
				return
			case <-ticker.C:
				if n := jm.CleanupOldJobs(jobRetention); n > 0 {
					log.Debugf("Cleaned up %d finished jobs", n)
				}
			}
		}
	}()

	return jm
}

// Stop shuts down the job manager. Pending and running jobs get their
// contexts cancelled so in-flight DNS queries abort; then workers are
// stopped. Safe to call more than once.
func (jm *JobManager) Stop() {
	jm.stopOnce.Do(func() {
		close(jm.shutdown)

		// Cancel every unfinished job — their contexts are detached from the
		// server lifecycle (30min Background timeout) and would otherwise run
		// to completion during shutdown.
		jm.mu.RLock()
		for _, job := range jm.jobs {
			job.mu.RLock()
			unfinished := job.Status == JobPending || job.Status == JobRunning
			job.mu.RUnlock()
			if unfinished {
				job.cancel()
			}
		}
		jm.mu.RUnlock()
	})
	jm.wg.Wait()
}

// worker processes jobs from the queue
func (jm *JobManager) worker(id int) {
	defer jm.wg.Done()

	log.Debugf("Job worker %d started", id)
	defer log.Debugf("Job worker %d stopped", id)

	for {
		// Prefer shutdown over draining the queue: when both are ready,
		// select picks randomly and would keep dequeuing jobs while the
		// server is trying to exit.
		select {
		case <-jm.shutdown:
			return
		default:
		}
		select {
		case job := <-jm.jobQueue:
			if job != nil {
				jm.processJob(job)
			}
		case <-jm.shutdown:
			return
		}
	}
}

// processJob executes a DNS lookup job
func (jm *JobManager) processJob(job *Job) {
	// A panic inside zdns (or our handlers) must not take down the worker
	// goroutine or the process — mark the job failed instead.
	defer func() {
		if rec := recover(); rec != nil {
			log.WithFields(log.Fields{
				"job_id": job.ID,
				"module": job.Module,
				"panic":  rec,
			}).Error("Panic while processing job")
			job.mu.Lock()
			job.Status = JobFailed
			job.Error = fmt.Sprintf("internal error: %v", rec)
			now := time.Now()
			job.CompletedAt = &now
			job.mu.Unlock()
			jobsTotal.WithLabelValues("failed").Inc()
		}
	}()

	job.mu.Lock()
	if job.Status == JobCancelled {
		// Job was cancelled while still in the queue
		job.mu.Unlock()
		jobsTotal.WithLabelValues("cancelled").Inc()
		return
	}
	job.Status = JobRunning
	now := time.Now()
	job.StartedAt = &now
	job.mu.Unlock()

	// Release the job context resources once processing finishes
	defer job.cancel()

	jobsActive.Inc()
	defer jobsActive.Dec()

	log.WithFields(log.Fields{
		"job_id": job.ID,
		"module": job.Module,
		"count":  len(job.Queries),
	}).Info("Starting job")

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		jobDuration.WithLabelValues(job.Module).Observe(duration)
	}()

	// The server's config snapshot is immutable; per-job variation is the
	// optional nameserver override.
	if _, ok := jm.engine.modules[job.Module]; !ok {
		job.mu.Lock()
		job.Status = JobFailed
		job.Error = "Invalid lookup module: " + job.Module
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("failed").Inc()
		return
	}

	// Check circuit breaker before doing any work
	if jm.cfg.CircuitBreakerEnabled && !jm.cb.CanExecute() {
		job.mu.Lock()
		job.Status = JobFailed
		job.Error = ErrCircuitBreakerOpen.Message
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("failed").Inc()
		return
	}

	// Create input from queries
	queries := make([]string, len(job.Queries))
	copy(queries, job.Queries)

	collector := NewOrderedResultCollector()

	// Check for cancellation
	select {
	case <-job.ctx.Done():
		job.mu.Lock()
		job.Status = JobCancelled
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("cancelled").Inc()
		return
	default:
	}

	cache := GetCache()
	uncachedQueries := make([]string, 0, len(queries))
	for _, query := range queries {
		select {
		case <-job.ctx.Done():
			job.mu.Lock()
			job.Status = JobCancelled
			now := time.Now()
			job.CompletedAt = &now
			job.mu.Unlock()
			jobsTotal.WithLabelValues("cancelled").Inc()
			return
		default:
		}

		if cache != nil && cache.enabled {
			if entry := cache.Get(job.Module, query, job.Nameserver, false); entry != nil {
				collector.Add(query, entry.Result)
				job.mu.Lock()
				job.Progress++
				job.mu.Unlock()
				continue
			}
		}

		uncachedQueries = append(uncachedQueries, query)
	}

	if len(uncachedQueries) > 0 {
		var ns *zdns.NameServer
		if job.Nameserver != "" {
			var err error
			ns, err = parseNameServer(job.Nameserver)
			if err != nil {
				job.mu.Lock()
				job.Status = JobFailed
				job.Error = fmt.Sprintf("Invalid nameserver: %v", err)
				now := time.Now()
				job.CompletedAt = &now
				job.mu.Unlock()
				jobsTotal.WithLabelValues("failed").Inc()
				return
			}
		}

		results := make(chan string)
		sink := &resultSink{
			requestID:  job.ID,
			module:     job.Module,
			nameserver: job.Nameserver,
			collector:  collector,
			start:      time.Now(),
			onResult: func() {
				job.mu.Lock()
				job.Progress++
				job.mu.Unlock()
			},
		}
		var outWG sync.WaitGroup
		outWG.Add(1)
		go func() {
			defer outWG.Done()
			sink.consume(results)
		}()

		// job.ctx cancels mid-query — v2 checks the context per network call.
		if err := jm.engine.executeQueries(job.ctx, job.Module, uncachedQueries, ns, results); err != nil {
			outWG.Wait()
			jm.cb.recordOutcome(false)
			job.mu.Lock()
			job.Status = JobFailed
			job.Error = fmt.Sprintf("Lookup execution failed: %v", err)
			now := time.Now()
			job.CompletedAt = &now
			job.mu.Unlock()
			jobsTotal.WithLabelValues("failed").Inc()
			return
		}
		outWG.Wait()
	}

	jm.cb.recordOutcome(true)

	select {
	case <-job.ctx.Done():
		job.mu.Lock()
		job.Status = JobCancelled
		now := time.Now()
		job.CompletedAt = &now
		job.Results = collector.Ordered(queries)
		job.mu.Unlock()
		jobsTotal.WithLabelValues("cancelled").Inc()
		return
	default:
	}

	results := collector.Ordered(queries)

	job.mu.Lock()
	if job.Status == JobCancelled {
		// CancelJob raced with completion
		job.Results = results
		now = time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("cancelled").Inc()
		return
	}
	job.Status = JobCompleted
	job.Results = results
	now = time.Now()
	job.CompletedAt = &now
	job.mu.Unlock()

	jobsTotal.WithLabelValues("completed").Inc()

	log.WithFields(log.Fields{
		"job_id":   job.ID,
		"module":   job.Module,
		"count":    len(job.Queries),
		"duration": time.Since(startTime),
	}).Info("Job completed")
}

// SubmitJob creates and queues a new job
func (jm *JobManager) SubmitJob(module string, queries []string, nameserver string) *Job {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

	job := &Job{
		ID:         generateJobID(),
		Status:     JobPending,
		Module:     module,
		Queries:    queries,
		Total:      len(queries),
		CreatedAt:  time.Now(),
		Nameserver: nameserver,
		ctx:        ctx,
		cancel:     cancel,
		Metadata:   make(map[string]interface{}),
	}

	jm.mu.Lock()
	jm.jobs[job.ID] = job
	jm.mu.Unlock()

	jobsTotal.WithLabelValues("created").Inc()

	// Queue the job
	select {
	case jm.jobQueue <- job:
		log.WithFields(log.Fields{
			"job_id": job.ID,
			"module": module,
			"count":  len(queries),
		}).Info("Job submitted")
	default:
		job.cancel()
		job.mu.Lock()
		job.Status = JobFailed
		job.Error = "Job queue is full"
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("failed").Inc()
	}

	return job
}

// GetJob retrieves a job by ID
func (jm *JobManager) GetJob(id string) *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.jobs[id]
}

// jobSnapshot is a consistent point-in-time copy of a Job's mutable fields.
type jobSnapshot struct {
	Status      JobStatus
	Progress    int
	Total       int
	Error       string
	Metadata    map[string]interface{}
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// snapshot copies the mutable fields under the job lock; ID/Module/Queries
// are immutable and safe to read directly.
func (j *Job) snapshot() jobSnapshot {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return jobSnapshot{
		Status:      j.Status,
		Progress:    j.Progress,
		Total:       j.Total,
		Error:       j.Error,
		Metadata:    j.Metadata,
		CreatedAt:   j.CreatedAt,
		StartedAt:   j.StartedAt,
		CompletedAt: j.CompletedAt,
	}
}

// GetJobStatus returns the current status of a job
func (jm *JobManager) GetJobStatus(id string) (JobStatus, int, int, error) {
	job := jm.GetJob(id)
	if job == nil {
		return "", 0, 0, errors.New("job not found")
	}

	snap := job.snapshot()
	return snap.Status, snap.Progress, snap.Total, nil
}

// GetJobResults returns the results of a completed job
func (jm *JobManager) GetJobResults(id string) ([]string, error) {
	job := jm.GetJob(id)
	if job == nil {
		return nil, errors.New("job not found")
	}

	job.mu.RLock()
	defer job.mu.RUnlock()

	if job.Status != JobCompleted {
		return nil, fmt.Errorf("job is not completed: %s", job.Status)
	}

	results := make([]string, len(job.Results))
	copy(results, job.Results)
	return results, nil
}

// CancelJob cancels a running or pending job
func (jm *JobManager) CancelJob(id string) error {
	job := jm.GetJob(id)
	if job == nil {
		return errors.New("job not found")
	}

	job.mu.Lock()
	defer job.mu.Unlock()

	if job.Status != JobPending && job.Status != JobRunning {
		return fmt.Errorf("cannot cancel job with status: %s", job.Status)
	}

	// Mark the job cancelled; the worker records the metric when it observes
	// the cancellation (or a pending job is dequeued).
	job.cancel()
	job.Status = JobCancelled
	now := time.Now()
	job.CompletedAt = &now

	return nil
}

// ListJobs returns a list of all jobs (for admin/debugging)
func (jm *JobManager) ListJobs() []*Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	jobs := make([]*Job, 0, len(jm.jobs))
	for _, job := range jm.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

// CleanupOldJobs removes jobs older than the specified duration
func (jm *JobManager) CleanupOldJobs(maxAge time.Duration) int {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, job := range jm.jobs {
		job.mu.RLock()
		created := job.CreatedAt
		completed := job.CompletedAt
		status := job.Status
		job.mu.RUnlock()

		// Remove completed/failed/cancelled jobs older than maxAge
		if status == JobCompleted || status == JobFailed || status == JobCancelled {
			if completed != nil && completed.Before(cutoff) {
				delete(jm.jobs, id)
				removed++
			} else if completed == nil && created.Before(cutoff) {
				delete(jm.jobs, id)
				removed++
			}
		}
	}

	return removed
}

// generateJobID generates a unique job ID
var jobIDCounter uint64

func generateJobID() string {
	id := atomic.AddUint64(&jobIDCounter, 1)
	return fmt.Sprintf("job-%d-%d", time.Now().Unix(), id)
}

// HTTP Handlers for job API

// createJobRequest handles POST /jobs
func (s *Server) createJobRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module  string   `json:"module"`
		Queries []string `json:"queries"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			ErrorResponse(w, ErrRequestTooLarge, "")
		} else {
			ErrorResponse(w, ErrDecodeRequest, err.Error())
		}
		return
	}

	module, ok := s.validateLookupParams(w, req.Module, len(req.Queries))
	if !ok {
		return
	}
	req.Module = module

	// Validate domains
	for _, q := range req.Queries {
		if !validateDomain(q) {
			ErrorResponse(w, ErrInvalidDomain, q)
			return
		}
	}

	nameserver := ""
	if len(s.cfg.NameServers) > 0 {
		nameserver = s.cfg.NameServers[0]
	}

	job := s.jm.SubmitJob(req.Module, req.Queries, nameserver)

	job.mu.RLock()
	status := job.Status
	job.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":     job.ID,
		"status":     status,
		"created_at": job.CreatedAt,
	})
}

// getJobRequest handles GET /jobs/{job_id}
func (s *Server) getJobRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]

	job := s.jm.GetJob(jobID)
	if job == nil {
		ErrorResponse(w, ErrJobNotFound, "")
		return
	}

	snap := job.snapshot()
	response := struct {
		ID          string                 `json:"id"`
		Status      JobStatus              `json:"status"`
		Module      string                 `json:"module"`
		Total       int                    `json:"total"`
		Progress    int                    `json:"progress"`
		CreatedAt   time.Time              `json:"created_at"`
		StartedAt   *time.Time             `json:"started_at,omitempty"`
		CompletedAt *time.Time             `json:"completed_at,omitempty"`
		Error       string                 `json:"error,omitempty"`
		Metadata    map[string]interface{} `json:"metadata,omitempty"`
	}{
		ID:          job.ID,
		Status:      snap.Status,
		Module:      job.Module,
		Total:       snap.Total,
		Progress:    snap.Progress,
		CreatedAt:   snap.CreatedAt,
		StartedAt:   snap.StartedAt,
		CompletedAt: snap.CompletedAt,
		Error:       snap.Error,
		Metadata:    snap.Metadata,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// getJobResultsRequest handles GET /jobs/{job_id}/results
func (s *Server) getJobResultsRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]

	results, err := s.jm.GetJobResults(jobID)
	if err != nil {
		job := s.jm.GetJob(jobID)
		if job != nil {
			snap := job.snapshot()

			if snap.Status == JobPending || snap.Status == JobRunning {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				if err := json.NewEncoder(w).Encode(map[string]interface{}{
					"status":   snap.Status,
					"progress": snap.Progress,
					"total":    snap.Total,
					"message":  "Job is still processing",
				}); err != nil {
					log.Errorf("Error encoding JSON response: %v", err)
				}
				return
			}

			detail := string(snap.Status)
			if snap.Error != "" {
				detail = snap.Error
			}
			ErrorResponse(w, ErrJobProcessing, detail)
			return
		}
		ErrorResponse(w, ErrJobNotFound, "")
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, result := range results {
		_, _ = w.Write([]byte(result + "\n"))
	}
}

// cancelJobRequest handles DELETE /jobs/{job_id}
func (s *Server) cancelJobRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]

	if err := s.jm.CancelJob(jobID); err != nil {
		ErrorResponse(w, ErrJobProcessing, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    1000,
		"message": "Job cancelled",
	})
}

// listJobsRequest handles GET /jobs (admin/debug endpoint)
func (s *Server) listJobsRequest(w http.ResponseWriter, r *http.Request) {
	jobs := s.jm.ListJobs()

	response := make([]map[string]interface{}, 0, len(jobs))
	for _, job := range jobs {
		snap := job.snapshot()
		response = append(response, map[string]interface{}{
			"id":       job.ID,
			"status":   snap.Status,
			"module":   job.Module,
			"progress": snap.Progress,
			"total":    snap.Total,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
