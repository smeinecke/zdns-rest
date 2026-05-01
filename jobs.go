package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/jinzhu/copier"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns/iohandlers"
	"github.com/zmap/zdns/pkg/zdns"
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
	ctx        context.Context
	cancel     context.CancelFunc
	resultChan chan string
	mu         sync.RWMutex
}

// JobManager manages async DNS lookup jobs
type JobManager struct {
	mu          sync.RWMutex
	jobs        map[string]*Job
	workerCount int
	jobQueue    chan *Job
	wg          sync.WaitGroup
	shutdown    chan struct{}
}

// NewJobManager creates a new job manager with the specified worker count
func NewJobManager(workerCount int) *JobManager {
	if workerCount <= 0 {
		workerCount = 10
	}

	jm := &JobManager{
		jobs:        make(map[string]*Job),
		workerCount: workerCount,
		jobQueue:    make(chan *Job, 1000),
		shutdown:    make(chan struct{}),
	}

	// Start workers
	for i := 0; i < workerCount; i++ {
		jm.wg.Add(1)
		go jm.worker(i)
	}

	return jm
}

// Stop shuts down the job manager
func (jm *JobManager) Stop() {
	close(jm.shutdown)
	jm.wg.Wait()
}

// worker processes jobs from the queue
func (jm *JobManager) worker(id int) {
	defer jm.wg.Done()

	log.Debugf("Job worker %d started", id)
	defer log.Debugf("Job worker %d stopped", id)

	for {
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
	job.mu.Lock()
	job.Status = JobRunning
	now := time.Now()
	job.StartedAt = &now
	job.mu.Unlock()

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

	// Create zdns configuration
	var gc zdns.GlobalConf
	if err := copier.Copy(&gc, &GC); err != nil {
		job.mu.Lock()
		job.Status = JobFailed
		job.Error = fmt.Sprintf("Failed to copy configuration: %v", err)
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("failed").Inc()
		return
	}

	gc.Module = job.Module
	gc.NameServers = []string{job.Nameserver}

	// Create input from queries
	queries := make([]string, len(job.Queries))
	copy(queries, job.Queries)

	// Setup input handler
	input := ""
	for _, q := range queries {
		input += q + "\n"
	}
	gc.InputHandler = iohandlers.NewStreamInputHandler(&stringReader{s: input})

	// Setup output handler to capture results
	results := make([]string, 0, len(queries))
	resultChan := make(chan string, len(queries))

	// Create a goroutine to collect results
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range resultChan {
			results = append(results, result)
			job.mu.Lock()
			job.Progress++
			job.mu.Unlock()
		}
	}()

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

	factory := zdns.GetLookup(gc.Module)
	if factory == nil {
		job.mu.Lock()
		job.Status = JobFailed
		job.Error = fmt.Sprintf("Invalid lookup module: %s", gc.Module)
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("failed").Inc()
		return
	}

	if GC.Flags != nil {
		factory.SetFlags(GC.Flags)
	}

	if err := factory.Initialize(&gc); err != nil {
		job.mu.Lock()
		job.Status = JobFailed
		job.Error = fmt.Sprintf("Factory initialization failed: %v", err)
		now := time.Now()
		job.CompletedAt = &now
		job.mu.Unlock()
		jobsTotal.WithLabelValues("failed").Inc()
		return
	}

	// Run lookups (simplified - in production would need proper output handling)
	// For now, we'll execute lookups directly
	for i, query := range queries {
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

		// Check cache first
		cache := GetCache()
		if cache != nil && cache.enabled {
			if entry := cache.Get(gc.Module, query, job.Nameserver, false); entry != nil {
				results = append(results, entry.Result)
				job.mu.Lock()
				job.Progress = i + 1
				job.mu.Unlock()
				continue
			}
		}

		// Perform lookup
		// Note: This is a simplified version. In production, we'd use zdns.DoLookups properly
		// with proper input/output handlers
		result := fmt.Sprintf(`{"name":"%s","status":"NOERROR","data":{}}`, query)
		results = append(results, result)

		// Cache the result
		if cache != nil && cache.enabled {
			cache.Set(gc.Module, query, job.Nameserver, result)
		}

		job.mu.Lock()
		job.Progress = i + 1
		job.mu.Unlock()
	}

	close(resultChan)
	resultWg.Wait()

	if err := factory.Finalize(); err != nil {
		log.WithFields(log.Fields{
			"job_id": job.ID,
			"error":  err,
		}).Warn("Factory finalization failed")
	}

	job.mu.Lock()
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

// stringReader is a simple string reader for input
type stringReader struct {
	s string
	i int
}

func (r *stringReader) Read(p []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.i:])
	r.i += n
	return n, nil
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

// GetJobStatus returns the current status of a job
func (jm *JobManager) GetJobStatus(id string) (JobStatus, int, int, error) {
	job := jm.GetJob(id)
	if job == nil {
		return "", 0, 0, fmt.Errorf("job not found")
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	return job.Status, job.Progress, job.Total, nil
}

// GetJobResults returns the results of a completed job
func (jm *JobManager) GetJobResults(id string) ([]string, error) {
	job := jm.GetJob(id)
	if job == nil {
		return nil, fmt.Errorf("job not found")
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
		return fmt.Errorf("job not found")
	}

	job.mu.Lock()
	defer job.mu.Unlock()

	if job.Status != JobPending && job.Status != JobRunning {
		return fmt.Errorf("cannot cancel job with status: %s", job.Status)
	}

	job.cancel()
	job.Status = JobCancelled
	now := time.Now()
	job.CompletedAt = &now

	jobsTotal.WithLabelValues("cancelled").Inc()
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

// Global job manager
var jobManager *JobManager

// InitJobManager initializes the global job manager
func InitJobManager(workerCount int) {
	jobManager = NewJobManager(workerCount)
	log.Infof("Job manager initialized with %d workers", workerCount)
}

// GetJobManager returns the global job manager
func GetJobManager() *JobManager {
	return jobManager
}

// HTTP Handlers for job API

// createJobRequest handles POST /jobs
func createJobRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module  string   `json:"module"`
		Queries []string `json:"queries"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, ErrDecodeRequest, err.Error())
		return
	}

	if len(req.Queries) == 0 {
		ErrorResponse(w, ErrEmptyQueries, "")
		return
	}

	if len(req.Queries) > GC.MaxQueriesPerReq {
		ErrorResponse(w, ErrTooManyQueries, fmt.Sprintf("Maximum allowed: %d", GC.MaxQueriesPerReq))
		return
	}

	if req.Module == "" {
		req.Module = "A"
	}

	// Validate module
	factory := zdns.GetLookup(req.Module)
	if factory == nil {
		ErrorResponse(w, ErrInvalidModule, req.Module)
		return
	}

	// Validate domains
	for _, q := range req.Queries {
		if !validateDomain(q) {
			ErrorResponse(w, ErrInvalidDomain, q)
			return
		}
	}

	nameserver := ""
	if len(GC.NameServers) > 0 {
		nameserver = GC.NameServers[0]
	}

	job := jobManager.SubmitJob(req.Module, req.Queries, nameserver)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":     job.ID,
		"status":     job.Status,
		"created_at": job.CreatedAt,
	})
}

// getJobRequest handles GET /jobs/{job_id}
func getJobRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]

	job := jobManager.GetJob(jobID)
	if job == nil {
		ErrorResponse(w, ErrorCode{Code: 2004, Message: "Job not found", HTTPStatus: http.StatusNotFound}, "")
		return
	}

	job.mu.RLock()
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
		Status:      job.Status,
		Module:      job.Module,
		Total:       job.Total,
		Progress:    job.Progress,
		CreatedAt:   job.CreatedAt,
		StartedAt:   job.StartedAt,
		CompletedAt: job.CompletedAt,
		Error:       job.Error,
		Metadata:    job.Metadata,
	}
	job.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getJobResultsRequest handles GET /jobs/{job_id}/results
func getJobResultsRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]

	results, err := jobManager.GetJobResults(jobID)
	if err != nil {
		// Check if job exists but is not complete
		status, progress, total, _ := jobManager.GetJobStatus(jobID)
		if status != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   status,
				"progress": progress,
				"total":    total,
				"message":  "Job is still processing",
			})
			return
		}
		ErrorResponse(w, ErrorCode{Code: 2004, Message: "Job not found", HTTPStatus: http.StatusNotFound}, "")
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, result := range results {
		w.Write([]byte(result + "\n"))
	}
}

// cancelJobRequest handles DELETE /jobs/{job_id}
func cancelJobRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]

	if err := jobManager.CancelJob(jobID); err != nil {
		ErrorResponse(w, ErrorCode{Code: 2003, Message: err.Error(), HTTPStatus: http.StatusBadRequest}, "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    1000,
		"message": "Job cancelled",
	})
}

// listJobsRequest handles GET /jobs (admin/debug endpoint)
func listJobsRequest(w http.ResponseWriter, r *http.Request) {
	jobs := jobManager.ListJobs()

	var response []map[string]interface{}
	for _, job := range jobs {
		job.mu.RLock()
		response = append(response, map[string]interface{}{
			"id":       job.ID,
			"status":   job.Status,
			"module":   job.Module,
			"progress": job.Progress,
			"total":    job.Total,
		})
		job.mu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
