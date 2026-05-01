package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func setupJobTestConfig(t *testing.T) {
	t.Helper()

	GC = GlobalConf{}
	AC = ArgumentsConf{}

	GC.Verbosity = 2
	GC.LogFilePath = ""
	GC.IterativeResolution = false
	GC.LookupAllNameServers = false
	GC.NameServerMode = false
	GC.TCPOnly = false
	GC.UDPOnly = false
	GC.GoMaxProcs = 0
	GC.MaxQueriesPerReq = 1000
	GC.RequestTimeout = 30
	GC.ResultVerbosity = "normal"
	GC.IncludeInOutput = ""

	AC.Servers_string = ""
	AC.Localaddr_string = ""
	AC.Localif_string = ""
	AC.Config_file = "/etc/resolv.conf"
	AC.Timeout = 5
	AC.IterationTimeout = 2
	AC.Class_string = "INET"
	AC.NanoSeconds = false

	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)
	prepareConfig()
}

func newIdleJobManager() *JobManager {
	return &JobManager{
		jobs:        make(map[string]*Job),
		workerCount: 1,
		jobQueue:    make(chan *Job, 1000),
		shutdown:    make(chan struct{}),
	}
}

func TestNewJobManager(t *testing.T) {
	setupJobTestConfig(t)

	jm := NewJobManager(5)
	assert.NotNil(t, jm)
	assert.Equal(t, 5, jm.workerCount)
	assert.NotNil(t, jm.jobs)
	assert.NotNil(t, jm.jobQueue)
	assert.NotNil(t, jm.shutdown)

	jm.Stop()
}

func TestNewJobManager_DefaultWorkers(t *testing.T) {
	setupJobTestConfig(t)

	jm := NewJobManager(0)
	assert.Equal(t, 10, jm.workerCount)
	jm.Stop()
}

func TestJobManager_SubmitJob(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com", "example.org"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	assert.NotNil(t, job)
	assert.NotEmpty(t, job.ID)
	assert.Equal(t, "A", job.Module)
	assert.Equal(t, 2, job.Total)
	assert.Equal(t, "8.8.8.8:53", job.Nameserver)
	assert.NotNil(t, job.CreatedAt)

	// Use GetJobStatus to safely read status (avoids race with worker)
	status, _, _, err := jm.GetJobStatus(job.ID)
	assert.NoError(t, err)
	// Status could be pending or running depending on timing
	assert.True(t, status == JobPending || status == JobRunning)

	// Verify job is stored
	retrieved := jm.GetJob(job.ID)
	assert.NotNil(t, retrieved)
	assert.Equal(t, job.ID, retrieved.ID)
}

func TestJobManager_GetJob_NotFound(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	job := jm.GetJob("nonexistent-id")
	assert.Nil(t, job)
}

func TestJobManager_GetJobStatus(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	status, progress, total, err := jm.GetJobStatus(job.ID)
	assert.NoError(t, err)
	// Status could be pending or running depending on timing
	assert.True(t, status == JobPending || status == JobRunning || status == JobCompleted)
	assert.True(t, progress >= 0)
	assert.Equal(t, 1, total)
}

func TestJobManager_GetJobStatus_NotFound(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	_, _, _, err := jm.GetJobStatus("nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "job not found")
}

func TestJobManager_GetJobResults_NotComplete(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	results, err := jm.GetJobResults(job.ID)
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "not completed")
}

func TestJobManager_GetJobResults_NotFound(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	results, err := jm.GetJobResults("nonexistent-id")
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "job not found")
}

func TestJobManager_CancelJob(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	// Cancel the job
	err := jm.CancelJob(job.ID)
	assert.NoError(t, err)

	// Verify job is cancelled
	job.mu.RLock()
	assert.Equal(t, JobCancelled, job.Status)
	assert.NotNil(t, job.CompletedAt)
	job.mu.RUnlock()
}

func TestJobManager_CancelJob_NotFound(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	err := jm.CancelJob("nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "job not found")
}

func TestJobManager_CancelJob_AlreadyCompleted(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	// Mark as completed manually
	job.mu.Lock()
	job.Status = JobCompleted
	job.mu.Unlock()

	// Should not be able to cancel completed job
	err := jm.CancelJob(job.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot cancel")
}

func TestJobManager_ListJobs(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	// Submit multiple jobs
	job1 := jm.SubmitJob("A", []string{"example.com"}, "8.8.8.8:53")
	job2 := jm.SubmitJob("MX", []string{"example.org"}, "8.8.8.8:53")

	jobs := jm.ListJobs()
	assert.Len(t, jobs, 2)

	ids := make([]string, len(jobs))
	for i, j := range jobs {
		ids[i] = j.ID
	}
	assert.Contains(t, ids, job1.ID)
	assert.Contains(t, ids, job2.ID)
}

func TestJobManager_CleanupOldJobs(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	// Create a job and manually set it as completed with old creation time
	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	job.mu.Lock()
	job.Status = JobCompleted
	oldTime := time.Now().Add(-2 * time.Hour)
	job.CreatedAt = oldTime
	job.CompletedAt = &oldTime
	job.mu.Unlock()

	// Cleanup jobs older than 1 hour
	removed := jm.CleanupOldJobs(1 * time.Hour)
	assert.Equal(t, 1, removed)

	// Verify job is gone
	assert.Nil(t, jm.GetJob(job.ID))
}

func TestJobManager_CleanupOldJobs_DoesNotRemoveRecent(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	// Mark as completed
	job.mu.Lock()
	job.Status = JobCompleted
	now := time.Now()
	job.CompletedAt = &now
	job.mu.Unlock()

	// Cleanup jobs older than 1 hour - should not remove recent
	removed := jm.CleanupOldJobs(1 * time.Hour)
	assert.Equal(t, 0, removed)

	// Verify job still exists
	assert.NotNil(t, jm.GetJob(job.ID))
}

func TestJobManager_CleanupOldJobs_DoesNotRemoveRunning(t *testing.T) {
	setupJobTestConfig(t)

	jm := newIdleJobManager()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	// Mark as running with old creation time
	job.mu.Lock()
	job.Status = JobRunning
	job.CreatedAt = time.Now().Add(-2 * time.Hour)
	job.mu.Unlock()

	// Should not remove running jobs even if old
	removed := jm.CleanupOldJobs(1 * time.Hour)
	assert.Equal(t, 0, removed)

	// Verify job still exists
	assert.NotNil(t, jm.GetJob(job.ID))
}

func TestGenerateJobID(t *testing.T) {
	id1 := generateJobID()
	id2 := generateJobID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Contains(t, id1, "job-")
}

func TestJobStatus_String(t *testing.T) {
	assert.Equal(t, "pending", string(JobPending))
	assert.Equal(t, "running", string(JobRunning))
	assert.Equal(t, "completed", string(JobCompleted))
	assert.Equal(t, "failed", string(JobFailed))
	assert.Equal(t, "cancelled", string(JobCancelled))
}

func TestJobStruct_JSONTags(t *testing.T) {
	now := time.Now()
	job := Job{
		ID:         "test-id",
		Status:     JobRunning,
		Module:     "A",
		Queries:    []string{"example.com"},
		Total:      1,
		Progress:   0,
		CreatedAt:  now,
		Nameserver: "8.8.8.8:53",
		Metadata:   map[string]interface{}{"key": "value"},
	}

	// Just verify the struct is correctly formed with all fields
	assert.Equal(t, "test-id", job.ID)
	assert.Equal(t, JobRunning, job.Status)
	assert.Equal(t, "A", job.Module)
	assert.Equal(t, []string{"example.com"}, job.Queries)
	assert.Equal(t, 1, job.Total)
	assert.Equal(t, "8.8.8.8:53", job.Nameserver)
	assert.NotNil(t, job.Metadata)
}

func TestJobOutputHandler_WriteResults(t *testing.T) {
	InitCache(true, 100, time.Hour)
	defer InitCache(false, 0, 0)

	job := &Job{}
	collector := NewOrderedResultCollector()
	handler := &JobOutputHandler{
		job:        job,
		module:     "A",
		nameserver: "8.8.8.8:53",
		collector:  collector,
	}

	results := make(chan string, 1)
	results <- `{"name":"example.com","status":"NOERROR"}`
	close(results)

	var wg sync.WaitGroup
	wg.Add(1)

	err := handler.WriteResults(results, &wg)
	wg.Wait()

	assert.NoError(t, err)
	collected := collector.Ordered([]string{"example.com"})
	assert.Equal(t, 1, len(collected))
	assert.Equal(t, 1, job.Progress)

	entry := GetCache().Get("A", "example.com", "8.8.8.8:53", false)
	assert.NotNil(t, entry)
	assert.Equal(t, collected[0], entry.Result)
}

func TestBuildQueryInput(t *testing.T) {
	assert.Equal(t, "example.com\nexample.org\n", buildQueryInput([]string{"example.com", "example.org"}))
	assert.Equal(t, "", buildQueryInput(nil))
}

func TestCreateJobRequest(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	body := `{"module":"A","queries":["example.com"]}`
	r := httptest.NewRequest("POST", "/jobs", strings.NewReader(body))
	w := httptest.NewRecorder()

	createJobRequest(w, r)

	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.Contains(t, w.Body.String(), "job_id")
	assert.Contains(t, w.Body.String(), "pending")
}

func TestCreateJobRequest_InvalidJSON(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	r := httptest.NewRequest("POST", "/jobs", strings.NewReader("not-json"))
	w := httptest.NewRecorder()

	createJobRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateJobRequest_EmptyQueries(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	body := `{"module":"A","queries":[]}`
	r := httptest.NewRequest("POST", "/jobs", strings.NewReader(body))
	w := httptest.NewRecorder()

	createJobRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateJobRequest_InvalidModule(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	body := `{"module":"INVALID","queries":["example.com"]}`
	r := httptest.NewRequest("POST", "/jobs", strings.NewReader(body))
	w := httptest.NewRecorder()

	createJobRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateJobRequest_InvalidDomain(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	body := `{"module":"A","queries":["not-a-domain!"]}`
	r := httptest.NewRequest("POST", "/jobs", strings.NewReader(body))
	w := httptest.NewRecorder()

	createJobRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetJobRequest(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	job := &Job{
		ID:       "job-123",
		Status:   JobRunning,
		Module:   "A",
		Total:    2,
		Progress: 1,
	}
	jobManager.jobs[job.ID] = job

	r := httptest.NewRequest("GET", "/jobs/job-123", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "job-123"})
	w := httptest.NewRecorder()

	getJobRequest(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "job-123")
	assert.Contains(t, w.Body.String(), "running")
}

func TestGetJobRequest_NotFound(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	r := httptest.NewRequest("GET", "/jobs/unknown", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "unknown"})
	w := httptest.NewRecorder()

	getJobRequest(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetJobResultsRequest_CompletedJob(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	job := &Job{
		ID:      "job-done",
		Status:  JobCompleted,
		Total:   1,
		Results: []string{`{"name":"example.com"}`},
	}
	jobManager.jobs[job.ID] = job

	r := httptest.NewRequest("GET", "/jobs/job-done/results", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "job-done"})
	w := httptest.NewRecorder()

	getJobResultsRequest(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "example.com")
}

func TestGetJobResultsRequest_RunningJob(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	job := &Job{
		ID:       "job-running",
		Status:   JobRunning,
		Total:    5,
		Progress: 2,
	}
	jobManager.jobs[job.ID] = job

	r := httptest.NewRequest("GET", "/jobs/job-running/results", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "job-running"})
	w := httptest.NewRecorder()

	getJobResultsRequest(w, r)

	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.Contains(t, w.Body.String(), "still processing")
}

func TestGetJobResultsRequest_NotFound(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	r := httptest.NewRequest("GET", "/jobs/unknown/results", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "unknown"})
	w := httptest.NewRecorder()

	getJobResultsRequest(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCancelJobRequest(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:     "job-cancel",
		Status: JobPending,
		ctx:    ctx,
		cancel: cancel,
	}
	jobManager.jobs[job.ID] = job

	r := httptest.NewRequest("DELETE", "/jobs/job-cancel", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "job-cancel"})
	w := httptest.NewRecorder()

	cancelJobRequest(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Job cancelled")
}

func TestCancelJobRequest_NotFound(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	r := httptest.NewRequest("DELETE", "/jobs/unknown", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": "unknown"})
	w := httptest.NewRecorder()

	cancelJobRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListJobsRequest(t *testing.T) {
	setupJobTestConfig(t)
	jobManager = newIdleJobManager()

	job1 := &Job{
		ID:     "job-1",
		Status: JobPending,
		Module: "A",
		Total:  1,
	}
	job2 := &Job{
		ID:     "job-2",
		Status: JobRunning,
		Module: "MX",
		Total:  2,
	}
	jobManager.jobs[job1.ID] = job1
	jobManager.jobs[job2.ID] = job2

	r := httptest.NewRequest("GET", "/jobs", nil)
	w := httptest.NewRecorder()

	listJobsRequest(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "job-1")
	assert.Contains(t, body, "job-2")
	assert.Contains(t, body, "pending")
	assert.Contains(t, body, "running")
}

func TestGetJobResultsRequest_FailedJob(t *testing.T) {
	jobManager = newIdleJobManager()
	job := &Job{
		ID:       "job-failed",
		Status:   JobFailed,
		Progress: 1,
		Total:    2,
		Error:    "lookup failed",
	}
	jobManager.jobs[job.ID] = job

	r := httptest.NewRequest("GET", "/jobs/"+job.ID+"/results", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": job.ID})
	w := httptest.NewRecorder()

	getJobResultsRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "lookup failed")
	assert.NotContains(t, w.Body.String(), "still processing")
}

func TestGetJobResultsRequest_CancelledJob(t *testing.T) {
	jobManager = newIdleJobManager()
	job := &Job{
		ID:       "job-cancelled",
		Status:   JobCancelled,
		Progress: 1,
		Total:    2,
	}
	jobManager.jobs[job.ID] = job

	r := httptest.NewRequest("GET", "/jobs/"+job.ID+"/results", nil)
	r = mux.SetURLVars(r, map[string]string{"job_id": job.ID})
	w := httptest.NewRecorder()

	getJobResultsRequest(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "cancelled")
	assert.NotContains(t, w.Body.String(), "still processing")
}
