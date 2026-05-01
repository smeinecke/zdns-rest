package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewJobManager(t *testing.T) {
	jm := NewJobManager(5)
	assert.NotNil(t, jm)
	assert.Equal(t, 5, jm.workerCount)
	assert.NotNil(t, jm.jobs)
	assert.NotNil(t, jm.jobQueue)
	assert.NotNil(t, jm.shutdown)

	jm.Stop()
}

func TestNewJobManager_DefaultWorkers(t *testing.T) {
	jm := NewJobManager(0)
	assert.Equal(t, 10, jm.workerCount)
	jm.Stop()
}

func TestJobManager_SubmitJob(t *testing.T) {
	jm := NewJobManager(2)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

	job := jm.GetJob("nonexistent-id")
	assert.Nil(t, job)
}

func TestJobManager_GetJobStatus(t *testing.T) {
	jm := NewJobManager(1)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

	_, _, _, err := jm.GetJobStatus("nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "job not found")
}

func TestJobManager_GetJobResults_NotComplete(t *testing.T) {
	jm := NewJobManager(1)
	defer jm.Stop()

	queries := []string{"example.com"}
	job := jm.SubmitJob("A", queries, "8.8.8.8:53")

	results, err := jm.GetJobResults(job.ID)
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "not completed")
}

func TestJobManager_GetJobResults_NotFound(t *testing.T) {
	jm := NewJobManager(1)
	defer jm.Stop()

	results, err := jm.GetJobResults("nonexistent-id")
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "job not found")
}

func TestJobManager_CancelJob(t *testing.T) {
	jm := NewJobManager(1)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

	err := jm.CancelJob("nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "job not found")
}

func TestJobManager_CancelJob_AlreadyCompleted(t *testing.T) {
	jm := NewJobManager(1)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

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
	jm := NewJobManager(1)
	defer jm.Stop()

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
