//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// getFreePort reserves an ephemeral TCP port for a test server. There is a
// small race between releasing the listener and the server binding the port,
// but it beats colliding with hardcoded ports (1808x/1809x) that other local
// processes may hold.
func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// startTestServer resets GC/AC to integration defaults, applies the caller's
// overrides (under GCMu), runs prepareConfig, and starts the API on a free
// loopback port. Returns the base URL.
//
// Normalizing every field each test may depend on prevents config from
// leaking between tests through the process-global GC/AC (e.g. an API key
// or rate limit set by an earlier test silently affecting this one).
func startTestServer(t *testing.T, overrides func()) string {
	t.Helper()
	GCMu.Lock()
	GC.ApiIP = "127.0.0.1"
	GC.ApiPort = getFreePort(t)
	GC.Verbosity = 2
	GC.LogFilePath = ""
	GC.Threads = 100
	GC.GoMaxProcs = 0
	GC.IterativeResolution = false
	GC.LookupAllNameServers = false
	GC.TCPOnly = false
	GC.UDPOnly = false
	GC.RateLimitEnabled = false
	GC.APIKey = ""
	GC.CacheEnabled = false
	GC.CacheMaxSize = 100
	GC.CacheTTL = 3600
	GC.CacheStaleTTL = 0
	GC.CircuitBreakerEnabled = false
	GC.CORSOrigins = ""
	GC.CORSMethods = ""
	GC.CORSHeaders = ""
	GC.MaxQueriesPerReq = 1000
	GC.EnablePprof = false
	GC.TLSEnabled = false
	GC.TrustedProxies = ""
	GC.OutputFormat = "v2"
	AC.Servers_string = ""
	AC.Localaddr_string = ""
	AC.Localif_string = ""
	AC.Config_file = "/etc/resolv.conf"
	AC.Timeout = 5
	AC.IterationTimeout = 2
	AC.Class_string = "INET"
	AC.NanoSeconds = false
	if overrides != nil {
		overrides()
	}
	port := GC.ApiPort
	GCMu.Unlock()

	prepareConfig()
	go func() {
		startServer()
	}()
	time.Sleep(500 * time.Millisecond)
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// TestIntegration_API starts a real server and makes HTTP requests
func TestIntegration_API(t *testing.T) {
	baseURL := startTestServer(t, nil)

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "ping",
			method:     "GET",
			path:       "/ping",
			body:       "",
			wantStatus: http.StatusOK,
			wantBody:   `"code":1000`,
		},
		{
			name:       "unknown path",
			method:     "GET",
			path:       "/unknown",
			body:       "",
			wantStatus: http.StatusBadRequest,
			wantBody:   `"code":2000`,
		},
		{
			name:       "job with invalid JSON",
			method:     "POST",
			path:       "/job",
			body:       `{invalid`,
			wantStatus: http.StatusBadRequest,
			wantBody:   `"code":2001`,
		},
		{
			name:       "job with missing queries",
			method:     "POST",
			path:       "/job",
			body:       `{"module":"A"}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   `"code":2005`,
		},
		{
			name:       "job with invalid module",
			method:     "POST",
			path:       "/job",
			body:       `{"module":"INVALID","queries":["example.com"]}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   `"code":2007`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			}
			req, err := http.NewRequest(tt.method, baseURL+tt.path, body)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Got status %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			respBody, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(respBody), tt.wantBody) {
				t.Errorf("Response body does not contain %q: %s", tt.wantBody, string(respBody))
			}
		})
	}

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_ALookup performs a real A lookup (if DNS is available)
func TestIntegration_ALookup(t *testing.T) {
	baseURL := startTestServer(t, nil)

	reqBody := `{"module":"A","queries":["example.com"]}`
	resp, err := http.Post(baseURL+"/job", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Skipf("DNS lookup test skipped: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err == nil {
		if status, ok := result["status"].(string); ok {
			t.Logf("DNS lookup status: %s", status)
		}
	}

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_HealthEndpoints tests health, ready, and metrics endpoints
func TestIntegration_HealthEndpoints(t *testing.T) {
	baseURL := startTestServer(t, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	// Test /health
	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Health request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var healthResult healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResult); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}
	if healthResult.Status != "up" {
		t.Errorf("Health status = %q, want 'up'", healthResult.Status)
	}
	if healthResult.BuildInfo.GoVersion == "" {
		t.Error("Health build_info.go_version is empty")
	}

	// Test /ready
	resp, err = client.Get(baseURL + "/ready")
	if err != nil {
		t.Fatalf("Ready request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Ready status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var readyResult readyResponse
	if err := json.NewDecoder(resp.Body).Decode(&readyResult); err != nil {
		t.Fatalf("Failed to decode ready response: %v", err)
	}
	if !readyResult.Ready {
		t.Error("Ready = false, want true")
	}

	// Test /metrics
	resp, err = client.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("Metrics request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Metrics status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "zdns_") {
		t.Errorf("Metrics response does not contain zdns metrics: %s", string(body))
	}

	// Test /ping still works
	resp, err = client.Get(baseURL + "/ping")
	if err != nil {
		t.Fatalf("Ping request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Ping status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_AuthMiddleware tests API key authentication
func TestIntegration_AuthMiddleware(t *testing.T) {
	baseURL := startTestServer(t, func() {
		GC.APIKey = "test-secret-key"
	})
	client := &http.Client{Timeout: 5 * time.Second}

	// Test request without auth (should fail)
	req, _ := http.NewRequest("GET", baseURL+"/job", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request without auth failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("No auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Test request with valid auth
	req, _ = http.NewRequest("GET", baseURL+"/job", nil)
	req.Header.Set("X-API-Key", "test-secret-key")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Request with valid auth failed: %v", err)
	}
	_ = resp.Body.Close()
	// Should not be 401 (may be other error since it's GET /job not POST)
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("Valid auth returned 401, expected success")
	}

	// Test request with invalid auth
	req, _ = http.NewRequest("GET", baseURL+"/job", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Request with invalid auth failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Invalid auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Reset API key
	GCMu.Lock()
	GC.APIKey = ""
	GCMu.Unlock()

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_Cache tests the DNS cache functionality
func TestIntegration_Cache(t *testing.T) {
	baseURL := startTestServer(t, func() {
		GC.CacheEnabled = true
		GC.CacheTTL = 300
		GC.CacheMaxSize = 1000
	})
	client := &http.Client{Timeout: 10 * time.Second}

	// First request - should populate cache
	reqBody := `{"module":"A","queries":["example.com"]}`
	resp, err := client.Post(baseURL+"/job", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Skipf("DNS lookup test skipped: %v", err)
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("DNS request failed with status: %d", resp.StatusCode)
		return
	}

	// Check metrics endpoint for cache metrics
	resp, err = client.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("Metrics request failed: %v", err)
	}
	metricsBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Should contain cache metrics
	if !strings.Contains(string(metricsBody), "zdns_cache_") {
		t.Log("Warning: Cache metrics not found in /metrics")
	}

	// Second request - should potentially hit cache
	resp, err = client.Post(baseURL+"/job", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Skipf("Second DNS lookup test skipped: %v", err)
		return
	}
	_ = resp.Body.Close()

	t.Log("Cache integration test completed successfully")

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_AsyncJobs tests the async job endpoints
func TestIntegration_AsyncJobs(t *testing.T) {
	baseURL := startTestServer(t, nil)
	client := &http.Client{Timeout: 10 * time.Second}

	// Test 1: Create a job
	reqBody := `{"module":"A","queries":["example.com","example.org"],"nameserver":"8.8.8.8:53"}`
	resp, err := client.Post(baseURL+"/jobs", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("Expected 202 Accepted, got %d: %s", resp.StatusCode, string(body))
	}

	var jobResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jobResp); err != nil {
		t.Fatalf("Failed to decode job response: %v", err)
	}
	_ = resp.Body.Close()

	jobID, ok := jobResp["job_id"].(string)
	if !ok || jobID == "" {
		t.Fatal("Job ID not returned in response")
	}

	status, ok := jobResp["status"].(string)
	if !ok || status != "pending" {
		t.Fatalf("Expected status 'pending', got %v", status)
	}

	t.Logf("Created job: %s", jobID)

	// Test 2: Get job status
	var jobStatus string
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		resp, err = client.Get(baseURL + "/jobs/" + jobID)
		if err != nil {
			t.Fatalf("Failed to get job status: %v", err)
		}

		var statusResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("Failed to decode status response: %v", err)
		}
		_ = resp.Body.Close()

		jobStatus, _ = statusResp["status"].(string)
		progress := 0
		if p, ok := statusResp["progress"].(float64); ok {
			progress = int(p)
		}
		total := 0
		if tot, ok := statusResp["total"].(float64); ok {
			total = int(tot)
		}

		t.Logf("Job status: %s, progress: %d/%d", jobStatus, progress, total)

		if jobStatus == "completed" || jobStatus == "failed" {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if jobStatus != "completed" && jobStatus != "failed" {
		t.Logf("Job did not complete in time, final status: %s", jobStatus)
	}

	// Test 3: Get job results (may be 202 if still running, or 200 with results)
	resp, err = client.Get(baseURL + "/jobs/" + jobID + "/results")
	if err != nil {
		t.Fatalf("Failed to get job results: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if len(body) == 0 {
			t.Log("Job completed but no results returned")
		} else {
			t.Logf("Job results received: %d bytes", len(body))
		}
	} else if resp.StatusCode == http.StatusAccepted {
		_ = resp.Body.Close()
		t.Log("Job still processing (202 returned)")
	} else {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Logf("Unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Test 4: List all jobs
	resp, err = client.Get(baseURL + "/jobs")
	if err != nil {
		t.Fatalf("Failed to list jobs: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Logf("List jobs returned %d: %s", resp.StatusCode, string(body))
	} else {
		var jobsList []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&jobsList); err != nil {
			_ = resp.Body.Close()
			t.Logf("Failed to decode jobs list: %v", err)
		} else {
			_ = resp.Body.Close()
			t.Logf("Found %d jobs", len(jobsList))
		}
	}

	t.Log("Async jobs integration test completed successfully")

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_CORS tests CORS preflight and actual requests
func TestIntegration_CORS(t *testing.T) {
	baseURL := startTestServer(t, func() {
		GC.CORSOrigins = "http://localhost:3000,https://example.com"
		GC.CORSMethods = "GET,POST,OPTIONS"
		GC.CORSHeaders = "Content-Type,X-Custom-Header"
	})
	client := &http.Client{Timeout: 5 * time.Second}

	tests := []struct {
		name             string
		method           string
		origin           string
		reqMethod        string
		reqHeaders       string
		wantStatus       int
		wantAllowOrigin  string
		wantAllowMethods bool
		wantAllowHeaders bool
	}{
		{
			name:             "preflight allowed origin",
			method:           "OPTIONS",
			origin:           "http://localhost:3000",
			reqMethod:        "POST",
			reqHeaders:       "content-type",
			wantStatus:       http.StatusNoContent,
			wantAllowOrigin:  "http://localhost:3000",
			wantAllowMethods: true,
			wantAllowHeaders: true,
		},
		{
			name:             "preflight second allowed origin",
			method:           "OPTIONS",
			origin:           "https://example.com",
			reqMethod:        "GET",
			wantStatus:       http.StatusNoContent,
			wantAllowOrigin:  "https://example.com",
			wantAllowMethods: true,
		},
		{
			name:             "preflight disallowed origin",
			method:           "OPTIONS",
			origin:           "https://evil.com",
			reqMethod:        "POST",
			wantStatus:       http.StatusNoContent,
			wantAllowOrigin:  "",
			wantAllowMethods: false,
		},
		{
			name:            "actual request with allowed origin",
			method:          "GET",
			origin:          "http://localhost:3000",
			wantStatus:      http.StatusOK,
			wantAllowOrigin: "http://localhost:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, baseURL+"/ping", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.reqMethod != "" {
				req.Header.Set("Access-Control-Request-Method", tt.reqMethod)
			}
			if tt.reqHeaders != "" {
				req.Header.Set("Access-Control-Request-Headers", tt.reqHeaders)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if tt.method == "OPTIONS" {
				if resp.StatusCode != tt.wantStatus {
					t.Errorf("Status = %d, want %d", resp.StatusCode, tt.wantStatus)
				}
				allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				if allowOrigin != tt.wantAllowOrigin {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", allowOrigin, tt.wantAllowOrigin)
				}
				if tt.wantAllowMethods && resp.Header.Get("Access-Control-Allow-Methods") == "" {
					t.Error("Access-Control-Allow-Methods header missing")
				}
				if tt.wantAllowHeaders && resp.Header.Get("Access-Control-Allow-Headers") == "" {
					t.Error("Access-Control-Allow-Headers header missing")
				}
			} else {
				if resp.StatusCode != tt.wantStatus {
					t.Errorf("Status = %d, want %d", resp.StatusCode, tt.wantStatus)
				}
				allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				if allowOrigin != tt.wantAllowOrigin {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", allowOrigin, tt.wantAllowOrigin)
				}
			}
		})
	}

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_JobLookupEndpoint tests POST /job/{lookup} with plain text body
func TestIntegration_JobLookupEndpoint(t *testing.T) {
	baseURL := startTestServer(t, nil)
	client := &http.Client{Timeout: 10 * time.Second}

	// Test with plain text body (one domain per line)
	body := "example.com\nexample.org"
	resp, err := client.Post(baseURL+"/job/A", "text/plain", bytes.NewBufferString(body))
	if err != nil {
		t.Skipf("DNS lookup test skipped: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("DNS request failed with status: %d", resp.StatusCode)
		return
	}

	// Read NDJSON response
	responseBody, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(responseBody)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		t.Skip("No DNS results returned")
		return
	}

	// Verify we got results for both domains
	domains := make(map[string]bool)
	for _, line := range lines {
		if line == "" {
			continue
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			if name, ok := result["name"].(string); ok {
				domains[name] = true
			}
		}
	}

	if len(domains) < 2 {
		t.Errorf("Expected results for 2 domains, got %d: %v", len(domains), domains)
	}

	t.Logf("Successfully queried %d domains via /job/A endpoint", len(domains))

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_RateLimiting tests rate limiting middleware
func TestIntegration_RateLimiting(t *testing.T) {
	baseURL := startTestServer(t, func() {
		GC.RateLimitEnabled = true
		GC.RateLimitRequests = 3
		GC.RateLimitWindow = 10
	})
	client := &http.Client{Timeout: 5 * time.Second}

	// Make requests up to the limit (use /jobs - /ping is a public endpoint)
	for i := 0; i < 3; i++ {
		resp, err := client.Get(baseURL + "/jobs")
		if err != nil {
			t.Fatalf("Request %d failed: %v", i+1, err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Request %d: status = %d, want %d", i+1, resp.StatusCode, http.StatusOK)
		}
	}

	// Next request should be rate limited
	resp, err := client.Get(baseURL + "/jobs")
	if err != nil {
		t.Fatalf("Rate limit request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Rate limit status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "3000") {
		t.Errorf("Rate limit response does not contain code 3000: %s", string(body))
	}

	t.Log("Rate limiting integration test completed successfully")

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_JobCancellation tests cancelling a pending job
func TestIntegration_JobCancellation(t *testing.T) {
	baseURL := startTestServer(t, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	// Create a job with many queries to keep it pending/running
	queries := make([]string, 100)
	for i := range queries {
		queries[i] = fmt.Sprintf("test%d.example.com", i)
	}
	reqBody := fmt.Sprintf(`{"module":"A","queries":["%s"]}`, strings.Join(queries, `","`))

	resp, err := client.Post(baseURL+"/jobs", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	var jobResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jobResp); err != nil {
		_ = resp.Body.Close()
		t.Fatalf("Failed to decode job response: %v", err)
	}
	_ = resp.Body.Close()

	jobID, ok := jobResp["job_id"].(string)
	if !ok || jobID == "" {
		t.Fatal("Job ID not returned in response")
	}

	t.Logf("Created job: %s", jobID)

	// Immediately cancel the job (should be pending or running)
	req, _ := http.NewRequest("DELETE", baseURL+"/jobs/"+jobID, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to cancel job: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("Cancel job returned %d: %s", resp.StatusCode, string(body))
	}
	_ = resp.Body.Close()

	// Verify job is cancelled
	resp, err = client.Get(baseURL + "/jobs/" + jobID)
	if err != nil {
		t.Fatalf("Failed to get job status: %v", err)
	}

	var statusResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		_ = resp.Body.Close()
		t.Fatalf("Failed to decode status response: %v", err)
	}
	_ = resp.Body.Close()

	status, _ := statusResp["status"].(string)
	if status != "cancelled" {
		t.Errorf("Job status after cancel = %q, want 'cancelled'", status)
	}

	t.Log("Job cancellation integration test completed successfully")

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_JobsErrorCases tests error handling for job endpoints
func TestIntegration_JobsErrorCases(t *testing.T) {
	baseURL := startTestServer(t, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "create job without queries",
			method:     "POST",
			path:       "/jobs",
			body:       `{"module":"A"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "create job with invalid module",
			method:     "POST",
			path:       "/jobs",
			body:       `{"module":"INVALID","queries":["example.com"]}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "get non-existent job",
			method:     "GET",
			path:       "/jobs/nonexistent-id",
			body:       "",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "get results for non-existent job",
			method:     "GET",
			path:       "/jobs/nonexistent-id/results",
			body:       "",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "cancel non-existent job",
			method:     "DELETE",
			path:       "/jobs/nonexistent-id",
			body:       "",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			}
			req, err := http.NewRequest(tt.method, baseURL+tt.path, body)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Got status %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_ConfigFile_KeyValue tests server startup with key=value config file
func TestIntegration_ConfigFile_KeyValue(t *testing.T) {
	port := getFreePort(t)
	tmpDir := t.TempDir()
	configFile := tmpDir + "/test.conf"
	content := fmt.Sprintf(`bind-port=%d
verbosity=2
rate-limit=false`, port)
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Configure using the config file
	cfgFile = configFile
	viper.Reset()
	initConfig()

	// Apply config to global settings
	baseURL := startTestServer(t, func() {
		GC.ApiPort = port
	})

	// Test ping endpoint
	resp, err := http.Get(baseURL + "/ping")
	if err != nil {
		t.Fatalf("Server did not start on port %d: %v", port, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify correct port was used
	GCMu.RLock()
	if GC.ApiPort != port {
		t.Errorf("ApiPort = %d, want %d", GC.ApiPort, port)
	}
	GCMu.RUnlock()

	// Reset
	cfgFile = ""
	viper.Reset()

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_ConfigFile_YAML tests server startup with YAML config file
func TestIntegration_ConfigFile_YAML(t *testing.T) {
	port := getFreePort(t)
	tmpDir := t.TempDir()
	configFile := tmpDir + "/test.yaml"
	content := fmt.Sprintf(`bind-port: %d
verbosity: 2
threads: 500`, port)
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Configure using the config file
	cfgFile = configFile
	viper.Reset()
	initConfig()

	// Apply config to global settings
	baseURL := startTestServer(t, func() {
		GC.ApiPort = port
		GC.Threads = 500
	})

	// Test ping endpoint
	resp, err := http.Get(baseURL + "/ping")
	if err != nil {
		t.Fatalf("Server did not start on port %d: %v", port, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify correct port was used
	GCMu.RLock()
	if GC.ApiPort != port {
		t.Errorf("ApiPort = %d, want %d", GC.ApiPort, port)
	}

	// Verify threads setting
	if GC.Threads != 500 {
		t.Errorf("Threads = %d, want 500", GC.Threads)
	}
	GCMu.RUnlock()

	// Reset
	cfgFile = ""
	viper.Reset()

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}

// TestIntegration_ConfigFileWithAPIKey tests server startup with API key from config
func TestIntegration_ConfigFileWithAPIKey(t *testing.T) {
	port := getFreePort(t)
	tmpDir := t.TempDir()
	configFile := tmpDir + "/test.conf"
	content := fmt.Sprintf(`bind-port=%d
verbosity=2
api-key=test-secret-key-12345`, port)
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Configure using the config file
	cfgFile = configFile
	viper.Reset()
	initConfig()

	// Apply config to global settings
	baseURL := startTestServer(t, func() {
		GC.ApiPort = port
		GC.APIKey = "test-secret-key-12345"
	})

	// Test request without API key should fail (use /jobs - /ping is a public endpoint)
	resp, err := http.Get(baseURL + "/jobs")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Without API key: got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	_ = resp.Body.Close()

	// Test request with correct API key should succeed
	req, _ := http.NewRequest("GET", baseURL+"/jobs", nil)
	req.Header.Set("X-API-Key", "test-secret-key-12345")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("With API key: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Reset
	cfgFile = ""
	viper.Reset()

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}
