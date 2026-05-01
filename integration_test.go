//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIntegration_API starts a real server and makes HTTP requests
func TestIntegration_API(t *testing.T) {
	// Configure minimal test settings
	GC.ApiIP = "127.0.0.1"
	GC.ApiPort = 18080 // Use high port to avoid conflicts
	GC.Verbosity = 2   // Error level to reduce noise
	GC.LogFilePath = ""
	AC.Servers_string = ""
	AC.Localaddr_string = ""
	AC.Localif_string = ""
	AC.Config_file = "/etc/resolv.conf"
	AC.Timeout = 5
	AC.IterationTimeout = 2
	AC.Class_string = "INET"
	AC.NanoSeconds = false
	GC.IterativeResolution = false
	GC.LookupAllNameServers = false
	GC.NameServerMode = false
	GC.TCPOnly = false
	GC.UDPOnly = false
	GC.GoMaxProcs = 0

	// Initialize regex patterns (normally done in init())
	prepareConfig()

	// Start server in background
	go func() {
		startServer()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	baseURL := "http://127.0.0.1:18080"

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
			defer resp.Body.Close()

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
	GC.ApiIP = "127.0.0.1"
	GC.ApiPort = 18081
	GC.Verbosity = 2
	prepareConfig()

	// Start server in background
	go func() {
		startServer()
	}()

	time.Sleep(500 * time.Millisecond)

	baseURL := "http://127.0.0.1:18081"

	reqBody := `{"module":"A","queries":["example.com"]}`
	resp, err := http.Post(baseURL+"/job", "application/json", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Skipf("DNS lookup test skipped: %v", err)
		return
	}
	defer resp.Body.Close()

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
	GC.ApiIP = "127.0.0.1"
	GC.ApiPort = 18082
	GC.Verbosity = 2
	GC.LogFilePath = ""
	GC.RateLimitEnabled = false // Disable rate limiting for tests
	GC.APIKey = ""              // Disable auth for tests
	prepareConfig()

	// Start server in background
	go func() {
		startServer()
	}()

	time.Sleep(500 * time.Millisecond)

	baseURL := "http://127.0.0.1:18082"
	client := &http.Client{Timeout: 5 * time.Second}

	// Test /health
	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Health request failed: %v", err)
	}
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	GC.ApiIP = "127.0.0.1"
	GC.ApiPort = 18083
	GC.Verbosity = 2
	GC.LogFilePath = ""
	GC.RateLimitEnabled = false
	GC.APIKey = "test-secret-key"
	prepareConfig()

	// Start server in background
	go func() {
		startServer()
	}()

	time.Sleep(500 * time.Millisecond)

	baseURL := "http://127.0.0.1:18083"
	client := &http.Client{Timeout: 5 * time.Second}

	// Test request without auth (should fail)
	req, _ := http.NewRequest("GET", baseURL+"/job", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request without auth failed: %v", err)
	}
	resp.Body.Close()
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
	resp.Body.Close()
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
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Invalid auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Reset API key
	GC.APIKey = ""

	// Signal shutdown
	proc, _ := os.FindProcess(os.Getpid())
	if proc != nil {
		proc.Signal(os.Interrupt)
	}
	time.Sleep(100 * time.Millisecond)
}
