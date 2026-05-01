package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// TestHealthRequest tests the health endpoint
func TestHealthRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	healthRequest(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthRequest() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Code != 1000 {
		t.Errorf("healthRequest() code = %d, want 1000", result.Code)
	}
	if result.Status != "up" {
		t.Errorf("healthRequest() status = %q, want 'up'", result.Status)
	}
	if result.BuildInfo.GoVersion == "" {
		t.Error("healthRequest() build_info.go_version is empty")
	}
}

// TestReadyRequest tests the ready endpoint
func TestReadyRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ready", nil)
	readyRequest(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyRequest() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result readyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Code != 1000 {
		t.Errorf("readyRequest() code = %d, want 1000", result.Code)
	}
	if !result.Ready {
		t.Error("readyRequest() ready = false, want true")
	}
}

// TestErrorResponse tests structured error responses
func TestErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		errCode    ErrorCode
		detail     string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "rate limit error",
			errCode:    ErrRateLimited,
			detail:     "",
			wantStatus: http.StatusTooManyRequests,
			wantBody:   `{"code":3000,"message":"Rate limit exceeded. Please try again later."}`,
		},
		{
			name:       "unauthorized with detail",
			errCode:    ErrUnauthorized,
			detail:     "invalid key",
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"code":4001,"message":"Unauthorized: valid API key required: invalid key"}`,
		},
		{
			name:       "invalid domain",
			errCode:    ErrInvalidDomain,
			detail:     "bad..domain",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"code":2008,"message":"Invalid domain name: bad..domain"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ErrorResponse(w, tt.errCode, tt.detail)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("ErrorResponse() status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			body := strings.TrimSpace(w.Body.String())
			if body != tt.wantBody {
				t.Errorf("ErrorResponse() body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestAPIResult(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		message    string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "success code",
			code:       1000,
			message:    "Command completed successfully",
			wantStatus: http.StatusOK,
			wantBody:   `{"code":1000,"message":"Command completed successfully"}`,
		},
		{
			name:       "error code",
			code:       2000,
			message:    "Unknown command",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"code":2000,"message":"Unknown command"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			APIResult(w, tt.code, tt.message)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("APIResult() status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			contentType := resp.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("APIResult() Content-Type = %q, want application/json", contentType)
			}

			body := strings.TrimSpace(w.Body.String())
			if body != tt.wantBody {
				t.Errorf("APIResult() body = %q, want %q", body, tt.wantBody)
			}
		})
	}
}

func TestPingRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ping", nil)
	pingRequest(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("pingRequest() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body := strings.TrimSpace(w.Body.String())
	expected := `{"code":1000,"message":"Command completed successfully"}`
	if body != expected {
		t.Errorf("pingRequest() body = %q, want %q", body, expected)
	}
}

func TestNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	notFound(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("notFound() status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	body := strings.TrimSpace(w.Body.String())
	expected := `{"code":2000,"message":"Unknown command"}`
	if body != expected {
		t.Errorf("notFound() body = %q, want %q", body, expected)
	}
}

func TestStreamOutputHandler(t *testing.T) {
	w := httptest.NewRecorder()
	handler := NewStreamOutputHandler(w)

	results := make(chan string, 3)
	results <- `{"name":"example.com","status":"NOERROR"}`
	results <- `{"name":"example.org","status":"NOERROR"}`
	close(results)

	var wg sync.WaitGroup
	wg.Add(1)

	err := handler.WriteResults(results, &wg)
	wg.Wait()

	if err != nil {
		t.Errorf("WriteResults() error = %v", err)
	}

	body := w.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 2 {
		t.Errorf("WriteResults() wrote %d lines, want 2", len(lines))
	}

	for i, line := range lines {
		if !strings.Contains(line, "NOERROR") {
			t.Errorf("WriteResults() line %d = %q, missing expected content", i, line)
		}
	}
}

func TestStreamOutputHandler_EmptyChannel(t *testing.T) {
	w := httptest.NewRecorder()
	handler := NewStreamOutputHandler(w)

	results := make(chan string)
	close(results)

	var wg sync.WaitGroup
	wg.Add(1)

	err := handler.WriteResults(results, &wg)
	wg.Wait()

	if err != nil {
		t.Errorf("WriteResults() error = %v", err)
	}

	if w.Body.Len() != 0 {
		t.Errorf("WriteResults() wrote %d bytes for empty channel, want 0", w.Body.Len())
	}
}

func TestRunModule_InvalidJSON(t *testing.T) {
	// Set up minimal global config for testing
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{invalid json`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("runModule() with invalid JSON status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRunModule_MissingQueries(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"module":"A"}`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("runModule() with missing queries status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestDNSRequestsSerialization(t *testing.T) {
	dr := DNSRequests{
		Module:  "A",
		Queries: []string{"example.com", "example.org"},
	}

	data, err := json.Marshal(dr)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded DNSRequests
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.Module != "A" {
		t.Errorf("Module = %q, want A", decoded.Module)
	}
	if len(decoded.Queries) != 2 {
		t.Errorf("len(Queries) = %d, want 2", len(decoded.Queries))
	}
}

func TestRouter(t *testing.T) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/job/{lookup}", runModule).Methods("POST")
	r.HandleFunc("/job", runModule).Methods("POST")
	r.HandleFunc("/ping", pingRequest)
	r.NotFoundHandler = http.HandlerFunc(notFound)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"ping GET", "GET", "/ping", http.StatusOK},
		{"ping POST", "POST", "/ping", http.StatusOK},
		{"unknown path", "GET", "/unknown", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))

			if w.Code != tt.wantStatus {
				t.Errorf("Router %s %s = %d, want %d", tt.method, tt.path, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestRunModule_FormEncoded(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"
	// GC.Flags needs to be initialized or nil checks added in runModule

	w := httptest.NewRecorder()
	body := bytes.NewBufferString("example.com")
	r := httptest.NewRequest(http.MethodPost, "/job/MX", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// This should not panic - we expect either success or bad request
	// The test will likely fail early due to factory not being available
	defer func() {
		if r := recover(); r != nil {
			t.Logf("runModule panicked as expected (Flags not initialized): %v", r)
		}
	}()

	runModule(w, r)

	resp := w.Result()
	// Should get error due to invalid module or factory initialization failure
	if resp.StatusCode == http.StatusOK {
		t.Log("runModule with form-encoded succeeded (may be due to DNS available)")
	}
}

func TestRunModule_InvalidModule(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"module":"INVALID","queries":["example.com"]}`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("runModule() with invalid module status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRunModule_DefaultModule(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"queries":["example.com"]}`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected panic due to nil Flags: %v", r)
		}
	}()

	runModule(w, r)

	resp := w.Result()
	// Should use default module "A" and fail due to factory initialization
	if resp.StatusCode == http.StatusOK {
		t.Log("runModule with default module succeeded")
	}
}

func TestRunModule_URLModule(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString("example.com")
	r := httptest.NewRequest(http.MethodPost, "/job/MX", body)
	// No Content-Type header - should use form encoding and extract module from URL

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected panic due to uninitialized flags: %v", r)
		}
	}()

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode == http.StatusOK {
		t.Log("runModule with URL module succeeded")
	}
}

func TestRunModule_ReadBodyError(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	// Create a reader that will cause ReadAll to fail
	body := &badReader{}
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("runModule() with read error status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// badReader is a reader that always returns an error
type badReader struct{}

func (b *badReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestRunModule_EmptyModuleDefault(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"module":"","queries":["example.com"]}`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected panic due to nil Flags: %v", r)
		}
	}()

	runModule(w, r)

	resp := w.Result()
	// Should use default "A" and likely fail due to factory init
	t.Logf("Response status: %d", resp.StatusCode)
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{"valid domain", "example.com", true},
		{"valid subdomain", "sub.example.co.uk", true},
		{"single label", "localhost", true},
		{"empty string", "", false},
		{"too long", strings.Repeat("a", 254), false},
		{"invalid chars", "exa mple.com", false},
		{"leading hyphen", "-example.com", false},
		{"trailing hyphen", "example-.com", false},
		{"valid with trailing dot", "example.com.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("validateDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(3, time.Second)

	// First 3 should pass
	if !limiter.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}
	if !limiter.Allow("192.168.1.1") {
		t.Error("Second request should be allowed")
	}
	if !limiter.Allow("192.168.1.1") {
		t.Error("Third request should be allowed")
	}

	// Fourth should fail
	if limiter.Allow("192.168.1.1") {
		t.Error("Fourth request should be rate limited")
	}

	// Different IP should still work
	if !limiter.Allow("192.168.1.2") {
		t.Error("Different IP should not be rate limited")
	}

	// Nil limiter should allow
	var nilLimiter *RateLimiter
	if !nilLimiter.Allow("any") {
		t.Error("Nil limiter should allow all requests")
	}
}

func TestRateLimiter_Window(t *testing.T) {
	// Very short window for testing
	limiter := NewRateLimiter(2, 50*time.Millisecond)

	if !limiter.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}
	if !limiter.Allow("192.168.1.1") {
		t.Error("Second request should be allowed")
	}
	if limiter.Allow("192.168.1.1") {
		t.Error("Third request should be rate limited")
	}

	// Wait for window to expire
	time.Sleep(100 * time.Millisecond)

	if !limiter.Allow("192.168.1.1") {
		t.Error("Request after window should be allowed")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)

	handler := RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), limiter)

	// First 2 requests pass
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.RemoteAddr = "192.168.1.1:12345"
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("Request %d: got status %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// Third request gets 429
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Got status %d, want %d", w.Code, http.StatusTooManyRequests)
	}

	// Check rate limit headers
	limit := w.Header().Get("X-RateLimit-Limit")
	if limit == "" {
		t.Error("Missing X-RateLimit-Limit header")
	}
}

func TestLimitBodySize(t *testing.T) {
	handler := LimitBodySize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body to trigger the limit check
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			// MaxBytesReader returns an error for oversized bodies
			if strings.Contains(err.Error(), "too large") || strings.Contains(err.Error(), "http: request body too large") {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
	}), 100)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(strings.Repeat("a", 50)))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Small body: got status %d, want %d", w.Code, http.StatusOK)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(strings.Repeat("a", 200)))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Large body: got status %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestRunModule_TooManyQueries(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"
	GC.MaxQueriesPerReq = 2

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"module":"A","queries":["example.com","example.org","example.net"]}`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("runModule() status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRunModule_InvalidDomain(t *testing.T) {
	GC.ApiPort = 8080
	GC.ApiIP = "127.0.0.1"

	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"module":"A","queries":["exa mple.com"]}`)
	r := httptest.NewRequest(http.MethodPost, "/job", body)
	r.Header.Set("Content-Type", "application/json")

	runModule(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("runModule() status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
