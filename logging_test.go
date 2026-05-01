package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoggingMiddleware(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Request-ID", "test-request-id")

	handler.ServeHTTP(w, r)

	// Response should include request ID
	requestID := w.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("LoggingMiddleware did not set X-Request-ID header")
	}

	if w.Code != http.StatusOK {
		t.Errorf("LoggingMiddleware: got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestLoggingMiddleware_GeneratesRequestID(t *testing.T) {
	handler := LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/job", nil)

	handler.ServeHTTP(w, r)

	requestID := w.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("LoggingMiddleware did not generate X-Request-ID header")
	}

	if len(requestID) < 8 {
		t.Errorf("Generated request ID too short: %q", requestID)
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" {
		t.Error("generateRequestID returned empty string")
	}

	if id1 == id2 {
		t.Error("generateRequestID returned duplicate IDs")
	}
}

func TestGetClientIP_FromHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.RemoteAddr = "10.0.0.1:1234"

	ip := getClientIP(r)
	if ip != "1.2.3.4" {
		t.Errorf("getClientIP from X-Forwarded-For = %q, want %q", ip, "1.2.3.4")
	}
}

func TestGetClientIP_FromRealIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Real-Ip", "5.6.7.8")
	r.RemoteAddr = "10.0.0.1:1234"

	ip := getClientIP(r)
	if ip != "5.6.7.8" {
		t.Errorf("getClientIP from X-Real-Ip = %q, want %q", ip, "5.6.7.8")
	}
}

func TestGetClientIP_FromRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "10.0.0.1:1234"

	ip := getClientIP(r)
	if ip != "10.0.0.1:1234" {
		t.Errorf("getClientIP from RemoteAddr = %q, want %q", ip, "10.0.0.1:1234")
	}
}

func TestLoggingResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	lrw := &loggingResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		requestID:      "test-id",
	}

	lrw.WriteHeader(http.StatusNotFound)
	if lrw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d", lrw.statusCode, http.StatusNotFound)
	}

	// Test Write triggers status OK if not written
	w2 := httptest.NewRecorder()
	lrw2 := &loggingResponseWriter{
		ResponseWriter: w2,
		statusCode:     http.StatusOK,
		requestID:      "test-id",
	}

	_, _ = lrw2.Write([]byte("hello"))
	if w2.Code != http.StatusOK {
		t.Errorf("Write triggered status = %d, want %d", w2.Code, http.StatusOK)
	}

	body := w2.Body.String()
	if body != "hello" {
		t.Errorf("Write body = %q, want %q", body, "hello")
	}

	// Test Header passthrough
	lrw.Header().Set("X-Custom", "value")
	if w.Header().Get("X-Custom") != "value" {
		t.Error("Header() did not pass through correctly")
	}
}

func TestLoggingResponseWriter_ImplementsFlusher(t *testing.T) {
	lrw := &loggingResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
	}

	flusher, ok := interface{}(lrw).(http.Flusher)
	if !ok {
		t.Fatal("loggingResponseWriter should implement http.Flusher")
	}

	flusher.Flush()
}

func TestMetricsMiddleware(t *testing.T) {
	handler := MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("MetricsMiddleware: got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestResponseRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	rr := &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Test WriteHeader captures status
	rr.WriteHeader(http.StatusNotFound)
	if rr.statusCode != http.StatusNotFound {
		t.Errorf("responseRecorder statusCode = %d, want %d", rr.statusCode, http.StatusNotFound)
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("responseRecorder underlying status = %d, want %d", w.Code, http.StatusNotFound)
	}

	// Test double WriteHeader doesn't change status
	rr.WriteHeader(http.StatusInternalServerError)
	if rr.statusCode != http.StatusNotFound {
		t.Errorf("responseRecorder statusCode after double write = %d, want %d", rr.statusCode, http.StatusNotFound)
	}
}

func TestResponseRecorder_ImplementsFlusher(t *testing.T) {
	rr := &responseRecorder{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
	}

	flusher, ok := interface{}(rr).(http.Flusher)
	if !ok {
		t.Fatal("responseRecorder should implement http.Flusher")
	}

	flusher.Flush()
}

func TestRecoverMiddleware(t *testing.T) {
	handler := RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("RecoverMiddleware: got status %d, want %d", w.Code, http.StatusInternalServerError)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Internal server error") && !strings.Contains(body, "5000") {
		t.Errorf("RecoverMiddleware: body = %q, expected error message", body)
	}
}

func TestRecoverMiddleware_NoPanic(t *testing.T) {
	handler := RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("RecoverMiddleware no panic: got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestLogDNSLookup(t *testing.T) {
	// Should not panic
	LogDNSLookup("req-123", "A", "example.com", "NOERROR", 100*time.Millisecond)
	LogDNSLookup("req-456", "MX", "example.org", "NXDOMAIN", 50*time.Millisecond)
}

func TestLoggingResponseWriter_ReadFrom(t *testing.T) {
	w := httptest.NewRecorder()
	lrw := &loggingResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		requestID:      "test-id",
	}

	// ReadFrom on httptest.ResponseRecorder should fall through to io.Copy
	src := strings.NewReader("streamed data")
	n, err := lrw.ReadFrom(src)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != int64(len("streamed data")) {
		t.Errorf("ReadFrom n = %d, want %d", n, len("streamed data"))
	}
	if w.Body.String() != "streamed data" {
		t.Errorf("ReadFrom body = %q, want %q", w.Body.String(), "streamed data")
	}
	if w.Code != http.StatusOK {
		t.Errorf("ReadFrom status = %d, want %d", w.Code, http.StatusOK)
	}
}
