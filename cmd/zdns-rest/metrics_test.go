package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsHandler(t *testing.T) {
	handler := MetricsHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", contentType)
	}
}

// TestMetricsMiddleware_RouteTemplate guards against a regression where the
// metrics middleware runs outside the router and mux.CurrentRoute is never
// populated — which would collapse every request onto path="unmatched".
func TestMetricsMiddleware_RouteTemplate(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/jobs/{job_id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Use(mux.MiddlewareFunc(MetricsMiddleware))

	before := testutil.ToFloat64(requestCounter.WithLabelValues("GET", "/jobs/{job_id}", "200"))

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/jobs/job-9999", nil))

	after := testutil.ToFloat64(requestCounter.WithLabelValues("GET", "/jobs/{job_id}", "200"))
	if after != before+1 {
		t.Fatalf("requestCounter for route template /jobs/{job_id} = %v, want %v", after, before+1)
	}
}

func TestResponseRecorder_WriteHeader(t *testing.T) {
	tests := []struct {
		name          string
		writeCodes    []int
		expectedCode  int
		expectedCalls int
	}{
		{"single write", []int{201}, 201, 1},
		{"double write ignores second", []int{201, 404}, 201, 1},
		{"default is 200", []int{}, 200, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := httptest.NewRecorder()
			rr := &responseRecorder{ResponseWriter: base, statusCode: http.StatusOK}

			for _, code := range tt.writeCodes {
				rr.WriteHeader(code)
			}

			if rr.statusCode != tt.expectedCode {
				t.Errorf("statusCode = %d, want %d", rr.statusCode, tt.expectedCode)
			}
		})
	}
}
