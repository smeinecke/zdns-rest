package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandler(t *testing.T) {
	handler := MetricsHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", contentType)
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
