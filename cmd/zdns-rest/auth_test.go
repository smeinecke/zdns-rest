package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware_Disabled(t *testing.T) {
	// Test with no API key (auth disabled)
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Auth disabled: got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAuthMiddleware_ValidBearerToken(t *testing.T) {
	apiKey := "secret-key"
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), apiKey)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)
	r.Header.Set("Authorization", "Bearer secret-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Valid bearer token: got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAuthMiddleware_ValidAPIKeyHeader(t *testing.T) {
	apiKey := "secret-key"
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), apiKey)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)
	r.Header.Set("X-API-Key", "secret-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Valid X-API-Key header: got status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAuthMiddleware_MissingKey(t *testing.T) {
	apiKey := "secret-key"
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), apiKey)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Missing key: got status %d, want %d", w.Code, http.StatusUnauthorized)
	}

	body := strings.TrimSpace(w.Body.String())
	if !strings.Contains(body, "4001") {
		t.Errorf("Missing key: expected error code 4001 in body, got %q", body)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	apiKey := "secret-key"
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), apiKey)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)
	r.Header.Set("X-API-Key", "wrong-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Invalid key: got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_CaseInsensitiveBearer(t *testing.T) {
	apiKey := "secret-key"
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), apiKey)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/job", nil)
	r.Header.Set("Authorization", "bearer secret-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Case insensitive bearer: got status %d, want %d", w.Code, http.StatusOK)
	}
}
