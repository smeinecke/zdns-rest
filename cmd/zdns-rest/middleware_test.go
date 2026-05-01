package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChainMiddleware(t *testing.T) {
	var order []string

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	result := ChainMiddleware(handler, m1, m2)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	result.ServeHTTP(w, r)

	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expected) {
		t.Fatalf("order = %v, want %v", order, expected)
	}
	for i := range order {
		if order[i] != expected[i] {
			t.Errorf("order[%d] = %q, want %q", i, order[i], expected[i])
		}
	}
}

func TestChainMiddleware_NoMiddlewares(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	result := ChainMiddleware(handler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	result.ServeHTTP(w, r)

	if !called {
		t.Error("handler was not called")
	}
}

func TestTimeoutMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	middleware := TimeoutMiddleware(10 * time.Millisecond)
	wrapped := middleware(handler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestTimeoutMiddleware_FastResponse(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := TimeoutMiddleware(5 * time.Second)
	wrapped := middleware(handler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
