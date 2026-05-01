package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{"simple comma", "a,b,c", ",", []string{"a", "b", "c"}},
		{"with spaces", " a , b , c ", ",", []string{"a", "b", "c"}},
		{"empty parts", "a,,c", ",", []string{"a", "c"}},
		{"single item", "only", ",", []string{"only"}},
		{"empty string", "", ",", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.sep)
			if len(result) != len(tt.expected) {
				t.Errorf("splitAndTrim(%q, %q) = %v, want %v", tt.input, tt.sep, result, tt.expected)
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("splitAndTrim(%q, %q)[%d] = %q, want %q", tt.input, tt.sep, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestSplitString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{"comma sep", "a,b,c", ",", []string{"a", "b", "c"}},
		{"multi char sep", "a::b::c", "::", []string{"a", "b", "c"}},
		{"no sep", "abc", ",", []string{"abc"}},
		{"empty string", "", ",", []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitString(tt.input, tt.sep)
			if len(result) != len(tt.expected) {
				t.Errorf("splitString(%q, %q) = %v, want %v", tt.input, tt.sep, result, tt.expected)
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("splitString(%q, %q)[%d] = %q, want %q", tt.input, tt.sep, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"spaces", "  hello  ", "hello"},
		{"tabs", "\thello\t", "hello"},
		{"mixed", " \t hello \n \r ", "hello"},
		{"no trim", "hello", "hello"},
		{"empty", "", ""},
		{"only spaces", "   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimSpace(tt.input)
			if result != tt.expected {
				t.Errorf("trimSpace(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCORSConfigFromFlags(t *testing.T) {
	tests := []struct {
		name           string
		origins        string
		methods        string
		headers        string
		wantEnabled    bool
		wantOriginsLen int
		wantMethodsLen int
	}{
		{"empty all", "", "", "", false, 0, 2},
		{"origins only", "http://localhost", "", "", true, 1, 2},
		{"with methods", "http://localhost", "GET,POST,PUT", "", true, 1, 3},
		{"with headers", "http://localhost", "", "X-Custom", true, 1, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CORSConfigFromFlags(tt.origins, tt.methods, tt.headers)
			if config.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", config.Enabled, tt.wantEnabled)
			}
			if len(config.Origins) != tt.wantOriginsLen {
				t.Errorf("len(Origins) = %d, want %d", len(config.Origins), tt.wantOriginsLen)
			}
			if len(config.Methods) != tt.wantMethodsLen {
				t.Errorf("len(Methods) = %d, want %d", len(config.Methods), tt.wantMethodsLen)
			}
		})
	}
}

func TestCORSMiddleware_Disabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := CORSConfig{Enabled: false}
	wrapped := CORSMiddleware(handler, config)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	wrapped.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCORSMiddleware_Enabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := CORSConfig{
		Enabled: true,
		Origins: []string{"http://localhost"},
		Methods: []string{"GET", "POST"},
		Headers: []string{"Content-Type"},
	}
	wrapped := CORSMiddleware(handler, config)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "http://localhost")
	wrapped.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
