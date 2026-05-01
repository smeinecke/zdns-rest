package main

import (
	"net/http"

	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	Enabled bool
	Origins []string
	Methods []string
	Headers []string
}

// CORSMiddleware wraps an HTTP handler with CORS support
// If CORS is not enabled, returns the handler unchanged (secure by default)
func CORSMiddleware(next http.Handler, config CORSConfig) http.Handler {
	if !config.Enabled || len(config.Origins) == 0 {
		log.Info("CORS disabled - denying cross-origin requests")
		return next
	}

	log.Infof("CORS enabled for origins: %v", config.Origins)

	c := cors.New(cors.Options{
		AllowedOrigins:   config.Origins,
		AllowedMethods:   config.Methods,
		AllowedHeaders:   config.Headers,
		AllowCredentials: true,
		Debug:            GC.Verbosity >= 5,
	})

	return c.Handler(next)
}

// CORSConfigFromFlags creates CORSConfig from global configuration
func CORSConfigFromFlags(origins, methods, headers string) CORSConfig {
	config := CORSConfig{
		Enabled: false,
		Methods: []string{"GET", "POST"},
		Headers: []string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID"},
	}

	if origins == "" {
		return config
	}

	config.Enabled = true
	config.Origins = splitAndTrim(origins, ",")

	if methods != "" {
		config.Methods = splitAndTrim(methods, ",")
	}

	if headers != "" {
		// Add custom headers to defaults
		customHeaders := splitAndTrim(headers, ",")
		config.Headers = append(config.Headers, customHeaders...)
	}

	return config
}

// splitAndTrim splits a string by separator and trims whitespace from each part
func splitAndTrim(s, sep string) []string {
	parts := []string{}
	for _, p := range splitString(s, sep) {
		if trimmed := trimSpace(p); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// Helper functions to avoid import conflicts
func splitString(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i < len(s)-len(sep)+1 && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
