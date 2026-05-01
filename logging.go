package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// RequestIDHeader is the header name for request ID
const RequestIDHeader = "X-Request-ID"

// generateRequestID generates a unique request ID
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// LoggingMiddleware wraps an HTTP handler with structured request logging
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Get or generate request ID
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set(RequestIDHeader, requestID)

		// Wrap response writer to capture status
		wrapped := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			requestID:      requestID,
		}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Log request details
		log.WithFields(log.Fields{
			"request_id":  requestID,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"client_ip":   getClientIP(r),
			"user_agent":  r.UserAgent(),
		}).Info("HTTP request completed")
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	requestID  string
	written    bool
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	if !lrw.written {
		lrw.statusCode = code
		lrw.written = true
		lrw.ResponseWriter.WriteHeader(code)
	}
}

func (lrw *loggingResponseWriter) Header() http.Header {
	return lrw.ResponseWriter.Header()
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if !lrw.written {
		lrw.WriteHeader(http.StatusOK)
	}
	return lrw.ResponseWriter.Write(b)
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return xff
	}

	xri := r.Header.Get("X-Real-Ip")
	if xri != "" {
		return xri
	}

	return r.RemoteAddr
}

// LogDNSLookup logs a DNS lookup result with request correlation
func LogDNSLookup(requestID, module, domain, status string, duration time.Duration) {
	log.WithFields(log.Fields{
		"request_id":  requestID,
		"module":      module,
		"domain":      domain,
		"status":      status,
		"duration_ms": duration.Milliseconds(),
	}).Debug("DNS lookup completed")

	dnsLookupCounter.WithLabelValues(module, status).Inc()
	dnsLookupDuration.WithLabelValues(module).Observe(duration.Seconds())
}
