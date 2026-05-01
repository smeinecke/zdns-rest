package main

import (
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

// AuthMiddleware wraps an HTTP handler with API key authentication
// If apiKey is empty, authentication is disabled
func AuthMiddleware(next http.Handler, apiKey string) http.Handler {
	if apiKey == "" {
		log.Info("API key authentication disabled")
		return next
	}

	log.Info("API key authentication enabled")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providedKey := extractAPIKey(r)

		if providedKey == "" {
			authFailures.Inc()
			log.WithFields(log.Fields{
				"client_ip": getClientIP(r),
			}).Warn("API request missing authentication")
			ErrorResponse(w, ErrUnauthorized, "")
			return
		}

		if providedKey != apiKey {
			authFailures.Inc()
			log.WithFields(log.Fields{
				"client_ip": getClientIP(r),
			}).Warn("API request with invalid API key")
			ErrorResponse(w, ErrUnauthorized, "invalid API key")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractAPIKey extracts the API key from the request
// Supports: Authorization: Bearer <key> or X-API-Key: <key>
func extractAPIKey(r *http.Request) string {
	// Check Authorization header (Bearer token)
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}

	// Check X-API-Key header
	return r.Header.Get("X-API-Key")
}
