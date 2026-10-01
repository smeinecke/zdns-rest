package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

// publicPaths are endpoints that never require authentication or count
// against rate limits (health probes, metrics).
var publicPaths = map[string]bool{
	"/ping":    true,
	"/health":  true,
	"/ready":   true,
	"/metrics": true,
}

// isPublicPath reports whether the given request path is a public endpoint.
func isPublicPath(path string) bool {
	return publicPaths[strings.TrimSuffix(path, "/")]
}

// AuthMiddleware wraps an HTTP handler with API key authentication
// If apiKey is empty, authentication is disabled. trustedProxies controls
// whether forwarded headers are honored when logging the client IP.
func AuthMiddleware(next http.Handler, apiKey string, trustedProxies []*net.IPNet) http.Handler {
	if apiKey == "" {
		log.Info("API key authentication disabled")
		return next
	}

	log.Info("API key authentication enabled")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		providedKey := extractAPIKey(r)

		if providedKey == "" {
			authFailures.Inc()
			log.WithFields(log.Fields{
				"client_ip": getClientIP(r, trustedProxies),
			}).Warn("API request missing authentication")
			ErrorResponse(w, ErrUnauthorized, "")
			return
		}

		if subtle.ConstantTimeCompare([]byte(providedKey), []byte(apiKey)) != 1 {
			authFailures.Inc()
			log.WithFields(log.Fields{
				"client_ip": getClientIP(r, trustedProxies),
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
