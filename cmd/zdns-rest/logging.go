package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// RequestIDHeader is the header name for request ID
const RequestIDHeader = "X-Request-ID"

// generateRequestID generates a unique request ID
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b)
}

// LoggingMiddleware wraps an HTTP handler with structured request logging.
// trustedProxies controls whether X-Forwarded-For/X-Real-IP are honored when
// deriving the client IP; pass nil to only trust the direct peer.
func LoggingMiddleware(next http.Handler, trustedProxies []*net.IPNet) http.Handler {
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
			"client_ip":   getClientIP(r, trustedProxies),
			"user_agent":  r.UserAgent(),
		}).Info("HTTP request completed")
	})
}

// parseTrustedProxies parses a comma-separated list of IPs and CIDRs into a
// list of networks. Bare IPs become /32 or /128 networks.
func parseTrustedProxies(s string) []*net.IPNet {
	var proxies []*net.IPNet
	for _, p := range splitAndTrim(s, ",") {
		if _, cidr, err := net.ParseCIDR(p); err == nil {
			proxies = append(proxies, cidr)
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			proxies = append(proxies, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		log.Warnf("Ignoring invalid trusted proxy entry %q", p)
	}
	return proxies
}

// isTrustedProxy reports whether ip is covered by the trusted proxy list.
func isTrustedProxy(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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

func (lrw *loggingResponseWriter) Flush() {
	if flusher, ok := lrw.ResponseWriter.(http.Flusher); ok {
		if !lrw.written {
			lrw.WriteHeader(http.StatusOK)
		}
		flusher.Flush()
	}
}

func (lrw *loggingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := lrw.ResponseWriter.(io.ReaderFrom); ok {
		if !lrw.written {
			lrw.WriteHeader(http.StatusOK)
		}
		return rf.ReadFrom(r)
	}
	return io.Copy(lrw.ResponseWriter, r)
}

// getClientIP extracts the client IP from the request. Forwarded headers are
// only honored when the direct peer is in trustedProxies; otherwise a client
// could spoof its IP to defeat rate limiting and forge log fields.
func getClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}

	peerIP := net.ParseIP(peer)
	if peerIP == nil || !isTrustedProxy(peerIP, trustedProxies) {
		return peer
	}

	// Check X-Forwarded-For header; the first entry is the originating client
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}

	return peer
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
