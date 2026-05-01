package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP request metrics
	requestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "zdns_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path"},
	)

	// DNS lookup metrics
	dnsLookupCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_dns_lookups_total",
			Help: "Total number of DNS lookups performed",
		},
		[]string{"module", "status"},
	)

	dnsLookupDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "zdns_dns_lookup_duration_seconds",
			Help:    "DNS lookup duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"module"},
	)

	// Rate limiting metrics
	rateLimitHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_rate_limit_hits_total",
			Help: "Total number of requests that hit rate limits",
		},
	)

	// Authentication metrics
	authFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_auth_failures_total",
			Help: "Total number of authentication failures",
		},
	)

	// Active connections gauge
	activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "zdns_active_connections",
			Help: "Number of active connections",
		},
	)
)

// MetricsMiddleware wraps an HTTP handler to collect Prometheus metrics
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()

		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(wrapped.statusCode)

		requestCounter.WithLabelValues(r.Method, r.URL.Path, status).Inc()
		requestDuration.WithLabelValues(r.URL.Path).Observe(duration)
	})
}

// responseRecorder wraps http.ResponseWriter to capture the status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rr *responseRecorder) WriteHeader(code int) {
	if !rr.written {
		rr.statusCode = code
		rr.written = true
		rr.ResponseWriter.WriteHeader(code)
	}
}

// MetricsHandler returns the Prometheus metrics HTTP handler
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
