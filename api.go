package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/jinzhu/copier"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns/iohandlers"
	"github.com/zmap/zdns/pkg/zdns"
)

type StreamOutputHandler struct {
	writer http.ResponseWriter
}

// NewStreamOutputHandler returns a new StreamOutputHandler that will write results to the given http.ResponseWriter.
func NewStreamOutputHandler(w http.ResponseWriter) *StreamOutputHandler {
	return &StreamOutputHandler{
		writer: w,
	}
}

// WriteResults takes a channel of strings and writes them to the embedded http.ResponseWriter.
// The WaitGroup is used to signal when the write operation is complete. The function will block until the
// channel is closed. If the http.ResponseWriter implements the http.Flusher interface, WriteResults will
// call Flush() after writing all the results in order to ensure that the writes are sent to the client as
// soon as possible.
func (h *StreamOutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()
	for n := range results {
		if _, err := h.writer.Write([]byte(n + "\n")); err != nil {
			return err
		}
	}

	if f, ok := h.writer.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// CachedStreamOutputHandler wraps StreamOutputHandler with caching
type CachedStreamOutputHandler struct {
	*StreamOutputHandler
	module     string
	nameserver string
	requestID  string
	mu         sync.Mutex
}

// NewCachedStreamOutputHandler creates a new caching-aware output handler
func NewCachedStreamOutputHandler(w http.ResponseWriter, module, nameserver, requestID string) *CachedStreamOutputHandler {
	return &CachedStreamOutputHandler{
		StreamOutputHandler: NewStreamOutputHandler(w),
		module:              module,
		nameserver:          nameserver,
		requestID:           requestID,
	}
}

// WriteResultsWithCache writes results and caches them
func (h *CachedStreamOutputHandler) WriteResultsWithCache(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()

	cache := GetCache()

	for n := range results {
		// Write to response
		if _, err := h.writer.Write([]byte(n + "\n")); err != nil {
			return err
		}

		// Cache the result if caching is enabled
		if cache != nil && cache.enabled {
			// Parse the result to extract domain name
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(n), &result); err == nil {
				if name, ok := result["name"].(string); ok {
					cache.Set(h.module, name, h.nameserver, n)
					log.WithFields(log.Fields{
						"request_id": h.requestID,
						"module":     h.module,
						"domain":     name,
					}).Debug("Cached DNS result")
				}
			}
		}
	}

	if f, ok := h.writer.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// domainRegex validates RFC 1123 hostnames
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)

// RateLimiter implements a simple token bucket rate limiter per IP
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter with the given limit and window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request from the given IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	if rl == nil || rl.limit <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old requests and count recent ones
	var recent []time.Time
	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		rl.requests[ip] = recent
		return false
	}

	recent = append(recent, now)
	rl.requests[ip] = recent
	return true
}

// RateLimitMiddleware wraps an HTTP handler with rate limiting
func RateLimitMiddleware(next http.Handler, limiter *RateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		if !limiter.Allow(ip) {
			rateLimitHits.Inc()
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.limit))
			w.Header().Set("X-RateLimit-Window", fmt.Sprintf("%v", limiter.window))
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(APIResultType{
				Code:    3000,
				Message: "Rate limit exceeded. Please try again later.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LimitBodySize wraps a handler to limit request body size
func LimitBodySize(next http.Handler, maxSize int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)
		next.ServeHTTP(w, r)
	})
}

// validateDomain checks if a domain name is valid
func validateDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}

type DNSRequests struct {
	Module  string   `json:"module"`
	Queries []string `json:"queries"`
}

type APIResultType struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIResult writes a JSON response with the given code and message to the
// given http.ResponseWriter. It will also set the HTTP status code to 400 if
// the code is 2000 or higher.
func APIResult(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if code >= 2000 {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = json.NewEncoder(w).Encode(APIResultType{Code: code,
		Message: message,
	})
}

// pingRequest is the handler for the GET /ping route. It returns a JSON result
// with code 1000 and the message "Command completed successfully".
func pingRequest(w http.ResponseWriter, r *http.Request) {
	APIResult(w, 1000, "Command completed successfully")
}

// BuildInfo holds information about the build
type BuildInfo struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Commit    string `json:"commit"`
	Date      string `json:"build_date"`
}

var buildInfo = BuildInfo{
	Version:   "dev",
	GoVersion: runtime.Version(),
	Commit:    "unknown",
	Date:      "unknown",
}

func init() {
	// Try to read build info from Go binary
	if info, ok := debug.ReadBuildInfo(); ok {
		buildInfo.GoVersion = info.GoVersion
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				buildInfo.Commit = setting.Value
			case "vcs.time":
				buildInfo.Date = setting.Value
			}
		}
	}
}

// healthResponse represents the health check response
type healthResponse struct {
	Code      int       `json:"code"`
	Message   string    `json:"message"`
	Status    string    `json:"status"`
	BuildInfo BuildInfo `json:"build_info"`
}

// healthRequest is the handler for the GET /health route
func healthRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(healthResponse{
		Code:      1000,
		Message:   "Healthy",
		Status:    "up",
		BuildInfo: buildInfo,
	})
}

// readyResponse represents the readiness check response
type readyResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Ready   bool   `json:"ready"`
}

// readyRequest is the handler for the GET /ready route
func readyRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ready := true
	_ = json.NewEncoder(w).Encode(readyResponse{
		Code:    1000,
		Message: "Ready",
		Ready:   ready,
	})
}

// notFound is the handler for any route that doesn't match any of the defined routes.
// It returns a JSON result with code 2000 and the message "Unknown command".
func notFound(w http.ResponseWriter, r *http.Request) {
	APIResult(w, 2000, "Unknown command")
}

// circuitBreaker is the global circuit breaker instance for DNS lookups
var circuitBreaker *CircuitBreaker

// runModule is the main handler function for the API server. It handles both form encoded
// and JSON encoded requests. It extracts the lookup type from the URL or the request
// body, and then runs the lookup using the zdns library.
// It also integrates with the DNS cache for improved performance.
func runModule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.Header().Set("Content-Type", "application/x-ndjson")
	requestID := w.Header().Get(RequestIDHeader)

	var dr DNSRequests
	var gc zdns.GlobalConf
	if err := copier.Copy(&gc, &GC); err != nil {
		ErrorResponse(w, ErrCopyConfig, err.Error())
		return
	}

	// Determine module and collect queries
	var queries []string
	var module string

	req_content_type := r.Header.Get("Content-Type")
	if req_content_type == "application/json" {
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			ErrorResponse(w, ErrReadRequest, err.Error())
			return
		}

		err = json.Unmarshal(reqBody, &dr)
		if err != nil {
			ErrorResponse(w, ErrDecodeRequest, err.Error())
			return
		}

		if dr.Module == "" {
			dr.Module = "A"
		}
		module = dr.Module

		if len(dr.Queries) < 1 {
			ErrorResponse(w, ErrEmptyQueries, "")
			return
		}

		if len(dr.Queries) > GC.MaxQueriesPerReq {
			ErrorResponse(w, ErrTooManyQueries, fmt.Sprintf("Maximum allowed: %d", GC.MaxQueriesPerReq))
			return
		}

		// Validate domain names
		for _, q := range dr.Queries {
			if !validateDomain(q) {
				ErrorResponse(w, ErrInvalidDomain, q)
				return
			}
		}

		queries = dr.Queries
	} else {
		if val, ok := vars["lookup"]; ok {
			module = val
		} else {
			module = "A"
		}

		// Read body for plain text queries
		body, err := io.ReadAll(r.Body)
		if err != nil {
			ErrorResponse(w, ErrReadRequest, err.Error())
			return
		}

		// Parse lines
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && validateDomain(line) {
				queries = append(queries, line)
			}
		}
	}

	gc.Module = strings.ToUpper(module)
	factory := zdns.GetLookup(gc.Module)
	if factory == nil {
		ErrorResponse(w, ErrInvalidModule, gc.Module)
		return
	}

	// Check circuit breaker
	if GC.CircuitBreakerEnabled && !circuitBreaker.CanExecute() {
		ErrorResponse(w, ErrCircuitBreakerOpen, "")
		return
	}

	// Get cache and nameserver for cache key
	cache := GetCache()
	nameserver := ""
	if len(GC.NameServers) > 0 {
		nameserver = GC.NameServers[0]
	}

	// Check cache for queries and collect uncached ones
	var uncachedQueries []string
	cacheHits := make(map[string]string)

	if cache != nil && cache.enabled {
		for _, query := range queries {
			if entry := cache.Get(gc.Module, query, nameserver, true); entry != nil {
				cacheHits[query] = entry.Result
				log.WithFields(log.Fields{
					"request_id": requestID,
					"module":     gc.Module,
					"domain":     query,
				}).Debug("Cache hit")
			} else {
				uncachedQueries = append(uncachedQueries, query)
			}
		}
	} else {
		uncachedQueries = queries
	}

	// Write cached results immediately
	for _, result := range cacheHits {
		w.Write([]byte(result + "\n"))
	}

	// If all queries were cached, we're done
	if len(uncachedQueries) == 0 {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}

	// Setup i/o for uncached queries
	t := strings.NewReader(strings.Join(uncachedQueries, "\n"))
	gc.InputHandler = iohandlers.NewStreamInputHandler(t)

	// Use caching output handler
	cachedHandler := NewCachedStreamOutputHandler(w, gc.Module, nameserver, requestID)
	gc.OutputHandler = cachedHandler.StreamOutputHandler

	factory.SetFlags(GC.Flags)

	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		if GC.CircuitBreakerEnabled {
			circuitBreaker.RecordFailure()
		}
		// Try to serve stale cache entries on error
		servedStale := false
		if cache != nil && cache.enabled {
			for _, query := range uncachedQueries {
				if entry := cache.Get(gc.Module, query, nameserver, true); entry != nil {
					w.Write([]byte(entry.Result + "\n"))
					servedStale = true
					log.WithFields(log.Fields{
						"request_id": requestID,
						"module":     gc.Module,
						"domain":     query,
					}).Warn("Served stale cache entry due to lookup error")
				}
			}
		}
		if !servedStale {
			ErrorResponse(w, ErrFactoryInit, err.Error())
		}
		return
	}

	// run it.
	if err := zdns.DoLookups(factory, &gc); err != nil {
		if GC.CircuitBreakerEnabled {
			circuitBreaker.RecordFailure()
		}
		// Try to serve stale cache entries on error
		servedStale := false
		if cache != nil && cache.enabled {
			for _, query := range uncachedQueries {
				if entry := cache.Get(gc.Module, query, nameserver, true); entry != nil {
					w.Write([]byte(entry.Result + "\n"))
					servedStale = true
					log.WithFields(log.Fields{
						"request_id": requestID,
						"module":     gc.Module,
						"domain":     query,
					}).Warn("Served stale cache entry due to lookup error")
				}
			}
		}
		if !servedStale {
			ErrorResponse(w, ErrRunLookups, err.Error())
		}
		return
	}

	// Record success for circuit breaker
	if GC.CircuitBreakerEnabled {
		circuitBreaker.RecordSuccess()
	}

	// allow the factory to finalize itself
	if err := factory.Finalize(); err != nil {
		ErrorResponse(w, ErrFactoryFinalize, err.Error())
		return
	}
}

// startServer sets up the gorilla/mux router and starts the server on the configured address and port.
// It will serve the following endpoints:
// - POST /job/{lookup}: runs a job for the given lookup type
// - POST /job: runs a job with JSON body
// - GET /ping: health check
// - GET /health: detailed health check with build info
// - GET /ready: readiness probe
// - GET /metrics: Prometheus metrics
// - Anything else: returns a 404 JSON response
func startServer() {
	// Initialize circuit breaker if enabled
	if GC.CircuitBreakerEnabled {
		circuitBreaker = NewCircuitBreaker(GC.CircuitBreakerFailures, time.Duration(GC.CircuitBreakerTimeout)*time.Second)
		log.Infof("Circuit breaker enabled: threshold=%d, timeout=%ds", GC.CircuitBreakerFailures, GC.CircuitBreakerTimeout)
	}

	// Initialize DNS cache
	InitCache(GC.CacheEnabled, GC.CacheMaxSize, time.Duration(GC.CacheTTL)*time.Second)
	if GC.CacheEnabled {
		globalCache.staleTTL = time.Duration(GC.CacheStaleTTL) * time.Second
	}

	// Initialize job manager
	InitJobManager(10)

	// Setup routes
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/job/{lookup}", runModule).Methods("POST")
	r.HandleFunc("/job", runModule).Methods("POST")

	// Async job routes
	r.HandleFunc("/jobs", createJobRequest).Methods("POST")
	r.HandleFunc("/jobs", listJobsRequest).Methods("GET")
	r.HandleFunc("/jobs/{job_id}", getJobRequest).Methods("GET")
	r.HandleFunc("/jobs/{job_id}/results", getJobResultsRequest).Methods("GET")
	r.HandleFunc("/jobs/{job_id}", cancelJobRequest).Methods("DELETE")

	r.HandleFunc("/ping", pingRequest)
	r.HandleFunc("/health", healthRequest)
	r.HandleFunc("/ready", readyRequest)
	r.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		MetricsHandler().ServeHTTP(w, r)
	})
	r.NotFoundHandler = http.HandlerFunc(notFound)

	// Setup pprof routes on a separate port if enabled
	if GC.EnablePprof {
		go func() {
			pprofAddr := net.JoinHostPort(GC.ApiIP, fmt.Sprintf("%d", GC.PprofPort))
			log.Info("Starting pprof server on ", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Error("pprof server error: ", err)
			}
		}()
	}

	// Build middleware chain
	var middlewares []Middleware

	// CORS first (outermost)
	corsConfig := CORSConfigFromFlags(GC.CORSOrigins, GC.CORSMethods, GC.CORSHeaders)
	middlewares = append(middlewares, func(next http.Handler) http.Handler {
		return CORSMiddleware(next, corsConfig)
	})

	// Metrics
	middlewares = append(middlewares, MetricsMiddleware)

	// Logging
	middlewares = append(middlewares, LoggingMiddleware)

	// Authentication
	middlewares = append(middlewares, func(next http.Handler) http.Handler {
		return AuthMiddleware(next, GC.APIKey)
	})

	// Rate limiting
	if GC.RateLimitEnabled {
		limiter := NewRateLimiter(GC.RateLimitRequests, time.Duration(GC.RateLimitWindow)*time.Second)
		middlewares = append(middlewares, func(next http.Handler) http.Handler {
			return RateLimitMiddleware(next, limiter)
		})
		log.Infof("Rate limiting enabled: %d requests per %d seconds per IP", GC.RateLimitRequests, GC.RateLimitWindow)
	}

	// Body size limit
	if GC.MaxRequestBodySize > 0 {
		middlewares = append(middlewares, func(next http.Handler) http.Handler {
			return LimitBodySize(next, GC.MaxRequestBodySize)
		})
	}

	// Recovery (innermost)
	middlewares = append(middlewares, RecoverMiddleware)

	// Apply middleware chain
	handler := ChainMiddleware(r, middlewares...)

	addr := net.JoinHostPort(GC.ApiIP, fmt.Sprintf("%d", GC.ApiPort))
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  time.Duration(GC.RequestTimeout) * time.Second,
		WriteTimeout: time.Duration(GC.RequestTimeout) * time.Second,
	}

	// Start server with or without TLS
	go func() {
		if GC.TLSEnabled {
			log.Info("Starting HTTPS Server on ", addr)
			if err := srv.ListenAndServeTLS(GC.TLSCertFile, GC.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatal("Server listen error: ", err)
			}
		} else {
			log.Info("Starting HTTP Server on ", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal("Server listen error: ", err)
			}
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}
	log.Info("Server exited")
}
