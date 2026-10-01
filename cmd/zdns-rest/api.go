package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: pprof endpoint is opt-in via --enable-pprof
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// validateLookupParams normalizes and validates the module name and query
// count shared by the sync and async lookup endpoints. It writes the error
// response itself and returns ok=false on failure.
func (s *Server) validateLookupParams(w http.ResponseWriter, module string, numQueries int) (string, bool) {
	if numQueries < 1 {
		ErrorResponse(w, ErrEmptyQueries, "")
		return "", false
	}
	if numQueries > s.cfg.MaxQueriesPerReq {
		ErrorResponse(w, ErrTooManyQueries, fmt.Sprintf("Maximum allowed: %d", s.cfg.MaxQueriesPerReq))
		return "", false
	}
	if module == "" {
		module = "A"
	}
	module = strings.ToUpper(module)
	if _, ok := s.engine.modules[module]; !ok {
		ErrorResponse(w, ErrInvalidModule, module)
		return "", false
	}
	return module, true
}

type OrderedResultCollector struct {
	mu      sync.Mutex
	results map[string][]string
}

func NewOrderedResultCollector() *OrderedResultCollector {
	return &OrderedResultCollector{
		results: make(map[string][]string),
	}
}

func (c *OrderedResultCollector) Add(query, result string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[query] = append(c.results[query], result)
}

// Pop removes and returns the next buffered result for the given query.
func (c *OrderedResultCollector) Pop(query string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if queue := c.results[query]; len(queue) > 0 {
		c.results[query] = queue[1:]
		return queue[0], true
	}
	return "", false
}

func (c *OrderedResultCollector) Ordered(queries []string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	ordered := make([]string, 0, len(queries))
	for _, query := range queries {
		if queue := c.results[query]; len(queue) > 0 {
			ordered = append(ordered, queue[0])
			c.results[query] = queue[1:]
		}
	}
	return ordered
}

// domainRegex validates RFC 1123 hostnames
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)

// RateLimiter implements a simple token bucket rate limiter per IP
type RateLimiter struct {
	mu         sync.Mutex
	requests   map[string][]time.Time
	limit      int
	window     time.Duration
	calls      int
	sweepEvery int
}

// NewRateLimiter creates a new rate limiter with the given limit and window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:   make(map[string][]time.Time),
		limit:      limit,
		window:     window,
		sweepEvery: 1024,
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

	if len(recent) == 0 {
		// avoid leaving empty entries around forever
		delete(rl.requests, ip)
	}
	recent = append(recent, now)
	rl.requests[ip] = recent

	// Periodically evict IPs whose last request aged out of the window so the
	// map does not grow without bound for one-off clients.
	rl.calls++
	if rl.calls >= rl.sweepEvery {
		rl.calls = 0
		for ip, times := range rl.requests {
			if len(times) == 0 || times[len(times)-1].Before(cutoff) {
				delete(rl.requests, ip)
			}
		}
	}
	return true
}

// RateLimitMiddleware wraps an HTTP handler with rate limiting. Forwarded
// headers are only honored when the direct peer is in trustedProxies, so a
// direct client cannot bypass the limiter by spoofing X-Forwarded-For.
func RateLimitMiddleware(next http.Handler, limiter *RateLimiter, trustedProxies []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := getClientIP(r, trustedProxies)

		if !limiter.Allow(ip) {
			rateLimitHits.Inc()
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limiter.limit))
			w.Header().Set("X-RateLimit-Window", strconv.Itoa(int(limiter.window.Seconds())))
			ErrorResponse(w, ErrRateLimited, "")
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

// buildVersion is set at link time via -ldflags "-X main.buildVersion=x.y.z".
var buildVersion = "dev"

var buildInfo = BuildInfo{
	Version:   buildVersion,
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

// Server bundles the runtime dependencies used by the HTTP handlers. It is
// constructed once from a snapshot of the global configuration; handlers use
// the snapshot instead of reading package-level state on the request path.
type Server struct {
	cfg            GlobalConf
	jm             *JobManager
	cb             *CircuitBreaker
	trustedProxies []*net.IPNet
	engine         *lookupEngine
}

// newServerFromGC snapshots the global configuration (under GCMu) and builds
// a Server with all per-server dependencies from it.
func newServerFromGC() *Server {
	GCMu.RLock()
	cfg := GC
	GCMu.RUnlock()

	var cb *CircuitBreaker
	if cfg.CircuitBreakerEnabled {
		cb = NewCircuitBreaker(cfg.CircuitBreakerFailures, time.Duration(cfg.CircuitBreakerTimeout)*time.Second)
		log.Infof("Circuit breaker enabled: threshold=%d, timeout=%ds", cfg.CircuitBreakerFailures, cfg.CircuitBreakerTimeout)
	}

	InitCache(cfg.CacheEnabled, cfg.CacheMaxSize, time.Duration(cfg.CacheTTL)*time.Second)
	if cfg.CacheEnabled {
		GetCache().SetStaleTTL(time.Duration(cfg.CacheStaleTTL) * time.Second)
	}

	s := &Server{
		cfg:            cfg,
		cb:             cb,
		trustedProxies: parseTrustedProxies(cfg.TrustedProxies),
	}

	// Resolver setup happens outside the config lock — it may do network I/O
	// (local-address probing) and can legitimately abort startup on error.
	rc, err := buildResolverConfig(&s.cfg, AC.Config_file)
	if err != nil {
		log.Fatalf("invalid resolver configuration: %v", err)
	}
	modules := initLookupModules(&s.cfg, rc)
	if len(modules) == 0 {
		log.Fatal("no lookup modules available")
	}
	s.engine = &lookupEngine{cfg: &s.cfg, rc: rc, modules: modules}

	s.jm = NewJobManager(10, &s.cfg, cb, s.engine)
	return s
}

// recordOutcome records a lookup success/failure when the breaker is enabled.
// Safe on a nil receiver (feature disabled).
func (cb *CircuitBreaker) recordOutcome(success bool) {
	if success {
		cb.RecordSuccess()
	} else {
		cb.RecordFailure()
	}
}

// runModule is the main handler function for the API server. It handles both form encoded
// and JSON encoded requests. It extracts the lookup type from the URL or the request
// body, and then runs the lookup using the zdns library.
// It also integrates with the DNS cache for improved performance.
func (s *Server) runModule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.Header().Set("Content-Type", "application/x-ndjson")
	requestID := w.Header().Get(RequestIDHeader)

	var dr DNSRequests

	// Determine module and collect queries
	var queries []string
	var module string
	if val, ok := vars["lookup"]; ok {
		module = val
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		contentType = ""
	}
	if contentType == "application/json" {
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				ErrorResponse(w, ErrRequestTooLarge, "")
			} else {
				ErrorResponse(w, ErrReadRequest, err.Error())
			}
			return
		}

		err = json.Unmarshal(reqBody, &dr)
		if err != nil {
			ErrorResponse(w, ErrDecodeRequest, err.Error())
			return
		}

		// A module given in the URL takes precedence over the request body
		if module == "" {
			module = dr.Module
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
		// Read body for plain text queries
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				ErrorResponse(w, ErrRequestTooLarge, "")
			} else {
				ErrorResponse(w, ErrReadRequest, err.Error())
			}
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

	module, ok := s.validateLookupParams(w, module, len(queries))
	if !ok {
		return
	}

	// Check circuit breaker
	if s.cfg.CircuitBreakerEnabled && !s.cb.CanExecute() {
		ErrorResponse(w, ErrCircuitBreakerOpen, "")
		return
	}

	// Get cache and nameserver for cache key
	cache := GetCache()
	nameserver := ""
	if len(s.cfg.NameServers) > 0 {
		nameserver = s.cfg.NameServers[0]
	}

	// Check cache for queries and collect uncached ones
	var uncachedQueries []string
	collector := NewOrderedResultCollector()

	if cache != nil && cache.enabled {
		for _, query := range queries {
			if entry := cache.Get(module, query, nameserver, false); entry != nil {
				collector.Add(query, entry.Result)
				log.WithFields(log.Fields{
					"request_id": requestID,
					"module":     module,
					"domain":     query,
				}).Debug("Cache hit")
			} else {
				uncachedQueries = append(uncachedQueries, query)
			}
		}
	} else {
		uncachedQueries = queries
	}

	// If all queries were cached, we're done
	if len(uncachedQueries) == 0 {
		for _, result := range collector.Ordered(queries) {
			_, _ = w.Write([]byte(result + "\n"))
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}

	// servePartialResults writes any buffered fresh/cached results, filling the
	// gaps with stale cache entries. Returns true if anything was written.
	servePartialResults := func() bool {
		served := false
		for _, query := range queries {
			res, ok := collector.Pop(query)
			if !ok && cache != nil && cache.enabled {
				if entry := cache.Get(module, query, nameserver, true); entry != nil {
					res = entry.Result
					ok = true
					log.WithFields(log.Fields{
						"request_id": requestID,
						"module":     module,
						"domain":     query,
					}).Warn("Served stale cache entry due to lookup error")
				}
			}
			if !ok {
				continue
			}
			if _, err := w.Write([]byte(res + "\n")); err != nil {
				log.WithFields(log.Fields{
					"request_id": requestID,
					"module":     module,
					"domain":     query,
				}).Error("Failed to write result: ", err)
			} else {
				served = true
			}
		}
		if served {
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return served
	}

	// Consume worker output: buffer into the ordered collector, record
	// metrics, cache definitive answers.
	sink := &resultSink{
		requestID:  requestID,
		module:     module,
		nameserver: nameserver,
		collector:  collector,
		start:      time.Now(),
	}

	// Run lookups in a worker pool; each worker owns a zdns.Resolver and
	// closes it on exit (v2 resolvers carry per-lookup state and are not
	// goroutine-safe). Request cancellation aborts in-flight queries.
	results := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sink.consume(results)
	}()
	execErr := s.engine.executeQueries(r.Context(), module, uncachedQueries, nil, results)
	wg.Wait()

	if execErr != nil {
		s.cb.recordOutcome(false)
		// Try to serve buffered results or stale cache entries on error
		if !servePartialResults() {
			ErrorResponse(w, ErrRunLookups, execErr.Error())
		}
		return
	}

	// Record success for circuit breaker
	s.cb.recordOutcome(true)

	for _, result := range collector.Ordered(queries) {
		_, _ = w.Write([]byte(result + "\n"))
	}

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
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
	// Snapshot the global config and build all per-server dependencies; the
	// request path below never reads GC again.
	s := newServerFromGC()
	cfg := &s.cfg

	// Setup routes
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/job/{lookup}", s.runModule).Methods("POST")
	r.HandleFunc("/job", s.runModule).Methods("POST")

	// Async job routes
	r.HandleFunc("/jobs", s.createJobRequest).Methods("POST")
	r.HandleFunc("/jobs", s.listJobsRequest).Methods("GET")
	r.HandleFunc("/jobs/{job_id}", s.getJobRequest).Methods("GET")
	r.HandleFunc("/jobs/{job_id}/results", s.getJobResultsRequest).Methods("GET")
	r.HandleFunc("/jobs/{job_id}", s.cancelJobRequest).Methods("DELETE")

	r.HandleFunc("/ping", pingRequest)
	r.HandleFunc("/health", healthRequest)
	r.HandleFunc("/ready", readyRequest)
	metricsHandler := MetricsHandler()
	r.Handle("/metrics", metricsHandler)
	r.NotFoundHandler = http.HandlerFunc(notFound)

	// Metrics must run inside the router (via r.Use) so mux.CurrentRoute is
	// populated and the path label uses the route template. As an outer
	// middleware every request would be labeled "unmatched".
	r.Use(mux.MiddlewareFunc(MetricsMiddleware))

	// Setup pprof routes on a separate port if enabled
	if cfg.EnablePprof {
		pprofAddr := net.JoinHostPort(cfg.ApiIP, strconv.Itoa(cfg.PprofPort))
		pprofSrv := &http.Server{
			Addr:              pprofAddr,
			Handler:           http.DefaultServeMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go func() {
			log.Info("Starting pprof server on ", pprofAddr)
			if err := pprofSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("pprof server error: ", err)
			}
		}()
	}

	// Build middleware chain
	var middlewares []Middleware

	// CORS first (outermost)
	corsConfig := CORSConfigFromFlags(cfg.CORSOrigins, cfg.CORSMethods, cfg.CORSHeaders)
	middlewares = append(middlewares, func(next http.Handler) http.Handler {
		return CORSMiddleware(next, corsConfig, cfg.Verbosity >= 5)
	})

	// Logging
	middlewares = append(middlewares, func(next http.Handler) http.Handler {
		return LoggingMiddleware(next, s.trustedProxies)
	})

	// Authentication
	middlewares = append(middlewares, func(next http.Handler) http.Handler {
		return AuthMiddleware(next, cfg.APIKey, s.trustedProxies)
	})

	// Rate limiting
	if cfg.RateLimitEnabled {
		limiter := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)
		middlewares = append(middlewares, func(next http.Handler) http.Handler {
			return RateLimitMiddleware(next, limiter, s.trustedProxies)
		})
		log.Infof("Rate limiting enabled: %d requests per %d seconds per IP", cfg.RateLimitRequests, cfg.RateLimitWindow)
	}

	// Body size limit
	if cfg.MaxRequestBodySize > 0 {
		middlewares = append(middlewares, func(next http.Handler) http.Handler {
			return LimitBodySize(next, cfg.MaxRequestBodySize)
		})
	}

	// Recovery (innermost)
	middlewares = append(middlewares, RecoverMiddleware)

	// Apply middleware chain
	handler := ChainMiddleware(r, middlewares...)

	addr := net.JoinHostPort(cfg.ApiIP, strconv.Itoa(cfg.ApiPort))
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  time.Duration(cfg.RequestTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.RequestTimeout) * time.Second,
	}

	// Start server with or without TLS
	tlsEnabled := cfg.TLSEnabled
	tlsCertFile := cfg.TLSCertFile
	tlsKeyFile := cfg.TLSKeyFile
	go func() {
		if tlsEnabled {
			log.Info("Starting HTTPS Server on ", addr)
			if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
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

	if err := srv.Shutdown(ctx); err != nil {
		cancel()
		log.Fatal("Server forced to shutdown: ", err)
	}
	cancel()

	// Stop job workers: cancels pending/running job contexts so in-flight
	// lookups abort instead of running to completion during shutdown.
	s.jm.Stop()
	log.Info("Server exited")
}
