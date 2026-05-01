package main

import (
	"net/http"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

// Middleware is a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// ChainMiddleware chains multiple middlewares together
func ChainMiddleware(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// RecoverMiddleware recovers from panics in HTTP handlers
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				log.Errorf("Panic recovered: %v\n%s", rec, buf[:n])
				ErrorResponse(w, ErrorCode{
					Code:       5000,
					Message:    "Internal server error",
					HTTPStatus: http.StatusInternalServerError,
				}, "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// TimeoutMiddleware adds a request-level timeout
func TimeoutMiddleware(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, timeout, `{"code":5002,"message":"Request timeout"}`)
	}
}
