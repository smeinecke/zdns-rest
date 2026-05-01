package main

import (
	"encoding/json"
	"net/http"
)

// ErrorCode represents a structured error code with HTTP status mapping
type ErrorCode struct {
	Code       int
	Message    string
	HTTPStatus int
}

var (
	// Success
	ErrSuccess = ErrorCode{Code: 1000, Message: "Command completed successfully", HTTPStatus: http.StatusOK}

	// Client errors (4xx mapping)
	ErrUnknownCommand     = ErrorCode{Code: 2000, Message: "Unknown command", HTTPStatus: http.StatusBadRequest}
	ErrDecodeRequest      = ErrorCode{Code: 2001, Message: "Failed to decode request", HTTPStatus: http.StatusBadRequest}
	ErrReadRequest        = ErrorCode{Code: 2002, Message: "Failed to read request body", HTTPStatus: http.StatusBadRequest}
	ErrEmptyQueries       = ErrorCode{Code: 2005, Message: "Queries array empty", HTTPStatus: http.StatusBadRequest}
	ErrTooManyQueries     = ErrorCode{Code: 2006, Message: "Too many queries", HTTPStatus: http.StatusBadRequest}
	ErrInvalidModule      = ErrorCode{Code: 2007, Message: "Invalid lookup module specified", HTTPStatus: http.StatusBadRequest}
	ErrInvalidDomain      = ErrorCode{Code: 2008, Message: "Invalid domain name", HTTPStatus: http.StatusBadRequest}
	ErrRequestTooLarge    = ErrorCode{Code: 2009, Message: "Request entity too large", HTTPStatus: http.StatusRequestEntityTooLarge}
	ErrRateLimited        = ErrorCode{Code: 3000, Message: "Rate limit exceeded. Please try again later.", HTTPStatus: http.StatusTooManyRequests}
	ErrUnauthorized       = ErrorCode{Code: 4001, Message: "Unauthorized: valid API key required", HTTPStatus: http.StatusUnauthorized}
	ErrCircuitBreakerOpen = ErrorCode{Code: 5001, Message: "Service temporarily unavailable due to upstream DNS failures", HTTPStatus: http.StatusServiceUnavailable}

	// Server errors (5xx)
	ErrCopyConfig      = ErrorCode{Code: 2400, Message: "Failed to copy configuration", HTTPStatus: http.StatusInternalServerError}
	ErrFactoryInit     = ErrorCode{Code: 2401, Message: "Factory was unable to initialize", HTTPStatus: http.StatusInternalServerError}
	ErrRunLookups      = ErrorCode{Code: 2402, Message: "Unable to run lookups", HTTPStatus: http.StatusInternalServerError}
	ErrFactoryFinalize = ErrorCode{Code: 2403, Message: "Factory was unable to finalize", HTTPStatus: http.StatusInternalServerError}
)

// ErrorResponse generates a JSON error response with the proper HTTP status code
func ErrorResponse(w http.ResponseWriter, err ErrorCode, detail string) {
	msg := err.Message
	if detail != "" {
		msg += ": " + detail
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	json.NewEncoder(w).Encode(APIResultType{Code: err.Code, Message: msg})
}
