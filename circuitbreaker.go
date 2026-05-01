package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	StateClosed   CircuitState = iota // Normal operation
	StateOpen                         // Failing fast
	StateHalfOpen                     // Testing if service recovered
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	mu sync.RWMutex

	failureThreshold int
	timeoutDuration  time.Duration
	halfOpenMaxCalls int

	state           CircuitState
	failures        int
	successes       int
	lastFailureTime time.Time
}

// NewCircuitBreaker creates a new circuit breaker with the given settings
func NewCircuitBreaker(failureThreshold int, timeoutDuration time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if timeoutDuration <= 0 {
		timeoutDuration = 60 * time.Second
	}

	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		timeoutDuration:  timeoutDuration,
		halfOpenMaxCalls: 3,
		state:            StateClosed,
	}
}

// CanExecute returns true if the circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	if cb == nil {
		return true
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailureTime) > cb.timeoutDuration {
			// Transition to half-open
			log.Info("Circuit breaker transitioning from open to half-open")
			cb.state = StateHalfOpen
			cb.failures = 0
			cb.successes = 0
			return true
		}
		return false
	case StateHalfOpen:
		return cb.successes+cb.failures < cb.halfOpenMaxCalls
	default:
		return true
	}
}

// RecordSuccess records a successful call
func (cb *CircuitBreaker) RecordSuccess() {
	if cb == nil {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		// Reset failure count on success
		if cb.failures > 0 {
			cb.failures = 0
		}

	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.halfOpenMaxCalls {
			log.Info("Circuit breaker transitioning from half-open to closed")
			cb.transitionTo(StateClosed)
		}
	}
}

// RecordFailure records a failed call
func (cb *CircuitBreaker) RecordFailure() {
	if cb == nil {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		cb.failures++
		cb.lastFailureTime = time.Now()
		if cb.failures >= cb.failureThreshold {
			log.Warnf("Circuit breaker transitioning from closed to open after %d failures", cb.failures)
			cb.transitionTo(StateOpen)
		}

	case StateOpen:
		// If timeout expired, transition to half-open and record failure
		if time.Since(cb.lastFailureTime) > cb.timeoutDuration {
			cb.state = StateHalfOpen
			cb.failures = 0
			cb.successes = 0
			log.Warn("Circuit breaker transitioning from half-open to open")
			cb.lastFailureTime = time.Now()
			cb.transitionTo(StateOpen)
		}
		// If timeout not expired, do nothing (stay in Open)

	case StateHalfOpen:
		log.Warn("Circuit breaker transitioning from half-open to open")
		cb.lastFailureTime = time.Now()
		cb.transitionTo(StateOpen)
	}
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitState {
	if cb == nil {
		return StateClosed
	}

	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Auto-transition from Open to Half-Open when timeout expires
	if cb.state == StateOpen && time.Since(cb.lastFailureTime) > cb.timeoutDuration {
		cb.mu.RUnlock()
		cb.mu.Lock()
		if cb.state == StateOpen && time.Since(cb.lastFailureTime) > cb.timeoutDuration {
			log.Info("Circuit breaker transitioning from open to half-open")
			cb.state = StateHalfOpen
			cb.failures = 0
			cb.successes = 0
		}
		cb.mu.Unlock()
		cb.mu.RLock()
	}

	return cb.state
}

// transitionTo changes the circuit breaker state
// Must be called with lock held
func (cb *CircuitBreaker) transitionTo(state CircuitState) {
	cb.state = state
	cb.failures = 0
	cb.successes = 0
}
