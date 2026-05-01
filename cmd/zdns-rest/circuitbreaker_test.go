package main

import (
	"testing"
	"time"
)

func TestCircuitBreaker_New(t *testing.T) {
	cb := NewCircuitBreaker(5, 60*time.Second)

	if cb == nil {
		t.Fatal("NewCircuitBreaker returned nil")
	}

	if cb.failureThreshold != 5 {
		t.Errorf("failureThreshold = %d, want 5", cb.failureThreshold)
	}

	if cb.timeoutDuration != 60*time.Second {
		t.Errorf("timeoutDuration = %v, want 60s", cb.timeoutDuration)
	}

	if cb.State() != StateClosed {
		t.Errorf("initial state = %v, want %v", cb.State(), StateClosed)
	}
}

func TestCircuitBreaker_NewWithDefaults(t *testing.T) {
	cb := NewCircuitBreaker(0, 0)

	if cb.failureThreshold != 5 {
		t.Errorf("default failureThreshold = %d, want 5", cb.failureThreshold)
	}

	if cb.timeoutDuration != 60*time.Second {
		t.Errorf("default timeoutDuration = %v, want 60s", cb.timeoutDuration)
	}
}

func TestCircuitBreaker_CanExecute(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	// Initially closed, should allow execution
	if !cb.CanExecute() {
		t.Error("Initial state: CanExecute should return true")
	}

	// Record failures to open circuit
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	// Circuit should be open now
	if cb.CanExecute() {
		t.Error("After 3 failures: CanExecute should return false")
	}

	if cb.State() != StateOpen {
		t.Errorf("State after 3 failures = %v, want %v", cb.State(), StateOpen)
	}
}

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	// Record successes while closed
	cb.RecordSuccess()
	cb.RecordSuccess()

	if !cb.CanExecute() {
		t.Error("After successes: CanExecute should return true")
	}
}

func TestCircuitBreaker_HalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != StateOpen {
		t.Errorf("State = %v, want %v", cb.State(), StateOpen)
	}

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// CanExecute should return true (half-open check)
	if !cb.CanExecute() {
		t.Error("After timeout: CanExecute should return true (half-open)")
	}
}

func TestCircuitBreaker_TransitionToClosed(t *testing.T) {
	cb := NewCircuitBreaker(5, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Should be half-open, allow some requests
	if !cb.CanExecute() {
		t.Error("Half-open: CanExecute should return true")
	}

	// Record successes to close circuit
	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordSuccess()

	if cb.State() != StateClosed {
		t.Errorf("State after successes = %v, want %v", cb.State(), StateClosed)
	}
}

func TestCircuitBreaker_TransitionToOpenFromHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// Wait for timeout to go half-open
	time.Sleep(60 * time.Millisecond)

	// Record failure while half-open should go back to open
	cb.RecordFailure()

	if cb.State() != StateOpen {
		t.Errorf("State after failure in half-open = %v, want %v", cb.State(), StateOpen)
	}
}

func TestCircuitBreaker_Nil(t *testing.T) {
	var cb *CircuitBreaker

	// All methods should handle nil gracefully
	if !cb.CanExecute() {
		t.Error("nil CanExecute should return true")
	}

	if cb.State() != StateClosed {
		t.Errorf("nil State should return StateClosed, got %v", cb.State())
	}

	// These should not panic
	cb.RecordSuccess()
	cb.RecordFailure()
}

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}
