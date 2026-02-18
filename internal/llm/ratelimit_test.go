package llm

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	// Create a rate limiter: 5 requests per second
	rl := NewRateLimiter(5, time.Second)
	ctx := context.Background()

	// Test that first 5 requests succeed immediately
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("First 5 requests took too long: %v", elapsed)
	}

	// Test that 6th request waits
	start = time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("6th request failed: %v", err)
	}
	elapsed = time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Errorf("6th request didn't wait long enough: %v", elapsed)
	}

	t.Logf("Rate limiter working correctly. 6th request waited %v", elapsed)
}

func TestRetryableErrors(t *testing.T) {
	tests := []struct {
		errorMsg string
		want     bool
	}{
		{"API error 429: Too Many Requests", true},
		{"API error 500: Internal Server Error", true},
		{"API error 502: Bad Gateway", true},
		{"API error 503: Service Unavailable", true},
		{"API error 504: Gateway Timeout", true},
		{"context deadline exceeded", true},
		{"timeout waiting for response", true},
		{"API error 400: Bad Request", false},
		{"API error 401: Unauthorized", false},
		{"invalid JSON", false},
	}

	for _, tt := range tests {
		t.Run(tt.errorMsg, func(t *testing.T) {
			err := &mockError{msg: tt.errorMsg}
			got := isRetryableError(err)
			if got != tt.want {
				t.Errorf("isRetryableError(%q) = %v, want %v", tt.errorMsg, got, tt.want)
			}
		})
	}
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
