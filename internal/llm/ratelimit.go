package llm

import (
	"context"
	"fmt"
	"time"
)

// RateLimiter implements token bucket rate limiting for API calls
type RateLimiter struct {
	tokens    chan struct{}
	interval  time.Duration
	maxTokens int
}

// NewRateLimiter creates a rate limiter that allows maxRequests per interval
func NewRateLimiter(maxRequests int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens:    make(chan struct{}, maxRequests),
		interval:  interval,
		maxTokens: maxRequests,
	}

	// Fill initial tokens
	for i := 0; i < maxRequests; i++ {
		rl.tokens <- struct{}{}
	}

	// Refill tokens periodically
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			// Try to add a token if not full
			select {
			case rl.tokens <- struct{}{}:
			default:
				// Channel is full, skip
			}
		}
	}()

	return rl
}

// Wait blocks until a token is available, respecting context cancellation
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RetryConfig configures retry behavior for API calls
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig returns sensible defaults for retrying
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
	}
}

// RetryWithBackoff executes fn with exponential backoff retry logic
func RetryWithBackoff(ctx context.Context, cfg RetryConfig, fn func() error) error {
	var lastErr error
	backoff := cfg.InitialBackoff

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}

			// Increase backoff for next attempt
			backoff = time.Duration(float64(backoff) * cfg.BackoffFactor)
			if backoff > cfg.MaxBackoff {
				backoff = cfg.MaxBackoff
			}
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable (429, 5xx)
		if !isRetryableError(err) {
			return err
		}

		if attempt < cfg.MaxRetries {
			fmt.Printf("  ⚠️  Attempt %d/%d failed: %v. Retrying in %v...\n",
				attempt+1, cfg.MaxRetries+1, err, backoff)
		}
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Retry on rate limit errors
	if contains(errStr, "429") || contains(errStr, "Too Many Requests") {
		return true
	}

	// Retry on server errors
	if contains(errStr, "500") || contains(errStr, "502") ||
		contains(errStr, "503") || contains(errStr, "504") {
		return true
	}

	// Retry on timeout errors
	if contains(errStr, "timeout") || contains(errStr, "deadline exceeded") {
		return true
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
