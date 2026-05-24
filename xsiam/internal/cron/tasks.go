package cron

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// FeedSyncTask wraps a feed service's sync operation for cron scheduling.
// The actual feed service interface is defined here to avoid import cycles.
type FeedSyncRunner interface {
	SyncAll(ctx context.Context) error
}

// IdentityRiskFlusher is implemented by identity risk service.
type IdentityRiskFlusher interface {
	FlushToDB(ctx context.Context)
}

// ReportGenerator generates pending reports.
type ReportGenerator interface {
	ProcessPending(ctx context.Context, tenantID string) error
}

// RunWithTimeout wraps a function in a timeout context and logs duration.
func RunWithTimeout(ctx context.Context, name string, timeout time.Duration, log *zap.Logger, fn func(context.Context)) {
	start := time.Now()
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		log.Info("cron task complete",
			zap.String("task", name),
			zap.Duration("elapsed", time.Since(start)),
		)
	}()
	fn(tctx)
}

// RetryWithBackoff retries fn up to maxRetries times with exponential backoff.
func RetryWithBackoff(ctx context.Context, maxRetries int, fn func() error) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := fn(); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<uint(i)) * time.Second):
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}
