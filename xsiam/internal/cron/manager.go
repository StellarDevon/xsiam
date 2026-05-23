package cron

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// Task is a named runnable job.
type Task struct {
	Name string
	Fn   func(ctx context.Context)
}

// Manager wraps robfig/cron with graceful shutdown support.
type Manager struct {
	c    *cron.Cron
	log  *zap.Logger
	ctx  context.Context
}

// New creates a Manager with a seconds-granularity cron scheduler.
func New(ctx context.Context, log *zap.Logger) *Manager {
	c := cron.New(cron.WithSeconds())
	return &Manager{c: c, log: log, ctx: ctx}
}

// RegisterCron adds a job using a cron expression (with optional seconds field).
func (m *Manager) RegisterCron(expr string, task Task) error {
	_, err := m.c.AddFunc(expr, func() {
		m.log.Info("cron task start", zap.String("task", task.Name))
		start := time.Now()
		task.Fn(m.ctx)
		m.log.Info("cron task done", zap.String("task", task.Name), zap.Duration("elapsed", time.Since(start)))
	})
	return err
}

// RegisterInterval adds a job that runs at a fixed interval.
func (m *Manager) RegisterInterval(d time.Duration, task Task) {
	expr := "@every " + d.String()
	_, _ = m.c.AddFunc(expr, func() {
		m.log.Info("interval task start", zap.String("task", task.Name))
		start := time.Now()
		task.Fn(m.ctx)
		m.log.Info("interval task done", zap.String("task", task.Name), zap.Duration("elapsed", time.Since(start)))
	})
}

// RegisterWorkerPool adds a task that runs immediately in a separate goroutine
// (intended for long-running background workers, not scheduled tasks).
func (m *Manager) RegisterWorkerPool(task Task) {
	go func() {
		m.log.Info("worker pool start", zap.String("task", task.Name))
		task.Fn(m.ctx)
		m.log.Info("worker pool exited", zap.String("task", task.Name))
	}()
}

// Start launches the cron scheduler.
func (m *Manager) Start() {
	m.c.Start()
	m.log.Info("cron manager started")
}

// Shutdown stops the cron scheduler and waits for running jobs to complete.
func (m *Manager) Shutdown() {
	stopCtx := m.c.Stop()
	<-stopCtx.Done()
	m.log.Info("cron manager stopped")
}
