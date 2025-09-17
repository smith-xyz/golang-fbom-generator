package utils

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"
)

// Instrumentation provides timing and progress tracking capabilities
type Instrumentation struct {
	logger  *slog.Logger
	verbose bool
}

// NewInstrumentation creates a new instrumentation instance
func NewInstrumentation(logger *slog.Logger, verbose bool) *Instrumentation {
	return &Instrumentation{
		logger:  logger,
		verbose: verbose,
	}
}

// TimedOperation wraps a function with timing instrumentation
func (i *Instrumentation) TimedOperation(name string, operation func() error) error {
	start := time.Now()
	i.logger.Debug("Starting operation", "operation", name)

	err := operation()
	duration := time.Since(start)

	if err != nil {
		i.logger.Error("Operation failed", "operation", name, "duration_seconds", duration.Seconds(), "error", err)
	} else {
		i.logger.Debug("Operation completed", "operation", name, "duration_seconds", duration.Seconds())
	}

	return err
}

// TimedOperationWithResult wraps a function that returns a result
func (i *Instrumentation) TimedOperationWithResult(name string, operation func() (interface{}, error)) (interface{}, error) {
	start := time.Now()
	i.logger.Debug("Starting operation", "operation", name)

	result, err := operation()
	duration := time.Since(start)

	if err != nil {
		i.logger.Error("Operation failed", "operation", name, "duration_seconds", duration.Seconds(), "error", err)
	} else {
		i.logger.Debug("Operation completed", "operation", name, "duration_seconds", duration.Seconds())
	}

	return result, err
}

// ProgressTracker provides progress tracking for long-running operations
type ProgressTracker struct {
	name       string
	total      int
	processed  int64 // Changed to int64 for atomic operations
	lastUpdate int64 // Unix nano timestamp for atomic operations
	startTime  time.Time
	verbose    bool
	logger     *slog.Logger
}

// NewProgressTracker creates a new progress tracker
func (i *Instrumentation) NewProgressTracker(name string, total int) *ProgressTracker {
	now := time.Now()
	return &ProgressTracker{
		name:       name,
		total:      total,
		processed:  0,
		lastUpdate: now.UnixNano(),
		startTime:  now,
		verbose:    i.verbose,
		logger:     i.logger,
	}
}

// Update increments the progress and optionally shows progress
func (pt *ProgressTracker) Update(increment int) {
	// Thread-safe increment using atomic operations
	newProcessed := atomic.AddInt64(&pt.processed, int64(increment))

	// Thread-safe check for update interval
	now := time.Now()
	lastUpdateNano := atomic.LoadInt64(&pt.lastUpdate)
	lastUpdate := time.Unix(0, lastUpdateNano)

	// Log progress every 25 items or every 2 seconds
	if pt.verbose && (newProcessed%25 == 0 || now.Sub(lastUpdate) > 2*time.Second) {
		// Atomic update of lastUpdate to prevent multiple goroutines from logging simultaneously
		if atomic.CompareAndSwapInt64(&pt.lastUpdate, lastUpdateNano, now.UnixNano()) {
			percentage := float64(newProcessed) / float64(pt.total) * 100
			elapsed := now.Sub(pt.startTime)

			// Calculate ETA
			var eta time.Duration
			if newProcessed > 0 {
				timePerItem := elapsed / time.Duration(newProcessed)
				remaining := int64(pt.total) - newProcessed
				eta = timePerItem * time.Duration(remaining)
			}

			pt.logger.Debug("Progress update",
				"operation", pt.name,
				"processed", newProcessed,
				"total", pt.total,
				"percentage", percentage,
				"elapsed_seconds", elapsed.Seconds(),
				"eta_seconds", eta.Seconds())
		}
	}
}

// Complete marks the operation as finished
func (pt *ProgressTracker) Complete() {
	finalProcessed := atomic.LoadInt64(&pt.processed)
	pt.logger.Debug("Progress tracking completed",
		"operation", pt.name,
		"processed", finalProcessed,
		"total", pt.total,
		"duration_seconds", time.Since(pt.startTime).Seconds())
}

// GetMemoryUsage returns current memory usage in a human-readable format
func GetMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Convert bytes to megabytes
	allocMB := float64(m.Alloc) / 1024 / 1024
	sysMB := float64(m.Sys) / 1024 / 1024

	return fmt.Sprintf("%.1fMB allocated, %.1fMB system", allocMB, sysMB)
}

// PhaseTracker tracks multiple phases of an operation
type PhaseTracker struct {
	name         string
	phases       map[string]time.Time
	currentPhase string
	startTime    time.Time
	verbose      bool
	logger       *slog.Logger
}

// NewPhaseTracker creates a new phase tracker
func (i *Instrumentation) NewPhaseTracker(name string) *PhaseTracker {
	i.logger.Debug("Starting operation", "operation", name)

	return &PhaseTracker{
		name:      name,
		phases:    make(map[string]time.Time),
		startTime: time.Now(),
		verbose:   i.verbose,
		logger:    i.logger,
	}
}

// StartPhase begins tracking a new phase
func (pt *PhaseTracker) StartPhase(phaseName string) {
	if pt.currentPhase != "" {
		pt.EndPhase()
	}

	pt.currentPhase = phaseName
	pt.phases[phaseName] = time.Now()

	pt.logger.Debug("Starting phase", "phase", phaseName, "parent_operation", pt.name)
}

// EndPhase ends the current phase
func (pt *PhaseTracker) EndPhase() {
	if pt.currentPhase == "" {
		return
	}

	if start, exists := pt.phases[pt.currentPhase]; exists {
		duration := time.Since(start)
		pt.logger.Debug("Phase completed", "phase", pt.currentPhase, "duration_seconds", duration.Seconds(), "parent_operation", pt.name)
	}

	pt.currentPhase = ""
}

// Complete finishes the entire operation
func (pt *PhaseTracker) Complete(totalItems int) {
	if pt.currentPhase != "" {
		pt.EndPhase()
	}

	totalDuration := time.Since(pt.startTime)
	memUsage := GetMemoryUsage()

	pt.logger.Debug("Operation completed",
		"operation", pt.name,
		"items", totalItems,
		"duration_seconds", totalDuration.Seconds(),
		"memory_usage", memUsage)
}
