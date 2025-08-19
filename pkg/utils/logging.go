package utils

import (
	"fmt"
	"os"
)

// VerboseLogger provides consistent verbose logging across packages
type VerboseLogger struct {
	verbose bool
}

// NewVerboseLogger creates a new verbose logger
func NewVerboseLogger(verbose bool) *VerboseLogger {
	return &VerboseLogger{verbose: verbose}
}

// Logf logs a formatted message to stderr if verbose mode is enabled
func (v *VerboseLogger) Logf(format string, args ...interface{}) {
	if v.verbose {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// Log logs a message to stderr if verbose mode is enabled
func (v *VerboseLogger) Log(message string) {
	if v.verbose {
		fmt.Fprint(os.Stderr, message)
	}
}

// IsVerbose returns whether verbose mode is enabled
func (v *VerboseLogger) IsVerbose() bool {
	return v.verbose
}

// DebugLogf logs a debug message to stderr if verbose mode is enabled (with [DEBUG] prefix)
func (v *VerboseLogger) DebugLogf(format string, args ...interface{}) {
	if v.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format, args...)
	}
}

// Convenience functions for one-off logging
func VerboseLogf(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func VerboseLog(verbose bool, message string) {
	if verbose {
		fmt.Fprint(os.Stderr, message)
	}
}
