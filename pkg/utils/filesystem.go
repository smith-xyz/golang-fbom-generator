package utils

import (
	"fmt"
	"os"
)

// WorkingDirectoryManager handles safe directory changes with automatic restoration
type WorkingDirectoryManager struct {
	originalDir string
}

// NewWorkingDirectoryManager creates a new directory manager and captures the current directory
func NewWorkingDirectoryManager() (*WorkingDirectoryManager, error) {
	originalDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	return &WorkingDirectoryManager{
		originalDir: originalDir,
	}, nil
}

// ChangeToDirectory changes to the specified directory
func (wm *WorkingDirectoryManager) ChangeToDirectory(targetDir string) error {
	if err := os.Chdir(targetDir); err != nil {
		return fmt.Errorf("failed to change to directory %s: %w", targetDir, err)
	}
	return nil
}

// RestoreOriginalDirectory restores the original working directory
func (wm *WorkingDirectoryManager) RestoreOriginalDirectory() error {
	if err := os.Chdir(wm.originalDir); err != nil {
		return fmt.Errorf("failed to restore original directory %s: %w", wm.originalDir, err)
	}
	return nil
}

// GetOriginalDirectory returns the original directory path
func (wm *WorkingDirectoryManager) GetOriginalDirectory() string {
	return wm.originalDir
}

// WithDirectoryChange executes a function in a different directory and automatically restores the original
func WithDirectoryChange(targetDir string, fn func() error) error {
	wm, err := NewWorkingDirectoryManager()
	if err != nil {
		return err
	}

	// Only change directory if it's different from current
	if targetDir != wm.originalDir {
		if err := wm.ChangeToDirectory(targetDir); err != nil {
			return err
		}
		defer func() {
			if restoreErr := wm.RestoreOriginalDirectory(); restoreErr != nil {
				// Log error but don't override the main error
				fmt.Fprintf(os.Stderr, "Warning: failed to restore original directory: %v\n", restoreErr)
			}
		}()
	}

	return fn()
}
