package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// SafeCreateFile creates a file with path validation to prevent directory traversal attacks
func SafeCreateFile(filename string) (*os.File, error) {
	// Validate the filename to prevent path traversal attacks
	if err := validateFilePath(filename); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	// Create the file
	file, err := os.Create(filename) // #nosec G304 - Path validated above
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", filename, err)
	}

	return file, nil
}

// validateFilePath validates a file path to prevent directory traversal attacks
func validateFilePath(path string) error {
	// Clean the path to resolve any ".." or "." components
	cleanPath := filepath.Clean(path)

	// Check for suspicious patterns
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path contains directory traversal patterns: %s", path)
	}

	// Ensure it's not an absolute path to sensitive system directories
	if filepath.IsAbs(cleanPath) {
		// Allow absolute paths but check for sensitive directories
		sensitiveDirectories := []string{
			"/etc", "/proc", "/sys", "/dev", "/boot", "/root",
			"/usr/bin", "/usr/sbin", "/bin", "/sbin",
		}

		for _, sensitive := range sensitiveDirectories {
			if strings.HasPrefix(cleanPath, sensitive) {
				return fmt.Errorf("path points to sensitive system directory: %s", path)
			}
		}
	}

	// Ensure the directory exists or can be created
	dir := filepath.Dir(cleanPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// DirectoryExists checks if a directory exists at the given path
func DirectoryExists(path string) bool {
	if path == "" {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return info.IsDir()
}

// FileExists checks if a file exists at the given path
func FileExists(path string) bool {
	if path == "" {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
