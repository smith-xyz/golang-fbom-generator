// Package shared contains common test utilities used across different test packages
package shared

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GetBinaryPath returns the path to the pre-built binary
// The binary should be built using 'make build' before running tests
func GetBinaryPath(t *testing.T) string {
	// Get the project root (varies based on test location)
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("Failed to find project root: %v", err)
	}

	// Check if the binary exists
	binaryPath := filepath.Join(projectRoot, "golang-fbom-generator")
	if _, err := os.Stat(binaryPath); err != nil {
		t.Fatalf("Binary not found at %s. Run 'make build' first to build the binary.", binaryPath)
	}

	return binaryPath
}

// findProjectRoot walks up the directory tree to find the project root
func findProjectRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up until we find go.mod with the main module
	for {
		goModPath := filepath.Join(currentDir, "go.mod")
		if goModData, err := os.ReadFile(goModPath); err == nil {
			// Check if this is the main module (contains main.go)
			if _, err := os.Stat(filepath.Join(currentDir, "main.go")); err == nil {
				lines := strings.Split(string(goModData), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "module ") && strings.Contains(line, "golang-fbom-generator") {
						return currentDir, nil
					}
				}
			}
		}

		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			break // reached root
		}
		currentDir = parent
	}

	return "", nil
}

// GetRootModuleName extracts the root module name from go.mod
func GetRootModuleName(projectPath string) string {
	goModPath := filepath.Join(projectPath, "go.mod")
	if goModData, err := os.ReadFile(goModPath); err == nil {
		lines := strings.Split(string(goModData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "module "))
			}
		}
	}
	return ""
}
