package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CacheStructure represents the detected FBOM cache directory structure
type CacheStructure struct {
	BasePath     string            // Base fboms directory path
	ExternalPath string            // Path to external dependencies cache
	StdlibPaths  map[string]string // Map of Go version to stdlib cache path
	Exists       bool              // Whether the cache structure exists
}

// DetectCacheStructure scans the current directory for FBOM cache structure
func DetectCacheStructure() *CacheStructure {
	basePath := filepath.Join(".", "fboms")
	externalPath := filepath.Join(basePath, "external")
	stdlibBasePath := filepath.Join(basePath, "stdlib")

	structure := &CacheStructure{
		BasePath:     basePath,
		ExternalPath: externalPath,
		StdlibPaths:  make(map[string]string),
		Exists:       false,
	}

	// Check if base cache directory exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return structure
	}

	// Check if external cache directory exists
	if _, err := os.Stat(externalPath); err == nil {
		structure.Exists = true
	}

	// Scan for stdlib version directories
	if entries, err := os.ReadDir(stdlibBasePath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "go") {
				goVersion := entry.Name()
				stdlibPath := filepath.Join(stdlibBasePath, goVersion)
				structure.StdlibPaths[goVersion] = stdlibPath
				structure.Exists = true
			}
		}
	}

	return structure
}

// LookupExternalFBOM checks if an external package FBOM exists in cache
func LookupExternalFBOM(packageName, version string) (path string, exists bool) {
	// Generate sanitized filename
	safeName := SanitizePackageName(packageName)
	filename := fmt.Sprintf("%s@%s.fbom.json", safeName, version)

	externalPath := filepath.Join(".", "fboms", "external")
	fbomPath := filepath.Join(externalPath, filename)

	// Check if file exists
	if _, err := os.Stat(fbomPath); err == nil {
		return fbomPath, true
	}

	return fbomPath, false
}

// LookupStdlibFBOM checks if a standard library package FBOM exists in cache
func LookupStdlibFBOM(packageName, goVersion string) (path string, exists bool) {
	// Generate sanitized filename for stdlib package
	safeName := SanitizePackageName(packageName)
	filename := fmt.Sprintf("%s.fbom.json", safeName)

	stdlibPath := filepath.Join(".", "fboms", "stdlib", goVersion)
	fbomPath := filepath.Join(stdlibPath, filename)

	// Check if file exists
	if _, err := os.Stat(fbomPath); err == nil {
		return fbomPath, true
	}

	return fbomPath, false
}

// SanitizePackageName converts package names to filesystem-safe names
func SanitizePackageName(packageName string) string {
	// Replace slashes and dots with hyphens to create valid filenames
	safeName := strings.ReplaceAll(packageName, "/", "-")
	safeName = strings.ReplaceAll(safeName, ".", "-")
	return safeName
}
