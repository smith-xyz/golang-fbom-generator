package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCachedFBOM(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_validation_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Save original directory and change to temp directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	t.Run("Valid FBOM file", func(t *testing.T) {
		validFBOM := map[string]interface{}{
			"fbom_version": "0.1.0",
			"functions":    []interface{}{},
			"dependencies": []interface{}{},
			"call_graph":   map[string]interface{}{},
		}

		content, _ := json.Marshal(validFBOM)
		filePath := "valid_fbom.json"
		err := os.WriteFile(filePath, content, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		result := ValidateCachedFBOM(filePath)
		if !result.IsValid {
			t.Errorf("Expected valid FBOM, got invalid: %s", result.Error)
		}
		if !result.Accessible {
			t.Error("Expected file to be accessible")
		}
		if !result.FBOMValid {
			t.Error("Expected FBOM structure to be valid")
		}
		if result.Checksum == "" {
			t.Error("Expected checksum to be calculated")
		}
	})

	t.Run("Non-existent file", func(t *testing.T) {
		result := ValidateCachedFBOM("nonexistent.json")
		if result.IsValid {
			t.Error("Expected non-existent file to be invalid")
		}
		if result.Accessible {
			t.Error("Expected non-existent file to be inaccessible")
		}
		if !strings.Contains(result.Error, "not accessible") {
			t.Errorf("Expected 'not accessible' error, got: %s", result.Error)
		}
	})

	t.Run("Empty file", func(t *testing.T) {
		filePath := "empty.json"
		err := os.WriteFile(filePath, []byte{}, 0644)
		if err != nil {
			t.Fatalf("Failed to write empty file: %v", err)
		}

		result := ValidateCachedFBOM(filePath)
		if result.IsValid {
			t.Error("Expected empty file to be invalid")
		}
		if !result.Accessible {
			t.Error("Expected empty file to be accessible")
		}
		if result.Error != "file is empty" {
			t.Errorf("Expected 'file is empty' error, got: %s", result.Error)
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		filePath := "invalid.json"
		err := os.WriteFile(filePath, []byte("invalid json content"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid JSON file: %v", err)
		}

		result := ValidateCachedFBOM(filePath)
		if result.IsValid {
			t.Error("Expected invalid JSON to be invalid")
		}
		if !result.Accessible {
			t.Error("Expected file to be accessible")
		}
		if !strings.Contains(result.Error, "invalid JSON") {
			t.Errorf("Expected 'invalid JSON' error, got: %s", result.Error)
		}
	})

	t.Run("Missing required fields", func(t *testing.T) {
		incompleteFBOM := map[string]interface{}{
			"fbom_version": "0.1.0",
			// Missing "functions" and "dependencies"
		}

		content, _ := json.Marshal(incompleteFBOM)
		filePath := "incomplete.json"
		err := os.WriteFile(filePath, content, 0644)
		if err != nil {
			t.Fatalf("Failed to write incomplete FBOM file: %v", err)
		}

		result := ValidateCachedFBOM(filePath)
		if result.IsValid {
			t.Error("Expected incomplete FBOM to be invalid")
		}
		if !strings.Contains(result.Error, "missing required field") {
			t.Errorf("Expected 'missing required field' error, got: %s", result.Error)
		}
	})

	t.Run("Unsupported FBOM version", func(t *testing.T) {
		futureFBOM := map[string]interface{}{
			"fbom_version": "2.0.0",
			"functions":    []interface{}{},
			"dependencies": []interface{}{},
		}

		content, _ := json.Marshal(futureFBOM)
		filePath := "future.json"
		err := os.WriteFile(filePath, content, 0644)
		if err != nil {
			t.Fatalf("Failed to write future FBOM file: %v", err)
		}

		result := ValidateCachedFBOM(filePath)
		if result.IsValid {
			t.Error("Expected future FBOM version to be invalid")
		}
		if !strings.Contains(result.Error, "unsupported FBOM version") {
			t.Errorf("Expected 'unsupported FBOM version' error, got: %s", result.Error)
		}
	})
}

func TestLinkToCachedFBOM(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_linking_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Save original directory and change to temp directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create cache structure with valid FBOM files
	externalDir := filepath.Join(".", "fboms", "external")
	stdlibDir := filepath.Join(".", "fboms", "stdlib", "go1.21.0")

	if err := os.MkdirAll(externalDir, 0755); err != nil {
		t.Fatalf("Failed to create external cache dir: %v", err)
	}
	if err := os.MkdirAll(stdlibDir, 0755); err != nil {
		t.Fatalf("Failed to create stdlib cache dir: %v", err)
	}

	// Create a valid external FBOM
	validFBOM := map[string]interface{}{
		"fbom_version": "0.1.0",
		"functions":    []interface{}{},
		"dependencies": []interface{}{},
		"call_graph":   map[string]interface{}{},
	}
	content, _ := json.Marshal(validFBOM)

	ginFBOMPath := filepath.Join(externalDir, "github-com-gin-gonic-gin@v1.9.1.fbom.json")
	if err := os.WriteFile(ginFBOMPath, content, 0644); err != nil {
		t.Fatalf("Failed to create gin FBOM: %v", err)
	}

	// Create a valid stdlib FBOM
	fmtFBOMPath := filepath.Join(stdlibDir, "fmt.fbom.json")
	if err := os.WriteFile(fmtFBOMPath, content, 0644); err != nil {
		t.Fatalf("Failed to create fmt FBOM: %v", err)
	}

	t.Run("External package cache hit", func(t *testing.T) {
		result := LinkToCachedFBOM("github.com/gin-gonic/gin", "v1.9.1", false)

		if !result.Found {
			t.Error("Expected package to be found in cache")
		}
		if !result.CacheHit {
			t.Errorf("Expected cache hit, got miss. Error: %s", result.Error)
		}
		if result.ResolutionType != "cached_external" {
			t.Errorf("Expected resolution type 'cached_external', got %s", result.ResolutionType)
		}
		expectedPath, _ := filepath.Abs(ginFBOMPath)
		if result.FilePath != expectedPath {
			t.Errorf("Expected file path %s, got %s", expectedPath, result.FilePath)
		}
		if result.Checksum == "" {
			t.Error("Expected checksum to be calculated")
		}
	})

	t.Run("Stdlib package cache hit", func(t *testing.T) {
		result := LinkToCachedFBOM("fmt", "go1.21.0", true)

		if !result.Found {
			t.Error("Expected stdlib package to be found in cache")
		}
		if !result.CacheHit {
			t.Errorf("Expected cache hit, got miss. Error: %s", result.Error)
		}
		if result.ResolutionType != "cached_stdlib" {
			t.Errorf("Expected resolution type 'cached_stdlib', got %s", result.ResolutionType)
		}
		expectedPath, _ := filepath.Abs(fmtFBOMPath)
		if result.FilePath != expectedPath {
			t.Errorf("Expected file path %s, got %s", expectedPath, result.FilePath)
		}
	})

	t.Run("Cache miss - package not found", func(t *testing.T) {
		result := LinkToCachedFBOM("github.com/unknown/package", "v1.0.0", false)

		if result.Found {
			t.Error("Expected package not to be found in cache")
		}
		if result.CacheHit {
			t.Error("Expected cache miss, got hit")
		}
		if result.ResolutionType != "cached_external" {
			t.Errorf("Expected resolution type 'cached_external', got %s", result.ResolutionType)
		}
	})

	t.Run("Cache miss - invalid file", func(t *testing.T) {
		// Create an invalid FBOM file
		invalidPath := filepath.Join(externalDir, "github-com-invalid-pkg@v1.0.0.fbom.json")
		if err := os.WriteFile(invalidPath, []byte("invalid json"), 0644); err != nil {
			t.Fatalf("Failed to create invalid FBOM: %v", err)
		}

		result := LinkToCachedFBOM("github.com/invalid/pkg", "v1.0.0", false)

		if !result.Found {
			t.Error("Expected file to be found (even if invalid)")
		}
		if result.CacheHit {
			t.Error("Expected cache miss due to invalid file")
		}
		if result.Error == "" {
			t.Error("Expected error message for invalid file")
		}
		if !strings.Contains(result.Error, "cached file invalid") {
			t.Errorf("Expected 'cached file invalid' error, got: %s", result.Error)
		}
	})
}

func TestGenerateCacheMissReport(t *testing.T) {
	t.Run("Empty miss list", func(t *testing.T) {
		report := GenerateCacheMissReport([]CacheMissReport{})
		if report != "" {
			t.Errorf("Expected empty report for no misses, got: %s", report)
		}
	})

	t.Run("Mixed stdlib and external misses", func(t *testing.T) {
		misses := []CacheMissReport{
			{
				PackageName:      "github.com/gin-gonic/gin",
				Version:          "v1.9.1",
				IsStdlib:         false,
				SuggestedCommand: "golang-fbom-generator -generate-fbom github.com/gin-gonic/gin@v1.9.1",
			},
			{
				PackageName:      "fmt",
				Version:          "go1.21.0",
				IsStdlib:         true,
				SuggestedCommand: "golang-fbom-generator -generate-fbom fmt",
			},
			{
				PackageName:      "github.com/sirupsen/logrus",
				Version:          "unknown",
				IsStdlib:         false,
				SuggestedCommand: "golang-fbom-generator -generate-fbom github.com/sirupsen/logrus",
			},
		}

		report := GenerateCacheMissReport(misses)

		if !strings.Contains(report, "Cache Miss Report: 3 missing FBOMs") {
			t.Error("Expected cache miss count in report")
		}
		if !strings.Contains(report, "github.com/gin-gonic/gin@v1.9.1") {
			t.Error("Expected external package with version in report")
		}
		if !strings.Contains(report, "fmt") {
			t.Error("Expected stdlib package in report")
		}
		if !strings.Contains(report, "2 external, 1 stdlib") {
			t.Error("Expected summary with correct counts")
		}
		if !strings.Contains(report, "golang-fbom-generator -generate-fbom") {
			t.Error("Expected suggested commands in report")
		}
	})
}

func TestCreateCacheMissReport(t *testing.T) {
	tests := []struct {
		name            string
		packageName     string
		version         string
		isStdlib        bool
		expectedCommand string
	}{
		{
			name:            "External package with version",
			packageName:     "github.com/gin-gonic/gin",
			version:         "v1.9.1",
			isStdlib:        false,
			expectedCommand: "golang-fbom-generator -generate-fbom github.com/gin-gonic/gin@v1.9.1",
		},
		{
			name:            "External package without version",
			packageName:     "github.com/sirupsen/logrus",
			version:         "",
			isStdlib:        false,
			expectedCommand: "golang-fbom-generator -generate-fbom github.com/sirupsen/logrus",
		},
		{
			name:            "External package with unknown version",
			packageName:     "github.com/unknown/pkg",
			version:         "unknown",
			isStdlib:        false,
			expectedCommand: "golang-fbom-generator -generate-fbom github.com/unknown/pkg",
		},
		{
			name:            "Stdlib package",
			packageName:     "fmt",
			version:         "go1.21.0",
			isStdlib:        true,
			expectedCommand: "golang-fbom-generator -generate-fbom fmt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := CreateCacheMissReport(tt.packageName, tt.version, tt.isStdlib)

			if report.PackageName != tt.packageName {
				t.Errorf("Expected package name %s, got %s", tt.packageName, report.PackageName)
			}
			if report.Version != tt.version {
				t.Errorf("Expected version %s, got %s", tt.version, report.Version)
			}
			if report.IsStdlib != tt.isStdlib {
				t.Errorf("Expected isStdlib %v, got %v", tt.isStdlib, report.IsStdlib)
			}
			if report.SuggestedCommand != tt.expectedCommand {
				t.Errorf("Expected command %s, got %s", tt.expectedCommand, report.SuggestedCommand)
			}
		})
	}
}

func TestEnsureCacheDirectoryExists(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_creation_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Save original directory and change to temp directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	t.Run("Create cache directories", func(t *testing.T) {
		err := EnsureCacheDirectoryExists()
		if err != nil {
			t.Fatalf("Failed to ensure cache directory exists: %v", err)
		}

		// Verify directories were created
		structure := DetectCacheStructure()
		if !structure.Exists {
			t.Error("Expected cache structure to exist after creation")
		}

		// Check that base and external directories exist
		if _, err := os.Stat(structure.BasePath); os.IsNotExist(err) {
			t.Errorf("Expected base directory %s to exist", structure.BasePath)
		}
		if _, err := os.Stat(structure.ExternalPath); os.IsNotExist(err) {
			t.Errorf("Expected external directory %s to exist", structure.ExternalPath)
		}
	})

	t.Run("Idempotent operation", func(t *testing.T) {
		// Run twice to ensure it's idempotent
		err1 := EnsureCacheDirectoryExists()
		err2 := EnsureCacheDirectoryExists()

		if err1 != nil {
			t.Errorf("First call failed: %v", err1)
		}
		if err2 != nil {
			t.Errorf("Second call failed: %v", err2)
		}
	})
}
