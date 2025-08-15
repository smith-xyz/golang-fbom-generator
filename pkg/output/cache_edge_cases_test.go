package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cache"
)

func TestCacheLinkingEdgeCases(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_edge_cases_test")
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

	t.Run("Cache miss should gracefully handle corrupted cache files", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Create cache structure
		externalDir := filepath.Join(".", "fboms", "external")
		if err := os.MkdirAll(externalDir, 0755); err != nil {
			t.Fatalf("Failed to create external cache dir: %v", err)
		}

		// Create a corrupted FBOM file
		corruptedFile := filepath.Join(externalDir, "github-com-corrupted-pkg@unknown.fbom.json")
		if err := os.WriteFile(corruptedFile, []byte("corrupted json content"), 0644); err != nil {
			t.Fatalf("Failed to create corrupted FBOM: %v", err)
		}

		// This should handle the corruption gracefully and fall back to placeholder
		fbomRef := generator.createCacheAwareFBOMReference("github.com/corrupted/pkg", "unknown", false)

		if fbomRef == nil {
			t.Fatal("Expected FBOM reference to be created even with corrupted cache file")
		}

		// Should fall back to placeholder path, not the corrupted file
		if fbomRef.ResolutionType == "cached_external" {
			t.Error("Should not use cached resolution type for corrupted file")
		}

		// Should have recorded a cache miss
		misses := generator.getCacheMisses()
		if len(misses) != 1 {
			t.Errorf("Expected 1 cache miss, got %d", len(misses))
		}
	})

	t.Run("Cache miss reporting should handle empty miss list", func(t *testing.T) {
		generator := NewFBOMGenerator(true) // verbose mode

		// No cache misses
		report := generator.generateCacheMissReport([]cache.CacheMissReport{})

		if report != "" {
			t.Errorf("Expected empty report for no misses, got: %s", report)
		}
	})

	t.Run("Cache linking should handle permission errors gracefully", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Create cache structure
		externalDir := filepath.Join(".", "fboms", "external")
		if err := os.MkdirAll(externalDir, 0755); err != nil {
			t.Fatalf("Failed to create external cache dir: %v", err)
		}

		// Create a file with no read permissions (Unix-like systems only)
		if os.Getenv("GOOS") != "windows" {
			restrictedFile := filepath.Join(externalDir, "github-com-restricted-pkg@unknown.fbom.json")
			validFBOM := map[string]interface{}{
				"fbom_version": "0.1.0",
				"functions":    []interface{}{},
				"dependencies": []interface{}{},
			}
			content, _ := json.Marshal(validFBOM)
			if err := os.WriteFile(restrictedFile, content, 0000); err != nil {
				t.Fatalf("Failed to create restricted FBOM: %v", err)
			}

			// This should handle the permission error gracefully
			fbomRef := generator.createCacheAwareFBOMReference("github.com/restricted/pkg", "unknown", false)

			if fbomRef == nil {
				t.Fatal("Expected FBOM reference to be created even with permission error")
			}

			// Should fall back to placeholder since file is not readable
			if fbomRef.ResolutionType == "cached_external" {
				t.Error("Should not use cached resolution type for unreadable file")
			}
		}
	})

	t.Run("Cache directory creation should be idempotent", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Create directories multiple times
		err1 := generator.ensureCacheDirectories()
		err2 := generator.ensureCacheDirectories()
		err3 := generator.ensureCacheDirectories()

		if err1 != nil {
			t.Errorf("First directory creation failed: %v", err1)
		}
		if err2 != nil {
			t.Errorf("Second directory creation failed: %v", err2)
		}
		if err3 != nil {
			t.Errorf("Third directory creation failed: %v", err3)
		}

		// Verify directories exist
		structure := cache.DetectCacheStructure()
		if !structure.Exists {
			t.Error("Expected cache structure to exist after multiple creations")
		}
	})

	t.Run("Cache miss collection should handle mixed package types", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Create cache structure with some packages cached
		currentGoVersion := generator.getCurrentGoVersion()
		stdlibDir := filepath.Join(".", "fboms", "stdlib", currentGoVersion)
		if err := os.MkdirAll(stdlibDir, 0755); err != nil {
			t.Fatalf("Failed to create stdlib cache dir: %v", err)
		}

		// Cache fmt but not os
		validFBOM := map[string]interface{}{
			"fbom_version": "0.1.0",
			"functions":    []interface{}{},
			"dependencies": []interface{}{},
		}
		content, _ := json.Marshal(validFBOM)
		fmtFile := filepath.Join(stdlibDir, "fmt.fbom.json")
		if err := os.WriteFile(fmtFile, content, 0644); err != nil {
			t.Fatalf("Failed to create fmt FBOM: %v", err)
		}

		packages := []string{
			"fmt",           // stdlib, cache hit
			"os",            // stdlib, cache miss
			"log",           // stdlib, cache miss
			"encoding/json", // stdlib, cache miss
		}

		misses := generator.collectCacheMisses(packages)

		// Should have 3 misses (os, log, encoding/json)
		if len(misses) != 3 {
			t.Errorf("Expected 3 cache misses, got %d", len(misses))
		}

		// All misses should be stdlib packages
		for _, miss := range misses {
			if !miss.IsStdlib {
				t.Errorf("Expected stdlib package, got %s (stdlib=%v)", miss.PackageName, miss.IsStdlib)
			}
		}
	})

	t.Run("FBOM reference should handle very long package names", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Very long package name
		longPackageName := "github.com/very/long/package/name/that/exceeds/normal/limits/and/tests/path/sanitization/logic/for/filesystem/compatibility"

		fbomRef := generator.createCacheAwareFBOMReference(longPackageName, "unknown", false)

		if fbomRef == nil {
			t.Fatal("Expected FBOM reference to be created for long package name")
		}

		// Should still work with placeholder path
		if fbomRef.FBOMLocation == "" {
			t.Error("Expected FBOM location to be set")
		}

		// Should have recorded a cache miss
		misses := generator.getCacheMisses()
		if len(misses) != 1 {
			t.Errorf("Expected 1 cache miss, got %d", len(misses))
		}
	})
}
