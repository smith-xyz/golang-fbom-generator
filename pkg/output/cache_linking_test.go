package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cache"
)

func TestFBOMGeneratorCacheLinking(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_linking_test")
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

	// Get current Go version for stdlib cache
	generator := NewFBOMGenerator(false)
	currentGoVersion := generator.getCurrentGoVersion()

	// Create cache structure
	externalDir := filepath.Join(".", "fboms", "external")
	stdlibDir := filepath.Join(".", "fboms", "stdlib", currentGoVersion)

	if err := os.MkdirAll(externalDir, 0755); err != nil {
		t.Fatalf("Failed to create external cache dir: %v", err)
	}
	if err := os.MkdirAll(stdlibDir, 0755); err != nil {
		t.Fatalf("Failed to create stdlib cache dir: %v", err)
	}

	// Create a valid cached FBOM for gin
	cachedFBOM := map[string]interface{}{
		"fbom_version": "0.1.0",
		"functions":    []interface{}{},
		"dependencies": []interface{}{},
		"call_graph":   map[string]interface{}{},
		"package_info": map[string]interface{}{
			"name": "github.com/gin-gonic/gin",
		},
	}
	cachedContent, _ := json.Marshal(cachedFBOM)

	// Create cache files with "unknown" version since we're not in a real module context
	ginCacheFile := filepath.Join(externalDir, "github-com-gin-gonic-gin@unknown.fbom.json")
	if err := os.WriteFile(ginCacheFile, cachedContent, 0644); err != nil {
		t.Fatalf("Failed to create cached gin FBOM: %v", err)
	}

	// Create cached FBOMs for stdlib packages
	fmtCacheFile := filepath.Join(stdlibDir, "fmt.fbom.json")
	if err := os.WriteFile(fmtCacheFile, cachedContent, 0644); err != nil {
		t.Fatalf("Failed to create cached fmt FBOM: %v", err)
	}

	// Also create cache for os package so we have the expected cache hits/misses
	osCacheFile := filepath.Join(stdlibDir, "os.fbom.json")
	if err := os.WriteFile(osCacheFile, cachedContent, 0644); err != nil {
		t.Fatalf("Failed to create cached os FBOM: %v", err)
	}

	t.Run("FBOM generator should link to cached external FBOMs", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Test the method that should be enhanced with cache linking
		// Use "unknown" version since that's what extractVersionFromGoMod returns in test context
		fbomRef := generator.createCacheAwareFBOMReference("github.com/gin-gonic/gin", "unknown", false)

		// Expectations after cache linking is implemented:
		if fbomRef == nil {
			t.Fatal("Expected FBOM reference to be created")
		}

		// Should use cached file path (absolute path)
		expectedPath, _ := filepath.Abs(ginCacheFile)
		if fbomRef.FBOMLocation != expectedPath {
			t.Errorf("Expected cached file path %s, got %s", expectedPath, fbomRef.FBOMLocation)
		}

		// Should have resolution type "cached"
		if fbomRef.ResolutionType != "cached_external" {
			t.Errorf("Expected resolution type 'cached_external', got %s", fbomRef.ResolutionType)
		}

		// Should have checksum populated
		if fbomRef.ChecksumSHA256 == "" {
			t.Error("Expected checksum to be populated from cached file")
		}

		// Should have last verified timestamp
		if fbomRef.LastVerified == "" {
			t.Error("Expected last verified timestamp to be set")
		}
	})

	t.Run("FBOM generator should link to cached stdlib FBOMs", func(t *testing.T) {
		// This should also fail until we implement cache linking for stdlib
		fbomRef := generator.createCacheAwareFBOMReference("fmt", "any_version", true)

		if fbomRef == nil {
			t.Fatal("Expected FBOM reference to be created for stdlib package")
		}

		// Should use cached file path (absolute path)
		expectedPath, _ := filepath.Abs(fmtCacheFile)
		if fbomRef.FBOMLocation != expectedPath {
			t.Errorf("Expected cached file path %s, got %s", expectedPath, fbomRef.FBOMLocation)
		}

		// Should have resolution type for stdlib
		if fbomRef.ResolutionType != "cached_stdlib" {
			t.Errorf("Expected resolution type 'cached_stdlib', got %s", fbomRef.ResolutionType)
		}
	})

	t.Run("FBOM generator should handle cache misses gracefully", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		// Test with package that has no cached FBOM
		fbomRef := generator.createCacheAwareFBOMReference("github.com/unknown/package", "v1.0.0", false)

		if fbomRef == nil {
			t.Fatal("Expected FBOM reference to be created even for cache miss")
		}

		// Should fall back to computed/placeholder reference
		if fbomRef.ResolutionType == "cached_external" {
			t.Error("Should not use cached resolution type for cache miss")
		}

		// Should use the old placeholder logic (now with absolute path)
		expectedPath, _ := filepath.Abs("./fboms/github-com-unknown-package.fbom.json")
		if fbomRef.FBOMLocation != expectedPath {
			t.Errorf("Expected placeholder path %s, got %s", expectedPath, fbomRef.FBOMLocation)
		}
	})

	t.Run("FBOM generator should collect cache misses for reporting", func(t *testing.T) {
		generator := NewFBOMGenerator(false)

		packages := []string{
			"github.com/gin-gonic/gin",   // Should be cache hit
			"github.com/unknown/package", // Should be cache miss
			"fmt",                        // Should be cache hit
			"os",                         // Should be cache hit
			"net/http",                   // Should be cache miss (no cache file)
		}

		// Test cache miss collection
		misses := generator.collectCacheMisses(packages)

		// Should have 2 misses (unknown package and net/http)
		if len(misses) != 2 {
			t.Errorf("Expected 2 cache misses, got %d", len(misses))
		}

		// Check that the right packages are in the miss list
		missNames := make(map[string]bool)
		for _, miss := range misses {
			missNames[miss.PackageName] = true
		}

		if !missNames["github.com/unknown/package"] {
			t.Error("Expected unknown package to be in cache miss list")
		}
		if !missNames["net/http"] {
			t.Error("Expected net/http package to be in cache miss list")
		}
		if missNames["github.com/gin-gonic/gin"] {
			t.Error("Gin package should not be in cache miss list (cache hit)")
		}
		if missNames["fmt"] {
			t.Error("fmt package should not be in cache miss list (cache hit)")
		}
		if missNames["os"] {
			t.Error("os package should not be in cache miss list (cache hit)")
		}
	})

	t.Run("FBOM generator should auto-create cache directories", func(t *testing.T) {
		// Remove cache directories
		os.RemoveAll(filepath.Join(".", "fboms"))

		generator := NewFBOMGenerator(false)

		// This should create directories automatically
		err := generator.ensureCacheDirectories()
		if err != nil {
			t.Errorf("Failed to ensure cache directories: %v", err)
		}

		// Verify directories were created
		structure := cache.DetectCacheStructure()
		if !structure.Exists {
			t.Error("Expected cache structure to exist after auto-creation")
		}
	})
}

func TestFBOMGeneratorCacheMissReporting(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_miss_test")
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

	t.Run("FBOM generator should generate cache miss report", func(t *testing.T) {
		generator := NewFBOMGenerator(true) // verbose mode

		// Mock some cache misses
		misses := []cache.CacheMissReport{
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
		}

		// This should fail until we implement cache miss reporting
		report := generator.generateCacheMissReport(misses)

		if report == "" {
			t.Error("Expected non-empty cache miss report")
		}

		// Should contain helpful information
		if !strings.Contains(report, "Cache Miss Report") {
			t.Error("Expected cache miss report header")
		}
		if !strings.Contains(report, "golang-fbom-generator -generate-fbom") {
			t.Error("Expected suggested commands in report")
		}
		if !strings.Contains(report, "github.com/gin-gonic/gin@v1.9.1") {
			t.Error("Expected external package with version")
		}
		if !strings.Contains(report, "fmt") {
			t.Error("Expected stdlib package")
		}
	})
}
