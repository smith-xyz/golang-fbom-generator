package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildDependencyTree(t *testing.T) {
	// Test dependency tree traversal
	testCases := []struct {
		name         string
		packagePath  string
		expectedDeps []string
		expectError  bool
	}{
		{
			name:        "Simple project with known dependencies",
			packagePath: "../../examples/test-project",
			expectedDeps: []string{
				"github.com/gin-gonic/gin",
				"gopkg.in/yaml.v2",
			},
			expectError: false,
		},
		{
			name:         "Invalid package path",
			packagePath:  "/nonexistent/path",
			expectedDeps: nil,
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps, err := BuildDependencyTree(tc.packagePath)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check that expected dependencies are present
			for _, expectedDep := range tc.expectedDeps {
				found := false
				for _, dep := range deps {
					if dep.Name == expectedDep {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected dependency %s not found in tree", expectedDep)
				}
			}
		})
	}
}

func TestGenerateAllFBOMs(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_batch_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Change to temp directory for testing
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	testCases := []struct {
		name         string
		dependencies []DependencySpec
		expectFiles  []string
		expectError  bool
	}{
		{
			name: "Generate FBOMs for multiple dependencies",
			dependencies: []DependencySpec{
				{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", IsStdlib: false},
				{Name: "fmt", Version: "go1.21.0", IsStdlib: true},
			},
			expectFiles: []string{
				"fboms/external/github-com-gin-gonic-gin@v1.9.1.fbom.json",
				"fboms/stdlib/go1.21.0/fmt.fbom.json",
			},
			expectError: false,
		},
		{
			name:         "Handle empty dependency list",
			dependencies: []DependencySpec{},
			expectFiles:  []string{},
			expectError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clean up any existing fboms directory
			os.RemoveAll("fboms")

			results, err := GenerateAllFBOMs(tc.dependencies)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check that expected files were created
			for _, expectedFile := range tc.expectFiles {
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("Expected file %s was not created", expectedFile)
				}
			}

			// Check that results match expectations
			if len(results) != len(tc.dependencies) {
				t.Errorf("Expected %d results, got %d", len(tc.dependencies), len(results))
			}
		})
	}
}

func TestGenerateMissingFBOMs(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_missing_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Change to temp directory for testing
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Pre-create one FBOM file
	externalDir := filepath.Join("fboms", "external")
	if err := os.MkdirAll(externalDir, 0755); err != nil {
		t.Fatalf("Failed to create external dir: %v", err)
	}

	existingFile := filepath.Join(externalDir, "github-com-gin-gonic-gin@v1.9.1.fbom.json")
	validFBOM := `{
		"fbom_version": "0.1.0",
		"name": "github.com/gin-gonic/gin",
		"version": "v1.9.1",
		"generated_at": "2024-01-01T00:00:00Z",
		"functions": [],
		"dependencies": []
	}`
	if err := os.WriteFile(existingFile, []byte(validFBOM), 0644); err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	dependencies := []DependencySpec{
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", IsStdlib: false}, // Already exists
		{Name: "gopkg.in/yaml.v2", Version: "v2.4.0", IsStdlib: false},         // Missing
	}

	results, err := GenerateMissingFBOMs(dependencies)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should only generate 1 FBOM (the missing one)
	if len(results) != 1 {
		t.Errorf("Expected 1 result for missing FBOM, got %d", len(results))
	}

	// Check that the missing file was created
	missingFile := filepath.Join("fboms", "external", "gopkg-in-yaml-v2@v2.4.0.fbom.json")
	if _, err := os.Stat(missingFile); os.IsNotExist(err) {
		t.Error("Expected missing FBOM file was not created")
	}
}

func TestParallelGeneration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_parallel_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Change to temp directory for testing
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Test with multiple dependencies to verify parallel execution
	dependencies := []DependencySpec{
		{Name: "fmt", Version: "go1.21.0", IsStdlib: true},
		{Name: "os", Version: "go1.21.0", IsStdlib: true},
		{Name: "strings", Version: "go1.21.0", IsStdlib: true},
	}

	results, err := GenerateAllFBOMs(dependencies)
	if err != nil {
		t.Fatalf("Unexpected error in parallel generation: %v", err)
	}

	// All should succeed
	for i, result := range results {
		if !result.Success {
			t.Errorf("Dependency %d failed to generate: %s", i, result.Error)
		}
	}

	// Check that all files were created
	expectedFiles := []string{
		"fboms/stdlib/go1.21.0/fmt.fbom.json",
		"fboms/stdlib/go1.21.0/os.fbom.json",
		"fboms/stdlib/go1.21.0/strings.fbom.json",
	}

	for _, expectedFile := range expectedFiles {
		if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
			t.Errorf("Expected file %s was not created", expectedFile)
		}
	}
}

// TestGenerateSingleFBOM_RealGeneration tests that the batch system generates real FBOMs
// This test ensures we replace mock FBOM content with real FBOM generation
func TestGenerateSingleFBOM_RealGeneration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "batch_real_fbom_test")
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

	t.Run("Generate real external package FBOM", func(t *testing.T) {
		dep := DependencySpec{
			Name:     "github.com/gin-gonic/gin",
			Version:  "v1.9.1",
			IsStdlib: false,
		}

		result := generateSingleFBOM(dep)

		if !result.Success {
			t.Fatalf("Expected successful FBOM generation, got error: %s", result.Error)
		}

		// Verify the FBOM file was created
		expectedPath := filepath.Join("fboms", "external", "github-com-gin-gonic-gin@v1.9.1.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}

		// Verify FBOM content structure (enhanced vs mock)
		fbomContent, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatalf("Failed to read FBOM file: %v", err)
		}

		var fbom map[string]interface{}
		if err := json.Unmarshal(fbomContent, &fbom); err != nil {
			t.Fatalf("Failed to parse FBOM JSON: %v", err)
		}

		// Verify enhanced FBOM structure (not just basic mock)
		if fbom["spdx_id"] != "SPDXRef-FBOM-ROOT" {
			t.Error("Expected enhanced FBOM to have spdx_id field")
		}

		// Verify creation_info exists (enhanced structure)
		if creationInfo, ok := fbom["creation_info"].(map[string]interface{}); ok {
			if creationInfo["tool_name"] != "golang-fbom-generator" {
				t.Error("Expected enhanced FBOM to have proper tool_name in creation_info")
			}
			if creationInfo["created"] == "2024-01-01T00:00:00Z" {
				t.Error("Expected real timestamp, not hardcoded 2024-01-01T00:00:00Z")
			}
		} else {
			t.Error("Expected enhanced FBOM to have creation_info structure")
		}

		// Verify package_info exists
		if packageInfo, ok := fbom["package_info"].(map[string]interface{}); ok {
			if packageInfo["name"] != dep.Name {
				t.Errorf("Expected package name %s, got %s", dep.Name, packageInfo["name"])
			}
		} else {
			t.Error("Expected enhanced FBOM to have package_info structure")
		}

		// Verify enhanced fields exist (even if empty for now)
		expectedFields := []string{"call_graph", "entry_points", "security_info"}
		for _, field := range expectedFields {
			if _, exists := fbom[field]; !exists {
				t.Errorf("Expected enhanced FBOM to have %s field", field)
			}
		}
	})

	t.Run("Generate real stdlib package FBOM", func(t *testing.T) {
		// Clean up from previous test
		os.RemoveAll(filepath.Join(".", "fboms"))

		dep := DependencySpec{
			Name:     "fmt",
			Version:  "go1.21.0",
			IsStdlib: true,
		}

		result := generateSingleFBOM(dep)

		if !result.Success {
			t.Fatalf("Expected successful FBOM generation, got error: %s", result.Error)
		}

		// Verify the FBOM file was created in the stdlib location
		expectedPath := filepath.Join("fboms", "stdlib", "go1.21.0", "fmt.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}

		// Verify stdlib FBOM content structure
		fbomContent, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatalf("Failed to read stdlib FBOM file: %v", err)
		}

		var fbom map[string]interface{}
		if err := json.Unmarshal(fbomContent, &fbom); err != nil {
			t.Fatalf("Failed to parse stdlib FBOM JSON: %v", err)
		}

		// Verify basic structure for stdlib package
		if fbom["name"] != dep.Name {
			t.Errorf("Expected package name %s, got %s", dep.Name, fbom["name"])
		}

		if fbom["version"] != dep.Version {
			t.Errorf("Expected version %s, got %s", dep.Version, fbom["version"])
		}

		if fbom["package_type"] != "stdlib" {
			t.Error("Expected stdlib FBOM to have package_type='stdlib'")
		}

		// Verify timestamp is not hardcoded
		if fbom["generated_at"] == "2024-01-01T00:00:00Z" {
			t.Error("Expected real timestamp for stdlib FBOM, not hardcoded 2024-01-01T00:00:00Z")
		}
	})
}

// TestGenerateSingleFBOM_ErrorCases tests error handling in FBOM generation
func TestGenerateSingleFBOM_ErrorCases(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "batch_error_test")
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

	t.Run("Generate FBOM with empty package name", func(t *testing.T) {
		dep := DependencySpec{
			Name:     "", // Empty name should not cause panic
			Version:  "v1.0.0",
			IsStdlib: false,
		}

		result := generateSingleFBOM(dep)

		// Should handle gracefully even with empty name
		if !result.Success {
			// This is acceptable - empty names might cause failures
			t.Logf("Empty package name failed as expected: %s", result.Error)
		}
	})

	t.Run("Both stdlib and external code paths", func(t *testing.T) {
		// Test both code paths are exercised

		// External package
		extDep := DependencySpec{
			Name:     "example.com/test/package",
			Version:  "v1.2.3",
			IsStdlib: false,
		}

		extResult := generateSingleFBOM(extDep)
		if !extResult.Success {
			t.Errorf("External package generation failed: %s", extResult.Error)
		}

		// Stdlib package
		stdlibDep := DependencySpec{
			Name:     "testing",
			Version:  "go1.21.0",
			IsStdlib: true,
		}

		stdlibResult := generateSingleFBOM(stdlibDep)
		if !stdlibResult.Success {
			t.Errorf("Stdlib package generation failed: %s", stdlibResult.Error)
		}

		// Verify different code paths were taken by checking file paths
		if filepath.Dir(extResult.FilePath) == filepath.Dir(stdlibResult.FilePath) {
			t.Error("Expected external and stdlib packages to have different cache paths")
		}
	})
}
