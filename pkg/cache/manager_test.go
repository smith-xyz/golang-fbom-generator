package cache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectCacheStructure(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_test")
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

	t.Run("No cache exists", func(t *testing.T) {
		structure := DetectCacheStructure()

		if structure.Exists {
			t.Error("Expected no cache structure to exist")
		}

		expectedBasePath, _ := filepath.Abs(filepath.Join(".", "fboms"))
		if structure.BasePath != expectedBasePath {
			t.Errorf("Expected base path '%s', got '%s'", expectedBasePath, structure.BasePath)
		}
	})

	t.Run("Cache with external directory exists", func(t *testing.T) {
		// Create external cache directory
		externalDir := filepath.Join(".", "fboms", "external")
		if err := os.MkdirAll(externalDir, 0755); err != nil {
			t.Fatalf("Failed to create external cache dir: %v", err)
		}

		structure := DetectCacheStructure()

		if !structure.Exists {
			t.Error("Expected cache structure to exist")
		}

		expectedExternalPath, _ := filepath.Abs(filepath.Join(".", "fboms", "external"))
		if structure.ExternalPath != expectedExternalPath {
			t.Errorf("Expected external path '%s', got '%s'", expectedExternalPath, structure.ExternalPath)
		}
	})

	t.Run("Cache with stdlib directories exists", func(t *testing.T) {
		// Clean up from previous test
		os.RemoveAll(filepath.Join(".", "fboms"))

		// Create stdlib cache directories for different Go versions
		stdlibDir1 := filepath.Join(".", "fboms", "stdlib", "go1.21.0")
		stdlibDir2 := filepath.Join(".", "fboms", "stdlib", "go1.20.0")

		if err := os.MkdirAll(stdlibDir1, 0755); err != nil {
			t.Fatalf("Failed to create stdlib cache dir 1: %v", err)
		}
		if err := os.MkdirAll(stdlibDir2, 0755); err != nil {
			t.Fatalf("Failed to create stdlib cache dir 2: %v", err)
		}

		structure := DetectCacheStructure()

		if !structure.Exists {
			t.Error("Expected cache structure to exist")
		}

		if len(structure.StdlibPaths) != 2 {
			t.Errorf("Expected 2 stdlib paths, got %d", len(structure.StdlibPaths))
		}

		expectedPath1, _ := filepath.Abs(filepath.Join(".", "fboms", "stdlib", "go1.21.0"))
		if structure.StdlibPaths["go1.21.0"] != expectedPath1 {
			t.Errorf("Expected stdlib path '%s', got '%s'", expectedPath1, structure.StdlibPaths["go1.21.0"])
		}

		expectedPath2, _ := filepath.Abs(filepath.Join(".", "fboms", "stdlib", "go1.20.0"))
		if structure.StdlibPaths["go1.20.0"] != expectedPath2 {
			t.Errorf("Expected stdlib path '%s', got '%s'", expectedPath2, structure.StdlibPaths["go1.20.0"])
		}
	})
}

func TestLookupExternalFBOM(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_test")
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

	// Create external cache directory and sample FBOM file
	externalDir := filepath.Join(".", "fboms", "external")
	if err := os.MkdirAll(externalDir, 0755); err != nil {
		t.Fatalf("Failed to create external cache dir: %v", err)
	}

	// Create a sample FBOM file
	fbomContent := `{"name": "gin", "version": "v1.9.1"}`
	fbomPath := filepath.Join(externalDir, "github-com-gin-gonic-gin@v1.9.1.fbom.json")
	if err := os.WriteFile(fbomPath, []byte(fbomContent), 0644); err != nil {
		t.Fatalf("Failed to create sample FBOM file: %v", err)
	}

	t.Run("Existing FBOM found", func(t *testing.T) {
		path, exists := LookupExternalFBOM("github.com/gin-gonic/gin", "v1.9.1")

		if !exists {
			t.Error("Expected FBOM to exist")
		}

		expectedPath, _ := filepath.Abs(filepath.Join(".", "fboms", "external", "github-com-gin-gonic-gin@v1.9.1.fbom.json"))
		if path != expectedPath {
			t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
		}
	})

	t.Run("Non-existing FBOM not found", func(t *testing.T) {
		path, exists := LookupExternalFBOM("github.com/unknown/package", "v1.0.0")

		if exists {
			t.Error("Expected FBOM not to exist")
		}

		expectedPath, _ := filepath.Abs(filepath.Join(".", "fboms", "external", "github-com-unknown-package@v1.0.0.fbom.json"))
		if path != expectedPath {
			t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
		}
	})
}

func TestLookupStdlibFBOM(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_cache_test")
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

	// Create stdlib cache directory and sample FBOM file
	stdlibDir := filepath.Join(".", "fboms", "stdlib", "go1.21.0")
	if err := os.MkdirAll(stdlibDir, 0755); err != nil {
		t.Fatalf("Failed to create stdlib cache dir: %v", err)
	}

	// Create a sample FBOM file
	fbomContent := `{"name": "fmt", "version": "stdlib"}`
	fbomPath := filepath.Join(stdlibDir, "fmt.fbom.json")
	if err := os.WriteFile(fbomPath, []byte(fbomContent), 0644); err != nil {
		t.Fatalf("Failed to create sample FBOM file: %v", err)
	}

	t.Run("Existing stdlib FBOM found", func(t *testing.T) {
		path, exists := LookupStdlibFBOM("fmt", "go1.21.0")

		if !exists {
			t.Error("Expected stdlib FBOM to exist")
		}

		expectedPath, _ := filepath.Abs(filepath.Join(".", "fboms", "stdlib", "go1.21.0", "fmt.fbom.json"))
		if path != expectedPath {
			t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
		}
	})

	t.Run("Non-existing stdlib FBOM not found", func(t *testing.T) {
		path, exists := LookupStdlibFBOM("unknown", "go1.21.0")

		if exists {
			t.Error("Expected stdlib FBOM not to exist")
		}

		expectedPath, _ := filepath.Abs(filepath.Join(".", "fboms", "stdlib", "go1.21.0", "unknown.fbom.json"))
		if path != expectedPath {
			t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
		}
	})

	t.Run("Different Go version", func(t *testing.T) {
		path, exists := LookupStdlibFBOM("fmt", "go1.20.0")

		if exists {
			t.Error("Expected stdlib FBOM not to exist for different Go version")
		}

		expectedPath, _ := filepath.Abs(filepath.Join(".", "fboms", "stdlib", "go1.20.0", "fmt.fbom.json"))
		if path != expectedPath {
			t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
		}
	})
}

func TestSanitizePackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com/gin-gonic/gin", "github-com-gin-gonic-gin"},
		{"gopkg.in/yaml.v2", "gopkg-in-yaml-v2"},
		{"golang.org/x/tools", "golang-org-x-tools"},
		{"simple", "simple"},
		{"no.change.needed", "no-change-needed"},
		{"path/with/slashes", "path-with-slashes"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := SanitizePackageName(test.input)
			if result != test.expected {
				t.Errorf("SanitizePackageName(%s) = %s, expected %s", test.input, result, test.expected)
			}
		})
	}
}

func TestEmptyInputs(t *testing.T) {
	t.Run("Empty package name", func(t *testing.T) {
		path, exists := LookupExternalFBOM("", "v1.0.0")
		if exists {
			t.Error("Expected FBOM not to exist for empty package name")
		}
		if path == "" {
			t.Error("Expected path to be returned even for non-existing FBOM")
		}
	})

	t.Run("Empty version", func(t *testing.T) {
		path, exists := LookupExternalFBOM("github.com/example/pkg", "")
		if exists {
			t.Error("Expected FBOM not to exist for empty version")
		}
		if path == "" {
			t.Error("Expected path to be returned even for non-existing FBOM")
		}
	})

	t.Run("Empty Go version", func(t *testing.T) {
		path, exists := LookupStdlibFBOM("fmt", "")
		if exists {
			t.Error("Expected stdlib FBOM not to exist for empty Go version")
		}
		if path == "" {
			t.Error("Expected path to be returned even for non-existing FBOM")
		}
	})
}
