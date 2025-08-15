package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MockFBOM represents a minimal FBOM structure for testing
type MockFBOM struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	GeneratedAt  string `json:"generated_at"`
	Dependencies []struct {
		Name string `json:"name"`
	} `json:"dependencies"`
}

func TestWriteFBOMToCache(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fbom_writer_test")
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

	// Test data
	mockFBOM := MockFBOM{
		Name:        "github.com/gin-gonic/gin",
		Version:     "v1.9.1",
		GeneratedAt: "2024-01-01T00:00:00Z",
		Dependencies: []struct {
			Name string `json:"name"`
		}{
			{Name: "net/http"},
		},
	}

	t.Run("Write external FBOM", func(t *testing.T) {
		err := WriteFBOMToCache(mockFBOM, "external", "github.com/gin-gonic/gin", "v1.9.1")
		if err != nil {
			t.Fatalf("Failed to write external FBOM: %v", err)
		}

		// Verify file exists and content is correct
		expectedPath := filepath.Join(".", "fboms", "external", "github-com-gin-gonic-gin@v1.9.1.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}

		// Read and verify content
		data, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatalf("Failed to read FBOM file: %v", err)
		}

		var readFBOM MockFBOM
		if err := json.Unmarshal(data, &readFBOM); err != nil {
			t.Fatalf("Failed to unmarshal FBOM: %v", err)
		}

		if readFBOM.Name != mockFBOM.Name {
			t.Errorf("Expected name %s, got %s", mockFBOM.Name, readFBOM.Name)
		}
		if readFBOM.Version != mockFBOM.Version {
			t.Errorf("Expected version %s, got %s", mockFBOM.Version, readFBOM.Version)
		}
	})

	t.Run("Write stdlib FBOM", func(t *testing.T) {
		// Clean up from previous test
		os.RemoveAll(filepath.Join(".", "fboms"))

		stdlibFBOM := MockFBOM{
			Name:        "fmt",
			Version:     "stdlib",
			GeneratedAt: "2024-01-01T00:00:00Z",
		}

		err := WriteFBOMToCache(stdlibFBOM, "stdlib", "fmt", "go1.21.0")
		if err != nil {
			t.Fatalf("Failed to write stdlib FBOM: %v", err)
		}

		// Verify file exists and content is correct
		expectedPath := filepath.Join(".", "fboms", "stdlib", "go1.21.0", "fmt.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}

		// Read and verify content
		data, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatalf("Failed to read FBOM file: %v", err)
		}

		var readFBOM MockFBOM
		if err := json.Unmarshal(data, &readFBOM); err != nil {
			t.Fatalf("Failed to unmarshal FBOM: %v", err)
		}

		if readFBOM.Name != stdlibFBOM.Name {
			t.Errorf("Expected name %s, got %s", stdlibFBOM.Name, readFBOM.Name)
		}
		if readFBOM.Version != stdlibFBOM.Version {
			t.Errorf("Expected version %s, got %s", stdlibFBOM.Version, readFBOM.Version)
		}
	})

	t.Run("Create directories if they don't exist", func(t *testing.T) {
		// Clean up from previous tests
		os.RemoveAll(filepath.Join(".", "fboms"))

		// This should create the directory structure
		err := WriteFBOMToCache(mockFBOM, "external", "github.com/example/pkg", "v1.0.0")
		if err != nil {
			t.Fatalf("Failed to write FBOM when directories don't exist: %v", err)
		}

		// Verify directory structure was created
		externalDir := filepath.Join(".", "fboms", "external")
		if _, err := os.Stat(externalDir); os.IsNotExist(err) {
			t.Error("Expected external directory to be created")
		}

		expectedFile := filepath.Join(externalDir, "github-com-example-pkg@v1.0.0.fbom.json")
		if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
			t.Error("Expected FBOM file to be created")
		}
	})
}

func TestWriteFBOMToCacheErrors(t *testing.T) {
	t.Run("Invalid cache type", func(t *testing.T) {
		mockFBOM := MockFBOM{Name: "test"}
		err := WriteFBOMToCache(mockFBOM, "invalid", "test", "v1.0.0")
		if err == nil {
			t.Error("Expected error for invalid cache type")
		}
		if !strings.Contains(err.Error(), "unsupported cache type") {
			t.Errorf("Expected 'unsupported cache type' error, got: %v", err)
		}
	})

	t.Run("Empty package name", func(t *testing.T) {
		mockFBOM := MockFBOM{Name: "test"}
		err := WriteFBOMToCache(mockFBOM, "external", "", "v1.0.0")
		if err == nil {
			t.Error("Expected error for empty package name")
		}
	})

	t.Run("Empty version", func(t *testing.T) {
		mockFBOM := MockFBOM{Name: "test"}
		err := WriteFBOMToCache(mockFBOM, "external", "test/pkg", "")
		if err == nil {
			t.Error("Expected error for empty version")
		}
	})
}
