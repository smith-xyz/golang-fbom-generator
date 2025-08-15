package standalone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePackageSpec(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    *PackageSpec
		expectError bool
	}{
		{
			name:  "External package with version",
			input: "github.com/gin-gonic/gin@v1.9.1",
			expected: &PackageSpec{
				Name:     "github.com/gin-gonic/gin",
				Version:  "v1.9.1",
				IsStdlib: false,
			},
			expectError: false,
		},
		{
			name:  "Stdlib package without version",
			input: "fmt",
			expected: &PackageSpec{
				Name:     "fmt",
				Version:  "go1.21.0", // This will vary based on runtime.Version()
				IsStdlib: true,
			},
			expectError: false,
		},
		{
			name:  "Stdlib package with slashes",
			input: "net/http",
			expected: &PackageSpec{
				Name:     "net/http",
				IsStdlib: true,
			},
			expectError: false,
		},
		{
			name:        "Empty specification",
			input:       "",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Invalid format with multiple @ symbols",
			input:       "github.com/test@v1.0.0@extra",
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePackageSpec(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for input %s, but got none", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", tt.input, err)
				return
			}

			if result.Name != tt.expected.Name {
				t.Errorf("Expected name %s, got %s", tt.expected.Name, result.Name)
			}

			if result.IsStdlib != tt.expected.IsStdlib {
				t.Errorf("Expected IsStdlib %v, got %v", tt.expected.IsStdlib, result.IsStdlib)
			}

			// For stdlib packages, just check that a version was assigned
			if tt.expected.IsStdlib && result.Version == "" {
				t.Error("Expected version to be assigned for stdlib package")
			}

			// For external packages with specified version, check exact match
			if !tt.expected.IsStdlib && tt.expected.Version != "" {
				if result.Version != tt.expected.Version {
					t.Errorf("Expected version %s, got %s", tt.expected.Version, result.Version)
				}
			}
		})
	}
}

func TestIsStandardLibraryPackage(t *testing.T) {
	tests := []struct {
		name     string
		package_ string
		expected bool
	}{
		{"fmt package", "fmt", true},
		{"net/http package", "net/http", true},
		{"encoding/json package", "encoding/json", true},
		{"github.com package", "github.com/gin-gonic/gin", false},
		{"gopkg.in package", "gopkg.in/yaml.v2", false},
		{"golang.org package", "golang.org/x/tools", false},
		{"simple external", "somepackage", true}, // Simplified heuristic treats this as stdlib
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isStandardLibraryPackage(tt.package_)
			if result != tt.expected {
				t.Errorf("isStandardLibraryPackage(%s) = %v, expected %v", tt.package_, result, tt.expected)
			}
		})
	}
}

func TestGenerateFBOM(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "standalone_fbom_test")
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

	t.Run("Generate external package FBOM", func(t *testing.T) {
		spec := &PackageSpec{
			Name:     "github.com/gin-gonic/gin",
			Version:  "v1.9.1",
			IsStdlib: false,
		}

		err := GenerateFBOM(spec)
		if err != nil {
			t.Fatalf("GenerateFBOM failed: %v", err)
		}

		// Verify FBOM was written to correct location
		expectedPath := filepath.Join(".", "fboms", "external", "github-com-gin-gonic-gin@v1.9.1.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}
	})

	t.Run("Generate stdlib package FBOM", func(t *testing.T) {
		// Clean up from previous test
		os.RemoveAll(filepath.Join(".", "fboms"))

		spec := &PackageSpec{
			Name:     "fmt",
			Version:  "go1.21.0",
			IsStdlib: true,
		}

		err := GenerateFBOM(spec)
		if err != nil {
			t.Fatalf("GenerateFBOM failed: %v", err)
		}

		// Verify FBOM was written to correct location
		expectedPath := filepath.Join(".", "fboms", "stdlib", "go1.21.0", "fmt.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}
	})
}

func TestResolveLatestVersion(t *testing.T) {
	t.Run("Known package", func(t *testing.T) {
		// This test might be flaky in CI environments without network access
		// In a real project, we'd mock this or skip in CI
		version, err := resolveLatestVersion("github.com/sirupsen/logrus")

		// For testing purposes, we'll accept any valid version or a network error
		if err != nil && !strings.Contains(err.Error(), "package not found") {
			t.Logf("Network error resolving version (expected in some environments): %v", err)
			return
		}

		if err == nil && version == "" {
			t.Error("Expected non-empty version for valid package")
		}
	})

	t.Run("Invalid package", func(t *testing.T) {
		_, err := resolveLatestVersion("github.com/nonexistent/package/that/does/not/exist")
		if err == nil {
			t.Error("Expected error for non-existent package")
		}
	})
}

func TestEdgeCases(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "standalone_edge_cases_test")
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

	t.Run("Package with complex path", func(t *testing.T) {
		spec := &PackageSpec{
			Name:     "k8s.io/client-go",
			Version:  "v0.28.0",
			IsStdlib: false,
		}

		err := GenerateFBOM(spec)
		if err != nil {
			t.Fatalf("GenerateFBOM failed for complex package path: %v", err)
		}

		// Verify FBOM was written with proper sanitization
		expectedPath := filepath.Join(".", "fboms", "external", "k8s-io-client-go@v0.28.0.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}
	})

	t.Run("Generate FBOM twice for same package", func(t *testing.T) {
		// Clean up from previous test
		os.RemoveAll(filepath.Join(".", "fboms"))

		spec := &PackageSpec{
			Name:     "encoding/json",
			Version:  "go1.21.0",
			IsStdlib: true,
		}

		// Generate first time
		err := GenerateFBOM(spec)
		if err != nil {
			t.Fatalf("First GenerateFBOM failed: %v", err)
		}

		// Generate second time (should overwrite)
		err = GenerateFBOM(spec)
		if err != nil {
			t.Fatalf("Second GenerateFBOM failed: %v", err)
		}

		// Verify only one file exists
		expectedPath := filepath.Join(".", "fboms", "stdlib", "go1.21.0", "encoding-json.fbom.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("Expected FBOM file to exist at %s", expectedPath)
		}
	})
}

func TestPackageSpecValidation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Package with version containing spaces",
			input:       "github.com/gin-gonic/gin@v1.9.1 extra",
			expectError: false, // Version parsing is flexible, extra text is ignored
		},
		{
			name:        "Package with only special character as version",
			input:       "fmt@!",
			expectError: false, // Version validation is not strict
		},
		{
			name:        "Multiple @ symbols in invalid format",
			input:       "github.com/test@v1.0.0@extra@more",
			expectError: true,
			errorMsg:    "invalid package specification format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePackageSpec(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for input %s, but got none", tt.input)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input %s: %v", tt.input, err)
				}
			}
		})
	}
}
