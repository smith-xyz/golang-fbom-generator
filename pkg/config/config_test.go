package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config, err := DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	if config == nil {
		t.Fatal("Default config is nil")
	}

	// Test that we have some stdlib patterns
	if len(config.Packages.StdlibPatterns) == 0 {
		t.Error("No stdlib patterns found in default config")
	}

	// Test that we have some dependency patterns
	if len(config.Packages.DependencyPatterns) == 0 {
		t.Error("No dependency patterns found in default config")
	}

	// Verify some expected patterns exist
	found := false
	for _, pattern := range config.Packages.StdlibPatterns {
		if pattern == "fmt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected stdlib pattern 'fmt' not found")
	}
}

func TestIsStandardLibrary(t *testing.T) {
	config, err := DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	tests := []struct {
		name        string
		packagePath string
		expected    bool
	}{
		{"fmt package", "fmt", true},
		{"net/http package", "net/http", true},
		{"encoding/json package", "encoding/json", true},
		{"internal package", "internal/cpu", true},
		{"vendor package", "vendor/example.com/pkg", true},
		{"cmd package", "cmd/go", true},
		{"user package", "myapp/service", false},
		{"github dependency", "github.com/user/repo", false},
		{"empty package", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsStandardLibrary(tt.packagePath)
			if result != tt.expected {
				t.Errorf("IsStandardLibrary(%q) = %v, want %v", tt.packagePath, result, tt.expected)
			}
		})
	}
}

func TestIsDependency(t *testing.T) {
	config, err := DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	tests := []struct {
		name        string
		packagePath string
		expected    bool
	}{
		{"github dependency", "github.com/gin-gonic/gin", true},
		{"golang.org dependency", "golang.org/x/tools", true},
		{"google dependency", "google.golang.org/grpc", true},
		{"gopkg.in dependency", "gopkg.in/yaml.v3", true},
		{"vendor dependency", "vendor/github.com/user/repo", true},
		{"stdlib package", "fmt", false},
		{"net/http package", "net/http", false},
		{"user package", "myapp/service", false},
		{"empty package", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsDependency(tt.packagePath)
			if result != tt.expected {
				t.Errorf("IsDependency(%q) = %v, want %v", tt.packagePath, result, tt.expected)
			}
		})
	}
}

func TestIsUserDefined(t *testing.T) {
	config, err := DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	tests := []struct {
		name        string
		packagePath string
		expected    bool
	}{
		{"user package", "myapp/service", true},
		{"local package", "internal/myservice", false}, // internal/ is stdlib
		{"another user package", "example.com/myapp", true},
		{"fmt package", "fmt", false},
		{"github dependency", "github.com/gin-gonic/gin", false},
		{"empty package", "", true}, // empty is considered user-defined
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsUserDefined(tt.packagePath)
			if result != tt.expected {
				t.Errorf("IsUserDefined(%q) = %v, want %v", tt.packagePath, result, tt.expected)
			}
		})
	}
}

func TestConfigStructure(t *testing.T) {
	config, err := DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	// Test that all required fields are present
	if config.Packages.StdlibPatterns == nil {
		t.Error("StdlibPatterns is nil")
	}

	if config.Packages.StdlibPrefixes == nil {
		t.Error("StdlibPrefixes is nil")
	}

	if config.Packages.DependencyPatterns == nil {
		t.Error("DependencyPatterns is nil")
	}

	if config.Packages.VendorPatterns == nil {
		t.Error("VendorPatterns is nil")
	}

	// Test that we have reasonable amounts of patterns
	if len(config.Packages.StdlibPatterns) < 10 {
		t.Errorf("Expected at least 10 stdlib patterns, got %d", len(config.Packages.StdlibPatterns))
	}

	if len(config.Packages.DependencyPatterns) < 5 {
		t.Errorf("Expected at least 5 dependency patterns, got %d", len(config.Packages.DependencyPatterns))
	}
}
