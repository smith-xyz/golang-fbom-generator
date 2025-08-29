package generator

import (
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestFBOMGeneration tests the unified FBOM generation approach
func TestFBOMGeneration(t *testing.T) {
	tests := []struct {
		name        string
		packageSpec string
		expectError bool
		description string
	}{
		{
			name:        "Local package (current directory)",
			packageSpec: ".",
			expectError: false,
			description: "Should generate FBOM for the current Go project",
		},
		{
			name:        "External package with version",
			packageSpec: "github.com/gin-gonic/gin@v1.9.1",
			expectError: true,
			description: "Should generate error trying to generate FBOM for external dependency",
		},
		{
			name:        "Standard library package",
			packageSpec: "fmt",
			expectError: true,
			description: "Should generate error trying to generate FBOM for stdlib package",
		},
		{
			name:        "Standard library package with version",
			packageSpec: "encoding/json@go1.21.0",
			expectError: true,
			description: "Should generate error trying to generate FBOM for stdlib package with specific version",
		},
		{
			name:        "Invalid package",
			packageSpec: "invalid/nonexistent/package",
			expectError: true,
			description: "Should fail gracefully for invalid packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the unified GenerateFBOM function
			_, err := GenerateFBOM(tt.packageSpec, "", false, "rta", nil, output.DefaultAnalysisConfig())

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.packageSpec)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.packageSpec, err)
			}
		})
	}
}

// TestUnifiedFBOMGenerationWithOptions tests unified FBOM generation with various options
func TestFBOMGenerationWithOptions(t *testing.T) {
	tests := []struct {
		name        string
		packageSpec string
		verbose     bool
		algorithm   string
		entryPoints []string
		expectError bool
		description string
	}{
		{
			name:        "Local package with RTA algorithm",
			packageSpec: ".",
			verbose:     true,
			algorithm:   "rta",
			entryPoints: nil,
			expectError: false,
			description: "Should generate FBOM with RTA algorithm",
		},
		{
			name:        "Local package with custom entry points",
			packageSpec: ".",
			verbose:     false,
			algorithm:   "rta",
			entryPoints: []string{"main.main", "*.Handler"},
			expectError: false,
			description: "Should generate FBOM with custom entry points",
		},
		{
			name:        "External package with VTA algorithm",
			packageSpec: "github.com/gin-gonic/gin@v1.9.1",
			verbose:     true,
			algorithm:   "vta",
			entryPoints: nil,
			expectError: true,
			description: "Should throw error trying to generate FBOM for external package with VTA",
		},
		{
			name:        "Invalid algorithm",
			packageSpec: ".",
			verbose:     false,
			algorithm:   "invalid",
			entryPoints: nil,
			expectError: true,
			description: "Should fail with invalid algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateFBOM(tt.packageSpec, "", tt.verbose, tt.algorithm, tt.entryPoints, output.DefaultAnalysisConfig())

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s with algorithm %s, but got none", tt.packageSpec, tt.algorithm)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s with algorithm %s: %v", tt.packageSpec, tt.algorithm, err)
			}
		})
	}
}

// TestBatchFunctionsRemoved ensures batch processing functions are removed
func TestBatchFunctionsRemoved(t *testing.T) {
	// This test will fail initially, proving that batch functions exist
	// After implementation, this should pass by confirming they're removed
	t.Run("generateBatchFBOMs should not exist", func(t *testing.T) {
		// This test will fail compilation if generateBatchFBOMs still exists
		// We'll implement this check in the actual implementation phase
		t.Skip("Will be implemented after generateBatchFBOMs is removed")
	})

	t.Run("batch flags should not exist", func(t *testing.T) {
		// This test will verify batch flags are removed from main.go
		t.Skip("Will be implemented after batch flags are removed")
	})
}
