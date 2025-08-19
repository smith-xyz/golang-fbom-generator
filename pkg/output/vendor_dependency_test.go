package output

import (
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
)

func TestVendorDependencyVersionAndPurl(t *testing.T) {
	// Create context-aware config for root package
	contextAwareConfig, err := config.NewContextAwareConfig("github.com/example/multi-component-project")
	if err != nil {
		t.Fatalf("Failed to create context-aware config: %v", err)
	}

	// Create FBOM generator like in existing tests
	generator := NewFBOMGenerator(false)
	generator.contextAwareConfig = contextAwareConfig

	tests := []struct {
		name                string
		vendorPackage       string
		expectedRootPackage string
		mockModuleVersions  map[string]string
		expectedVersion     string
		expectedPurl        string
	}{
		{
			name:                "vendor golang.org/x/crypto package",
			vendorPackage:       "vendor/golang.org/x/crypto/chacha20",
			expectedRootPackage: "golang.org/x/crypto",
			mockModuleVersions: map[string]string{
				"golang.org/x/crypto": "v0.21.0",
			},
			expectedVersion: "v0.21.0",
			expectedPurl:    "pkg:golang/golang.org/x/crypto@v0.21.0",
		},
		{
			name:                "vendor github.com package",
			vendorPackage:       "vendor/github.com/gin-gonic/gin/binding",
			expectedRootPackage: "github.com/gin-gonic/gin",
			mockModuleVersions: map[string]string{
				"github.com/gin-gonic/gin": "v1.9.1",
			},
			expectedVersion: "v1.9.1",
			expectedPurl:    "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		},
		{
			name:                "vendor google.golang.org package",
			vendorPackage:       "vendor/google.golang.org/grpc/codes",
			expectedRootPackage: "google.golang.org/grpc",
			mockModuleVersions: map[string]string{
				"google.golang.org/grpc": "v1.60.1",
			},
			expectedVersion: "v1.60.1",
			expectedPurl:    "pkg:golang/google.golang.org/grpc@v1.60.1",
		},
		{
			name:                "vendor gopkg.in package",
			vendorPackage:       "vendor/gopkg.in/yaml.v3/internal",
			expectedRootPackage: "gopkg.in/yaml.v3",
			mockModuleVersions: map[string]string{
				"gopkg.in/yaml.v3": "v3.0.1",
			},
			expectedVersion: "v3.0.1",
			expectedPurl:    "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test extractRootPackageForVersionLookup first
			rootPackage := generator.extractRootPackageForVersionLookup(tt.vendorPackage)
			if rootPackage != tt.expectedRootPackage {
				t.Errorf("extractRootPackageForVersionLookup(%s) = %s, want %s",
					tt.vendorPackage, rootPackage, tt.expectedRootPackage)
			}

			// Mock the getModuleVersions function by temporarily replacing the logic
			// Since we can't easily mock, we'll test the version extraction logic directly
			version := "unknown"
			if v, exists := tt.mockModuleVersions[rootPackage]; exists {
				version = v
			}

			if version != tt.expectedVersion {
				t.Errorf("Version lookup for %s (root: %s) = %s, want %s",
					tt.vendorPackage, rootPackage, version, tt.expectedVersion)
			}

			// Test PURL generation
			purl := generator.generatePurlIdentifier(tt.vendorPackage, version)
			if purl != tt.expectedPurl {
				t.Errorf("generatePurlIdentifier(%s, %s) = %s, want %s",
					tt.vendorPackage, version, purl, tt.expectedPurl)
			}
		})
	}
}

func TestExtractRootPackageForVersionLookup_VendorHandling(t *testing.T) {
	generator := NewFBOMGenerator(false)

	tests := []struct {
		name         string
		packageName  string
		expectedRoot string
	}{
		{
			name:         "vendor golang.org/x/crypto package",
			packageName:  "vendor/golang.org/x/crypto/chacha20",
			expectedRoot: "golang.org/x/crypto",
		},
		{
			name:         "vendor github.com package",
			packageName:  "vendor/github.com/gin-gonic/gin/binding",
			expectedRoot: "github.com/gin-gonic/gin",
		},
		{
			name:         "vendor google.golang.org package",
			packageName:  "vendor/google.golang.org/grpc/codes",
			expectedRoot: "google.golang.org/grpc",
		},
		{
			name:         "vendor gopkg.in package",
			packageName:  "vendor/gopkg.in/yaml.v3/internal",
			expectedRoot: "gopkg.in/yaml.v3",
		},
		{
			name:         "non-vendor golang.org/x package should work as before",
			packageName:  "golang.org/x/crypto/chacha20",
			expectedRoot: "golang.org/x/crypto",
		},
		{
			name:         "non-vendor github.com package should work as before",
			packageName:  "github.com/gin-gonic/gin/binding",
			expectedRoot: "github.com/gin-gonic/gin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generator.extractRootPackageForVersionLookup(tt.packageName)
			if result != tt.expectedRoot {
				t.Errorf("extractRootPackageForVersionLookup(%s) = %s, want %s",
					tt.packageName, result, tt.expectedRoot)
			}
		})
	}
}
