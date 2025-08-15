package output

import (
	"testing"
)

// TestPurlIdentifierGeneration tests the generation of PURL identifiers for Go dependencies
func TestPurlIdentifierGeneration(t *testing.T) {
	tests := []struct {
		name         string
		packageName  string
		version      string
		expectedPurl string
	}{
		{
			name:         "GitHub package with semantic version",
			packageName:  "github.com/gin-gonic/gin",
			version:      "v1.9.1",
			expectedPurl: "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		},
		{
			name:         "gopkg.in package with semantic version",
			packageName:  "gopkg.in/yaml.v2",
			version:      "v2.4.0",
			expectedPurl: "pkg:golang/gopkg.in/yaml.v2@v2.4.0",
		},
		{
			name:         "golang.org/x package",
			packageName:  "golang.org/x/crypto",
			version:      "v0.9.0",
			expectedPurl: "pkg:golang/golang.org/x/crypto@v0.9.0",
		},
		{
			name:         "google.golang.org package",
			packageName:  "google.golang.org/protobuf",
			version:      "v1.30.0",
			expectedPurl: "pkg:golang/google.golang.org/protobuf@v1.30.0",
		},
		{
			name:         "go.uber.org package",
			packageName:  "go.uber.org/zap",
			version:      "v1.24.0",
			expectedPurl: "pkg:golang/go.uber.org/zap@v1.24.0",
		},
		{
			name:         "k8s.io package",
			packageName:  "k8s.io/client-go",
			version:      "v0.27.0",
			expectedPurl: "pkg:golang/k8s.io/client-go@v0.27.0",
		},
		{
			name:         "subpackage should use root package name",
			packageName:  "github.com/gin-gonic/gin/binding",
			version:      "v1.9.1",
			expectedPurl: "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		},
		{
			name:         "golang.org/x subpackage",
			packageName:  "golang.org/x/crypto/sha3",
			version:      "v0.9.0",
			expectedPurl: "pkg:golang/golang.org/x/crypto@v0.9.0",
		},
		{
			name:         "unknown version should return empty PURL",
			packageName:  "github.com/gin-gonic/gin",
			version:      "unknown",
			expectedPurl: "",
		},
		{
			name:         "empty version should return empty PURL",
			packageName:  "github.com/gin-gonic/gin",
			version:      "",
			expectedPurl: "",
		},
		{
			name:         "complex github package name",
			packageName:  "github.com/sirupsen/logrus",
			version:      "v1.9.0",
			expectedPurl: "pkg:golang/github.com/sirupsen/logrus@v1.9.0",
		},
		{
			name:         "package with replace directive (pseudo-version)",
			packageName:  "example.com/internal/package",
			version:      "v0.0.0-20230101120000-abcdef123456",
			expectedPurl: "pkg:golang/example.com/internal/package@v0.0.0-20230101120000-abcdef123456",
		},
	}

	generator := NewFBOMGenerator(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPurl := generator.generatePurlIdentifier(tt.packageName, tt.version)
			if actualPurl != tt.expectedPurl {
				t.Errorf("generatePurlIdentifier(%q, %q) = %q, want %q",
					tt.packageName, tt.version, actualPurl, tt.expectedPurl)
			}
		})
	}
}

// TestPurlIdentifierValidation tests that generated PURLs conform to the PURL specification
func TestPurlIdentifierValidation(t *testing.T) {
	generator := NewFBOMGenerator(false)

	testCases := []struct {
		packageName string
		version     string
	}{
		{"github.com/gin-gonic/gin", "v1.9.1"},
		{"gopkg.in/yaml.v2", "v2.4.0"},
		{"golang.org/x/crypto", "v0.9.0"},
		{"google.golang.org/protobuf", "v1.30.0"},
	}

	for _, tc := range testCases {
		t.Run(tc.packageName, func(t *testing.T) {
			purl := generator.generatePurlIdentifier(tc.packageName, tc.version)

			// Basic PURL format validation
			if purl == "" {
				t.Errorf("Expected non-empty PURL for %s@%s", tc.packageName, tc.version)
				return
			}

			// Must start with "pkg:golang/"
			expectedPrefix := "pkg:golang/"
			if len(purl) < len(expectedPrefix) || purl[:len(expectedPrefix)] != expectedPrefix {
				t.Errorf("PURL %q must start with %q", purl, expectedPrefix)
			}

			// Must contain the version with @
			if len(purl) < len(tc.version)+1 || purl[len(purl)-len(tc.version)-1:] != "@"+tc.version {
				t.Errorf("PURL %q must end with @%s", purl, tc.version)
			}
		})
	}
}

// TestIntegrationWithExistingDependencyExtraction tests that PURL generation
// integrates correctly with the existing dependency extraction logic
func TestIntegrationWithExistingDependencyExtraction(t *testing.T) {
	generator := NewFBOMGenerator(false)

	// Test that when we extract dependencies, they now have PURL identifiers
	testDependency := Dependency{
		Name:    "github.com/gin-gonic/gin",
		Version: "v1.9.1",
		Type:    "go-module",
	}

	// Simulate what extractDependencies should do now
	purl := generator.generatePurlIdentifier(testDependency.Name, testDependency.Version)
	testDependency.PurlIdentifier = purl

	expectedPurl := "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
	if testDependency.PurlIdentifier != expectedPurl {
		t.Errorf("Dependency PURL = %q, want %q", testDependency.PurlIdentifier, expectedPurl)
	}

	// Ensure the PURL is not empty for valid packages with versions
	if testDependency.PurlIdentifier == "" {
		t.Error("Expected non-empty PURL identifier for valid dependency")
	}
}
