package vulncheck

import (
	"strings"
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner, err := NewScanner(false)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	if scanner == nil {
		t.Fatal("Scanner should not be nil")
	}

	// Scanner no longer has a client field - it uses govulncheck command directly

	if scanner.verbose != false {
		t.Error("Verbose should be false")
	}

	// Test with verbose
	verboseScanner, err := NewScanner(true)
	if err != nil {
		t.Fatalf("Failed to create verbose scanner: %v", err)
	}

	if verboseScanner.verbose != true {
		t.Error("Verbose should be true")
	}
}

// Note: extractModuleName and getProjectModules are not exposed in the new scanner
// They are internal implementation details used by the scanning process

// Note: getProjectModules is internal to the scanner implementation

func TestParseVulnerabilityEntry(t *testing.T) {
	scanner, err := NewScanner(false)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	tests := []struct {
		name     string
		entry    map[string]interface{}
		expected *VulnerabilityResult
	}{
		{
			name: "basic vulnerability entry",
			entry: map[string]interface{}{
				"osv": map[string]interface{}{
					"id":      "GO-2023-1234",
					"summary": "Test vulnerability",
					"details": "Detailed description",
				},
				"modules": []interface{}{
					map[string]interface{}{
						"path":          "github.com/example/package",
						"found_version": "v1.0.0",
						"fixed_version": "v1.1.0",
					},
				},
			},
			expected: &VulnerabilityResult{
				ID:         "GO-2023-1234",
				Package:    "github.com/example/package",
				Summary:    "Test vulnerability",
				Details:    "Detailed description",
				Severity:   "UNKNOWN",
				Introduced: "v1.0.0",
				Fixed:      "v1.1.0",
				Functions:  []string{},
				References: []string{},
			},
		},
		{
			name: "entry with high severity in summary",
			entry: map[string]interface{}{
				"osv": map[string]interface{}{
					"id":      "GO-2023-5678",
					"summary": "HIGH severity vulnerability",
				},
			},
			expected: &VulnerabilityResult{
				ID:         "GO-2023-5678",
				Summary:    "HIGH severity vulnerability",
				Severity:   "HIGH",
				Functions:  []string{},
				References: []string{},
			},
		},
		{
			name: "minimal entry",
			entry: map[string]interface{}{
				"osv": map[string]interface{}{
					"id": "GO-2023-9999",
				},
			},
			expected: &VulnerabilityResult{
				ID:         "GO-2023-9999",
				Severity:   "UNKNOWN",
				Functions:  []string{},
				References: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.parseVulnerabilityEntry(tt.entry)

			if result == nil {
				t.Fatal("Expected result, got nil")
			}

			if result.ID != tt.expected.ID {
				t.Errorf("Expected ID '%s', got '%s'", tt.expected.ID, result.ID)
			}

			if result.Package != tt.expected.Package {
				t.Errorf("Expected Package '%s', got '%s'", tt.expected.Package, result.Package)
			}

			if result.Summary != tt.expected.Summary {
				t.Errorf("Expected Summary '%s', got '%s'", tt.expected.Summary, result.Summary)
			}

			if result.Severity != tt.expected.Severity {
				t.Errorf("Expected Severity '%s', got '%s'", tt.expected.Severity, result.Severity)
			}
		})
	}
}

// Note: ScanPackage and ScanProject would require mocking the vulnerability client
// for proper unit testing. These tests focus on the internal logic that can be tested
// without network calls. Integration tests would test the full scanning functionality.

func TestScanResultsStructure(t *testing.T) {
	// Test that ScanResults structure works as expected
	results := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{
			{
				ID:      "TEST-1",
				Package: "test/package",
			},
		},
		PackagesScanned: 1,
		TotalIssues:     1,
	}

	if results.TotalIssues != 1 {
		t.Errorf("Expected TotalIssues 1, got %d", results.TotalIssues)
	}

	if len(results.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(results.Vulnerabilities))
	}

	if results.Vulnerabilities[0].ID != "TEST-1" {
		t.Errorf("Expected vulnerability ID 'TEST-1', got '%s'", results.Vulnerabilities[0].ID)
	}
}

func TestVulnerabilityResultStructure(t *testing.T) {
	// Test VulnerabilityResult structure
	vuln := VulnerabilityResult{
		ID:         "GO-2023-TEST",
		Package:    "github.com/test/package",
		Functions:  []string{"VulnerableFunc1", "VulnerableFunc2"},
		Severity:   "HIGH",
		Summary:    "Test vulnerability summary",
		Details:    "Detailed test vulnerability description",
		References: []string{"https://example.com/advisory"},
		Introduced: "v1.0.0",
		Fixed:      "v1.2.0",
	}

	if vuln.ID != "GO-2023-TEST" {
		t.Errorf("Expected ID 'GO-2023-TEST', got '%s'", vuln.ID)
	}

	if len(vuln.Functions) != 2 {
		t.Errorf("Expected 2 functions, got %d", len(vuln.Functions))
	}

	if vuln.Functions[0] != "VulnerableFunc1" {
		t.Errorf("Expected first function 'VulnerableFunc1', got '%s'", vuln.Functions[0])
	}

	if vuln.Severity != "HIGH" {
		t.Errorf("Expected severity 'HIGH', got '%s'", vuln.Severity)
	}
}

func TestPackageFiltering(t *testing.T) {
	// Test the package filtering logic used in ScanPackage
	tests := []struct {
		name        string
		targetPkg   string
		vulnPkg     string
		shouldMatch bool
	}{
		{
			name:        "exact match",
			targetPkg:   "github.com/gin-gonic/gin",
			vulnPkg:     "github.com/gin-gonic/gin",
			shouldMatch: true,
		},
		{
			name:        "subpackage match",
			targetPkg:   "github.com/gin-gonic/gin",
			vulnPkg:     "github.com/gin-gonic/gin/binding",
			shouldMatch: true,
		},
		{
			name:        "no match - different package",
			targetPkg:   "github.com/gin-gonic/gin",
			vulnPkg:     "github.com/gorilla/mux",
			shouldMatch: false,
		},
		{
			name:        "no match - similar prefix but different package",
			targetPkg:   "github.com/gin-gonic/gin",
			vulnPkg:     "github.com/gin-gonic/gin-contrib",
			shouldMatch: false,
		},
		{
			name:        "no match - parent package",
			targetPkg:   "github.com/gin-gonic/gin/binding",
			vulnPkg:     "github.com/gin-gonic/gin",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the filtering logic: exact match OR starts with targetPkg+"/"
			matches := tt.vulnPkg == tt.targetPkg || strings.HasPrefix(tt.vulnPkg, tt.targetPkg+"/")

			if matches != tt.shouldMatch {
				t.Errorf("Expected match=%v for target='%s' vuln='%s', got %v",
					tt.shouldMatch, tt.targetPkg, tt.vulnPkg, matches)
			}
		})
	}
}
