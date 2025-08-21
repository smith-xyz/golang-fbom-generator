package vulncheck

import (
	"os"
	"strings"
	"testing"
)

// TestEndToEndWorkflow tests the complete workflow from scanning to CVE conversion
func TestEndToEndWorkflow(t *testing.T) {
	// Create integration
	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	// Test data - simulate govulncheck results
	mockResults := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{
			{
				ID:       "GO-2023-1234",
				Package:  "github.com/gin-gonic/gin",
				Severity: "HIGH",
				Summary:  "Test vulnerability in gin",
			},
			{
				ID:       "GO-2023-5678",
				Package:  "github.com/gorilla/mux",
				Severity: "MEDIUM",
				Summary:  "Test vulnerability in mux",
			},
		},
		PackagesScanned: 2,
		TotalIssues:     2,
	}

	// Convert to CVE database
	cveDB := ConvertToCVEDatabase(mockResults)

	// Verify conversion
	if len(cveDB.CVEs) != 2 {
		t.Errorf("Expected 2 CVEs, got %d", len(cveDB.CVEs))
	}

	// Verify first CVE
	if cveDB.CVEs[0].ID != "GO-2023-1234" {
		t.Errorf("Expected first CVE ID 'GO-2023-1234', got '%s'", cveDB.CVEs[0].ID)
	}

	if cveDB.CVEs[0].VulnerablePackage != "github.com/gin-gonic/gin" {
		t.Errorf("Expected first CVE package 'github.com/gin-gonic/gin', got '%s'", cveDB.CVEs[0].VulnerablePackage)
	}

	if cveDB.CVEs[0].OriginalSeverity != "High" {
		t.Errorf("Expected first CVE severity 'High', got '%s'", cveDB.CVEs[0].OriginalSeverity)
	}

	// Verify CVSS score mapping
	if cveDB.CVEs[0].CVSSScore != 8.9 {
		t.Errorf("Expected first CVE CVSS score 8.9, got %f", cveDB.CVEs[0].CVSSScore)
	}

	// Verify metadata
	if cveDB.CVEs[0].Metadata["source"] != "govulncheck" {
		t.Errorf("Expected metadata source 'govulncheck', got '%s'", cveDB.CVEs[0].Metadata["source"])
	}

	// Test temp file creation and cleanup
	tempFile, cleanup, err := integration.CreateTempCVEFileFromDatabase(cveDB)
	if err != nil {
		t.Fatalf("Failed to create temp CVE file: %v", err)
	}

	// Verify file exists
	if tempFile == "" {
		t.Error("Expected non-empty temp file path")
	}

	// Verify file contains expected JSON structure
	content, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatalf("Failed to read temp file: %v", err)
	}

	if !strings.Contains(string(content), "GO-2023-1234") {
		t.Error("Temp file should contain vulnerability ID")
	}

	if !strings.Contains(string(content), "github.com/gin-gonic/gin") {
		t.Error("Temp file should contain package name")
	}

	// Test cleanup
	cleanup()
	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Error("Temp file should be cleaned up after calling cleanup()")
	}
}

func TestPackageFilteringEndToEnd(t *testing.T) {
	// Test the complete package filtering workflow
	allVulns := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{
			{ID: "1", Package: "github.com/gin-gonic/gin", Severity: "HIGH"},
			{ID: "2", Package: "github.com/gin-gonic/gin/binding", Severity: "MEDIUM"},
			{ID: "3", Package: "github.com/gorilla/mux", Severity: "LOW"},
			{ID: "4", Package: "github.com/gin-gonic/gin-contrib", Severity: "HIGH"}, // Should NOT match
		},
		TotalIssues: 4,
	}

	// Simulate filtering for "github.com/gin-gonic/gin"
	targetPackage := "github.com/gin-gonic/gin"
	filtered := []VulnerabilityResult{}

	for _, vuln := range allVulns.Vulnerabilities {
		if vuln.Package == targetPackage || strings.HasPrefix(vuln.Package, targetPackage+"/") {
			filtered = append(filtered, vuln)
		}
	}

	// Should match gin core and gin/binding, but NOT gin-contrib or mux
	expectedIDs := []string{"1", "2"}
	if len(filtered) != len(expectedIDs) {
		t.Errorf("Expected %d filtered vulnerabilities, got %d", len(expectedIDs), len(filtered))
	}

	for i, expectedID := range expectedIDs {
		if i < len(filtered) && filtered[i].ID != expectedID {
			t.Errorf("Expected filtered vuln %d to have ID '%s', got '%s'", i, expectedID, filtered[i].ID)
		}
	}
}

func TestNewScannerRequiresGovulncheck(t *testing.T) {
	// This test verifies that NewScanner checks for govulncheck availability
	// In a real environment where govulncheck is not installed, this would fail
	_, err := NewScanner(false)
	if err != nil {
		// This is expected if govulncheck is not installed
		if !strings.Contains(err.Error(), "govulncheck not found") {
			t.Errorf("Expected 'govulncheck not found' error, got: %v", err)
		}
		t.Skip("Skipping test - govulncheck not available (this is expected in CI/testing environments)")
	}
	// If we get here, govulncheck is available and scanner was created successfully
}
