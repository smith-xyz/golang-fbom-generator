package vulncheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
)

func TestNewIntegration(t *testing.T) {
	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	if integration == nil {
		t.Fatal("Integration should not be nil")
	}

	if integration.scanner == nil {
		t.Fatal("Scanner should not be nil")
	}

	if integration.verbose != false {
		t.Error("Verbose should be false")
	}

	// Test with verbose
	verboseIntegration, err := NewIntegration(true)
	if err != nil {
		t.Fatalf("Failed to create verbose integration: %v", err)
	}

	if verboseIntegration.verbose != true {
		t.Error("Verbose should be true")
	}
}

func TestCreateTempCVEFileFromDatabase(t *testing.T) {
	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	tests := []struct {
		name     string
		input    *cve.CVEDatabase
		expected map[string]interface{}
	}{
		{
			name: "empty database creates valid file",
			input: &cve.CVEDatabase{
				CVEs: []cve.CVE{},
			},
			expected: map[string]interface{}{
				"cves": []interface{}{},
			},
		},
		{
			name: "single CVE creates valid file",
			input: &cve.CVEDatabase{
				CVEs: []cve.CVE{
					{
						ID:                "GO-2023-1234",
						VulnerablePackage: "github.com/gin-gonic/gin",
						OriginalSeverity:  "High",
						CVSSScore:         8.9,
						Description:       "Test vulnerability",
					},
				},
			},
			expected: map[string]interface{}{
				"cves": []interface{}{
					map[string]interface{}{
						"id":                 "GO-2023-1234",
						"vulnerable_package": "github.com/gin-gonic/gin",
						"original_severity":  "High",
						"cvss_score":         8.9,
						"description":        "Test vulnerability",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileName, cleanup, err := integration.CreateTempCVEFileFromDatabase(tt.input)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer cleanup()

			// Check file exists
			if _, err := os.Stat(fileName); os.IsNotExist(err) {
				t.Fatal("Temp file was not created")
			}

			// Read and parse file content
			content, err := os.ReadFile(fileName)
			if err != nil {
				t.Fatalf("Failed to read temp file: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(content, &parsed); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			// Basic structure check
			cves, ok := parsed["cves"].([]interface{})
			if !ok {
				t.Fatal("Expected 'cves' array in JSON")
			}

			expectedCves := tt.expected["cves"].([]interface{})
			if len(cves) != len(expectedCves) {
				t.Errorf("Expected %d CVEs, got %d", len(expectedCves), len(cves))
			}

			// Check cleanup works
			cleanup()
			if _, err := os.Stat(fileName); !os.IsNotExist(err) {
				t.Error("Temp file should be cleaned up after calling cleanup()")
			}
		})
	}
}

func TestMergeWithExistingCVEFile(t *testing.T) {
	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	// Create a temporary existing CVE file
	existingCVEData := &cve.CVEDatabase{
		CVEs: []cve.CVE{
			{
				ID:                "CVE-2023-1111",
				VulnerablePackage: "github.com/existing/package",
				OriginalSeverity:  "Medium",
				CVSSScore:         6.5,
				Description:       "Existing vulnerability",
			},
		},
	}

	tempDir, err := os.MkdirTemp("", "cve-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	existingFile := filepath.Join(tempDir, "existing.json")
	existingFileHandle, err := os.Create(existingFile)
	if err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	encoder := json.NewEncoder(existingFileHandle)
	if err := encoder.Encode(existingCVEData); err != nil {
		t.Fatalf("Failed to write existing CVE data: %v", err)
	}
	existingFileHandle.Close()

	// Test merging
	liveCVEData := &cve.CVEDatabase{
		CVEs: []cve.CVE{
			{
				ID:                "GO-2023-2222",
				VulnerablePackage: "github.com/live/package",
				OriginalSeverity:  "High",
				CVSSScore:         8.9,
				Description:       "Live vulnerability",
			},
		},
	}

	result, err := integration.MergeWithExistingCVEFile(existingFile, liveCVEData)
	if err != nil {
		t.Fatalf("Failed to merge CVE files: %v", err)
	}

	// Check results
	if len(result.CVEs) != 2 {
		t.Errorf("Expected 2 CVEs after merge, got %d", len(result.CVEs))
	}

	// Check that both CVEs are present
	foundExisting := false
	foundLive := false
	for _, cve := range result.CVEs {
		if cve.ID == "CVE-2023-1111" {
			foundExisting = true
		}
		if cve.ID == "GO-2023-2222" {
			foundLive = true
		}
	}

	if !foundExisting {
		t.Error("Existing CVE not found in merged result")
	}
	if !foundLive {
		t.Error("Live CVE not found in merged result")
	}
}

func TestReportScanResults(t *testing.T) {
	// Capture stderr for testing
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	testResults := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{
			{
				ID:       "GO-2023-1111",
				Package:  "test/package1",
				Severity: "HIGH",
			},
			{
				ID:       "GO-2023-2222",
				Package:  "test/package2",
				Severity: "MEDIUM",
			},
		},
		PackagesScanned: 2,
		TotalIssues:     2,
	}

	// Call the method
	integration.reportScanResults(testResults)

	// Restore stderr and read output
	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}
	output := buf.String()

	// Check expected content
	expectedStrings := []string{
		"Live CVE Scan Results:",
		"Packages scanned: 2",
		"Vulnerabilities found: 2",
		"GO-2023-1111 (HIGH) - test/package1",
		"GO-2023-2222 (MEDIUM) - test/package2",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestReportScanResultsNoVulnerabilities(t *testing.T) {
	// Capture stderr for testing
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	testResults := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{},
		PackagesScanned: 5,
		TotalIssues:     0,
	}

	// Call the method
	integration.reportScanResults(testResults)

	// Restore stderr and read output
	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}
	output := buf.String()

	// Check expected content
	expectedStrings := []string{
		"Live CVE Scan Results:",
		"Packages scanned: 5",
		"Vulnerabilities found: 0",
		"No vulnerabilities found",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestConvertCVEDatabaseToScanResults(t *testing.T) {
	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	cveDB := &cve.CVEDatabase{
		CVEs: []cve.CVE{
			{
				ID:                  "CVE-2023-1111",
				VulnerablePackage:   "github.com/test/package1",
				VulnerableFunctions: []string{"Function1", "Function2"},
				OriginalSeverity:    "High",
				Description:         "Test vulnerability description",
			},
			{
				ID:                "CVE-2023-2222",
				VulnerablePackage: "github.com/test/package2",
				OriginalSeverity:  "Low",
				Description:       "Another test vulnerability",
			},
		},
	}

	result := integration.convertCVEDatabaseToScanResults(cveDB)

	// Check basic structure
	if result.TotalIssues != 2 {
		t.Errorf("Expected TotalIssues to be 2, got %d", result.TotalIssues)
	}

	if len(result.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(result.Vulnerabilities))
	}

	// Check first vulnerability
	vuln1 := result.Vulnerabilities[0]
	if vuln1.ID != "CVE-2023-1111" {
		t.Errorf("Expected ID 'CVE-2023-1111', got '%s'", vuln1.ID)
	}

	if vuln1.Package != "github.com/test/package1" {
		t.Errorf("Expected package 'github.com/test/package1', got '%s'", vuln1.Package)
	}

	if len(vuln1.Functions) != 2 {
		t.Errorf("Expected 2 functions, got %d", len(vuln1.Functions))
	}

	if vuln1.Severity != "High" {
		t.Errorf("Expected severity 'High', got '%s'", vuln1.Severity)
	}

	if vuln1.Summary != "Test vulnerability description" {
		t.Errorf("Expected summary 'Test vulnerability description', got '%s'", vuln1.Summary)
	}
}

func TestErrorHandling(t *testing.T) {
	integration, err := NewIntegration(false)
	if err != nil {
		t.Fatalf("Failed to create integration: %v", err)
	}

	t.Run("merge with non-existent file", func(t *testing.T) {
		liveCVEData := &cve.CVEDatabase{CVEs: []cve.CVE{}}
		_, err := integration.MergeWithExistingCVEFile("/nonexistent/file.json", liveCVEData)
		if err == nil {
			t.Error("Expected error when merging with non-existent file")
		}
	})

	t.Run("create temp file with nil database", func(t *testing.T) {
		fileName, cleanup, err := integration.CreateTempCVEFileFromDatabase(nil)
		if err != nil {
			t.Fatalf("Should handle nil database gracefully: %v", err)
		}
		defer cleanup()

		// File should be created and contain empty CVEs array
		content, err := os.ReadFile(fileName)
		if err != nil {
			t.Fatalf("Failed to read temp file: %v", err)
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal(content, &parsed); err != nil {
			t.Fatalf("Failed to parse JSON: %v", err)
		}

		if cves, ok := parsed["cves"]; !ok || cves == nil {
			t.Error("Expected 'cves' field in JSON output")
		}
	})
}
