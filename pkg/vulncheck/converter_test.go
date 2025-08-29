package vulncheck

import (
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

func TestConvertToCVEDatabase(t *testing.T) {
	tests := []struct {
		name     string
		input    *ScanResults
		expected *cveloader.CVEDatabase
	}{
		{
			name:  "nil input returns empty database",
			input: nil,
			expected: &cveloader.CVEDatabase{
				CVEs: []models.CVE{},
			},
		},
		{
			name: "empty scan results returns empty database",
			input: &ScanResults{
				Vulnerabilities: []VulnerabilityResult{},
				PackagesScanned: 0,
				TotalIssues:     0,
			},
			expected: &cveloader.CVEDatabase{
				CVEs: []models.CVE{},
			},
		},
		{
			name: "single vulnerability converts correctly",
			input: &ScanResults{
				Vulnerabilities: []VulnerabilityResult{
					{
						ID:        "GO-2023-1234",
						Package:   "github.com/gin-gonic/gin",
						Functions: []string{"Context.File", "Context.FileAttachment"},
						Severity:  "HIGH",
						Summary:   "Path traversal vulnerability",
						Details:   "Detailed description of the vulnerability",
						References: []string{
							"https://github.com/gin-gonic/gin/security/advisories/GHSA-1234",
						},
						Introduced: "v1.0.0",
						Fixed:      "v1.9.1",
					},
				},
				PackagesScanned: 1,
				TotalIssues:     1,
			},
			expected: &cveloader.CVEDatabase{
				CVEs: []models.CVE{
					{
						ID:                  "GO-2023-1234",
						VulnerablePackage:   "github.com/gin-gonic/gin",
						VulnerableFunctions: []string{"Context.File", "Context.FileAttachment"},
						OriginalSeverity:    "High",
						CVSSScore:           8.9,
						Description:         "Path traversal vulnerability Detailed description of the vulnerability",
						References: []string{
							"https://github.com/gin-gonic/gin/security/advisories/GHSA-1234",
						},
						Metadata: map[string]string{
							"source":     "govulncheck",
							"introduced": "v1.0.0",
							"fixed":      "v1.9.1",
						},
					},
				},
			},
		},
		{
			name: "multiple vulnerabilities with different severities",
			input: &ScanResults{
				Vulnerabilities: []VulnerabilityResult{
					{
						ID:       "GO-2023-1111",
						Package:  "github.com/example/pkg1",
						Severity: "LOW",
						Summary:  "Low severity issue",
					},
					{
						ID:       "GO-2023-2222",
						Package:  "github.com/example/pkg2",
						Severity: "CRITICAL",
						Summary:  "Critical security flaw",
					},
					{
						ID:       "GO-2023-3333",
						Package:  "github.com/example/pkg3",
						Severity: "UNKNOWN",
						Summary:  "Unknown severity issue",
					},
				},
				PackagesScanned: 3,
				TotalIssues:     3,
			},
			expected: &cveloader.CVEDatabase{
				CVEs: []models.CVE{
					{
						ID:                "GO-2023-1111",
						VulnerablePackage: "github.com/example/pkg1",
						OriginalSeverity:  "Low",
						CVSSScore:         3.9,
						Description:       "Low severity issue ",
						Metadata: map[string]string{
							"source":     "govulncheck",
							"introduced": "",
							"fixed":      "",
						},
					},
					{
						ID:                "GO-2023-2222",
						VulnerablePackage: "github.com/example/pkg2",
						OriginalSeverity:  "Critical",
						CVSSScore:         10.0,
						Description:       "Critical security flaw ",
						Metadata: map[string]string{
							"source":     "govulncheck",
							"introduced": "",
							"fixed":      "",
						},
					},
					{
						ID:                "GO-2023-3333",
						VulnerablePackage: "github.com/example/pkg3",
						OriginalSeverity:  "Medium",
						CVSSScore:         5.0,
						Description:       "Unknown severity issue ",
						Metadata: map[string]string{
							"source":     "govulncheck",
							"introduced": "",
							"fixed":      "",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertToCVEDatabase(tt.input)

			// Check basic structure
			if len(result.CVEs) != len(tt.expected.CVEs) {
				t.Errorf("Expected %d CVEs, got %d", len(tt.expected.CVEs), len(result.CVEs))
				return
			}

			// Check each CVE
			for i, expectedCVE := range tt.expected.CVEs {
				actualCVE := result.CVEs[i]

				if actualCVE.ID != expectedCVE.ID {
					t.Errorf("CVE %d: Expected ID %s, got %s", i, expectedCVE.ID, actualCVE.ID)
				}

				if actualCVE.VulnerablePackage != expectedCVE.VulnerablePackage {
					t.Errorf("CVE %d: Expected package %s, got %s", i, expectedCVE.VulnerablePackage, actualCVE.VulnerablePackage)
				}

				if actualCVE.OriginalSeverity != expectedCVE.OriginalSeverity {
					t.Errorf("CVE %d: Expected severity %s, got %s", i, expectedCVE.OriginalSeverity, actualCVE.OriginalSeverity)
				}

				if actualCVE.CVSSScore != expectedCVE.CVSSScore {
					t.Errorf("CVE %d: Expected CVSS score %f, got %f", i, expectedCVE.CVSSScore, actualCVE.CVSSScore)
				}

				// Check functions
				if len(actualCVE.VulnerableFunctions) != len(expectedCVE.VulnerableFunctions) {
					t.Errorf("CVE %d: Expected %d functions, got %d", i, len(expectedCVE.VulnerableFunctions), len(actualCVE.VulnerableFunctions))
				}

				// Check metadata
				if actualCVE.Metadata["source"] != "govulncheck" {
					t.Errorf("CVE %d: Expected source metadata to be 'govulncheck', got %s", i, actualCVE.Metadata["source"])
				}
			}
		})
	}
}

func TestIntegrateWithExistingCVEs(t *testing.T) {
	tests := []struct {
		name          string
		existingDB    *cveloader.CVEDatabase
		vulnResults   *ScanResults
		expectedCount int
		expectedIDs   []string
	}{
		{
			name:       "nil existing DB uses only vuln results",
			existingDB: nil,
			vulnResults: &ScanResults{
				Vulnerabilities: []VulnerabilityResult{
					{ID: "GO-2023-1111", Package: "pkg1", Severity: "HIGH"},
				},
			},
			expectedCount: 1,
			expectedIDs:   []string{"GO-2023-1111"},
		},
		{
			name: "nil vuln results returns existing DB",
			existingDB: &cveloader.CVEDatabase{
				CVEs: []models.CVE{
					{ID: "CVE-2023-1111", VulnerablePackage: "pkg1"},
				},
			},
			vulnResults:   nil,
			expectedCount: 1,
			expectedIDs:   []string{"CVE-2023-1111"},
		},
		{
			name: "merges without duplicates",
			existingDB: &cveloader.CVEDatabase{
				CVEs: []models.CVE{
					{ID: "CVE-2023-1111", VulnerablePackage: "pkg1"},
					{ID: "GO-2023-2222", VulnerablePackage: "pkg2"}, // This ID will be duplicated
				},
			},
			vulnResults: &ScanResults{
				Vulnerabilities: []VulnerabilityResult{
					{ID: "GO-2023-2222", Package: "pkg2", Severity: "HIGH"}, // Duplicate
					{ID: "GO-2023-3333", Package: "pkg3", Severity: "LOW"},  // New
				},
			},
			expectedCount: 3, // Original 2 + 1 new (1 duplicate ignored)
			expectedIDs:   []string{"CVE-2023-1111", "GO-2023-2222", "GO-2023-3333"},
		},
		{
			name: "adds all new vulnerabilities",
			existingDB: &cveloader.CVEDatabase{
				CVEs: []models.CVE{
					{ID: "CVE-2023-1111", VulnerablePackage: "pkg1"},
				},
			},
			vulnResults: &ScanResults{
				Vulnerabilities: []VulnerabilityResult{
					{ID: "GO-2023-2222", Package: "pkg2", Severity: "HIGH"},
					{ID: "GO-2023-3333", Package: "pkg3", Severity: "LOW"},
				},
			},
			expectedCount: 3,
			expectedIDs:   []string{"CVE-2023-1111", "GO-2023-2222", "GO-2023-3333"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IntegrateWithExistingCVEs(tt.existingDB, tt.vulnResults)

			if len(result.CVEs) != tt.expectedCount {
				t.Errorf("Expected %d CVEs, got %d", tt.expectedCount, len(result.CVEs))
			}

			// Check that all expected IDs are present
			actualIDs := make([]string, len(result.CVEs))
			for i, cve := range result.CVEs {
				actualIDs[i] = cve.ID
			}

			for _, expectedID := range tt.expectedIDs {
				found := false
				for _, actualID := range actualIDs {
					if actualID == expectedID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected ID %s not found in result. Got IDs: %v", expectedID, actualIDs)
				}
			}
		})
	}
}

func TestSeverityMapping(t *testing.T) {
	severityTests := []struct {
		input        string
		expectedSev  string
		expectedCVSS float64
	}{
		{"LOW", "Low", 3.9},
		{"MODERATE", "Medium", 6.9},
		{"MEDIUM", "Medium", 6.9},
		{"HIGH", "High", 8.9},
		{"CRITICAL", "Critical", 10.0},
		{"UNKNOWN", "Medium", 5.0},
		{"", "Medium", 5.0},
		{"INVALID", "Medium", 5.0},
	}

	for _, tt := range severityTests {
		t.Run("severity_"+tt.input, func(t *testing.T) {
			vulnResults := &ScanResults{
				Vulnerabilities: []VulnerabilityResult{
					{
						ID:       "TEST-123",
						Package:  "test/package",
						Severity: tt.input,
						Summary:  "Test vulnerability",
					},
				},
			}

			cveDB := ConvertToCVEDatabase(vulnResults)

			if len(cveDB.CVEs) != 1 {
				t.Fatalf("Expected 1 CVE, got %d", len(cveDB.CVEs))
			}

			cve := cveDB.CVEs[0]
			if cve.OriginalSeverity != tt.expectedSev {
				t.Errorf("Expected severity %s, got %s", tt.expectedSev, cve.OriginalSeverity)
			}

			if cve.CVSSScore != tt.expectedCVSS {
				t.Errorf("Expected CVSS score %f, got %f", tt.expectedCVSS, cve.CVSSScore)
			}
		})
	}
}
