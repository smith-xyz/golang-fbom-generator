package cveloader

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

func createTestCVE() models.CVE {
	publishedDate, _ := time.Parse("2006-01-02", "2023-01-01")
	modifiedDate, _ := time.Parse("2006-01-02", "2023-01-15")

	return models.CVE{
		ID:                  "CVE-2023-0001",
		VulnerablePackage:   "github.com/example/vulnerable",
		VulnerableFunctions: []string{"vulnerableFunc1", "vulnerableFunc2"},
		OriginalSeverity:    "High",
		CVSSScore:           7.5,
		Description:         "Test vulnerability description",
		References:          []string{"https://example.com/cve-2023-0001"},
		PublishedDate:       publishedDate,
		ModifiedDate:        modifiedDate,
		Metadata: map[string]string{
			"category": "security",
			"type":     "injection",
		},
	}
}

func createTestCVEDatabase() *CVEDatabase {
	return &CVEDatabase{
		CVEs: []models.CVE{
			createTestCVE(),
			{
				ID:                "CVE-2023-0002",
				VulnerablePackage: "github.com/example/another",
				OriginalSeverity:  "Medium",
				CVSSScore:         5.0,
				Description:       "Another test vulnerability",
			},
			{
				ID:                "CVE-2023-0003",
				VulnerablePackage: "github.com/example/vulnerable",
				OriginalSeverity:  "Low",
				CVSSScore:         2.5,
				Description:       "Low severity vulnerability",
			},
		},
	}
}

func TestNewLoader(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
	}{
		{"verbose loader", true},
		{"non-verbose loader", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewLoader(tt.verbose)
			if loader == nil {
				t.Fatal("NewLoader() returned nil")
			}
			if loader.verbose != tt.verbose {
				t.Errorf("Expected verbose %v, got %v", tt.verbose, loader.verbose)
			}
		})
	}
}

func TestLoadFromReader(t *testing.T) {
	loader := NewLoader(true) // Enable verbose for coverage

	// Create test JSON data
	testDB := createTestCVEDatabase()
	jsonData, err := json.Marshal(testDB)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	// Test successful loading
	reader := strings.NewReader(string(jsonData))
	result, err := loader.LoadFromReader(reader)
	if err != nil {
		t.Fatalf("LoadFromReader() error = %v", err)
	}

	if result == nil {
		t.Fatal("LoadFromReader() returned nil")
	}

	if len(result.CVEs) != len(testDB.CVEs) {
		t.Errorf("Expected %d CVEs, got %d", len(testDB.CVEs), len(result.CVEs))
	}

	// Verify first CVE is loaded correctly
	if len(result.CVEs) > 0 {
		firstCVE := result.CVEs[0]
		expectedCVE := testDB.CVEs[0]

		if firstCVE.ID != expectedCVE.ID {
			t.Errorf("Expected CVE ID %s, got %s", expectedCVE.ID, firstCVE.ID)
		}
		if firstCVE.VulnerablePackage != expectedCVE.VulnerablePackage {
			t.Errorf("Expected package %s, got %s", expectedCVE.VulnerablePackage, firstCVE.VulnerablePackage)
		}
	}

	// Test invalid JSON
	invalidReader := strings.NewReader("{invalid json")
	_, err = loader.LoadFromReader(invalidReader)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestLoadFromFile(t *testing.T) {
	loader := NewLoader(false)

	// Create temporary test file
	testDB := createTestCVEDatabase()
	jsonData, err := json.Marshal(testDB)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "cve_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(jsonData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	// Test successful loading
	result, err := loader.LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if result == nil {
		t.Fatal("LoadFromFile() returned nil")
	}

	if len(result.CVEs) != len(testDB.CVEs) {
		t.Errorf("Expected %d CVEs, got %d", len(testDB.CVEs), len(result.CVEs))
	}

	// Test loading non-existent file
	_, err = loader.LoadFromFile("non_existent_file.json")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestCVEDatabaseFindByPackage(t *testing.T) {
	db := createTestCVEDatabase()

	tests := []struct {
		name          string
		packageName   string
		expectedCount int
	}{
		{
			name:          "package with multiple CVEs",
			packageName:   "github.com/example/vulnerable",
			expectedCount: 2,
		},
		{
			name:          "package with single CVE",
			packageName:   "github.com/example/another",
			expectedCount: 1,
		},
		{
			name:          "non-existent package",
			packageName:   "github.com/example/nonexistent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := db.FindByPackage(tt.packageName)
			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d CVEs for package %s, got %d",
					tt.expectedCount, tt.packageName, len(results))
			}

			// Verify all results match the package
			for _, cve := range results {
				if cve.VulnerablePackage != tt.packageName {
					t.Errorf("Expected package %s, got %s", tt.packageName, cve.VulnerablePackage)
				}
			}
		})
	}
}

func TestCVEDatabaseFindBySeverity(t *testing.T) {
	db := createTestCVEDatabase()

	tests := []struct {
		name          string
		severity      models.Severity
		expectedCount int
	}{
		{
			name:          "high severity",
			severity:      models.SeverityHigh,
			expectedCount: 1,
		},
		{
			name:          "medium severity",
			severity:      models.SeverityMedium,
			expectedCount: 1,
		},
		{
			name:          "low severity",
			severity:      models.SeverityLow,
			expectedCount: 1,
		},
		{
			name:          "critical severity",
			severity:      models.SeverityCritical,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := db.FindBySeverity(tt.severity)
			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d CVEs with severity %v, got %d",
					tt.expectedCount, tt.severity, len(results))
			}

			// Verify all results match the severity
			for _, cve := range results {
				if cve.GetSeverity() != tt.severity {
					t.Errorf("Expected severity %v, got %v", tt.severity, cve.GetSeverity())
				}
			}
		})
	}
}

func TestCVEDatabaseGetPackages(t *testing.T) {
	db := createTestCVEDatabase()

	packages := db.GetPackages()

	expectedPackages := []string{
		"github.com/example/vulnerable",
		"github.com/example/another",
	}

	if len(packages) != len(expectedPackages) {
		t.Errorf("Expected %d unique packages, got %d", len(expectedPackages), len(packages))
	}

	// Check that all expected packages are present
	packageMap := make(map[string]bool)
	for _, pkg := range packages {
		packageMap[pkg] = true
	}

	for _, expectedPkg := range expectedPackages {
		if !packageMap[expectedPkg] {
			t.Errorf("Expected package %s not found in results", expectedPkg)
		}
	}
}

func TestJSONMarshalling(t *testing.T) {
	// Test that CVE struct can be marshalled and unmarshalled correctly
	originalCVE := createTestCVE()

	// Marshal to JSON
	jsonData, err := json.Marshal(originalCVE)
	if err != nil {
		t.Fatalf("Failed to marshal CVE: %v", err)
	}

	// Unmarshal from JSON
	var unmarshalledCVE models.CVE
	err = json.Unmarshal(jsonData, &unmarshalledCVE)
	if err != nil {
		t.Fatalf("Failed to unmarshal CVE: %v", err)
	}

	// Compare key fields
	if unmarshalledCVE.ID != originalCVE.ID {
		t.Errorf("ID mismatch: expected %s, got %s", originalCVE.ID, unmarshalledCVE.ID)
	}

	if unmarshalledCVE.VulnerablePackage != originalCVE.VulnerablePackage {
		t.Errorf("VulnerablePackage mismatch: expected %s, got %s",
			originalCVE.VulnerablePackage, unmarshalledCVE.VulnerablePackage)
	}

	if unmarshalledCVE.OriginalSeverity != originalCVE.OriginalSeverity {
		t.Errorf("OriginalSeverity mismatch: expected %s, got %s",
			originalCVE.OriginalSeverity, unmarshalledCVE.OriginalSeverity)
	}

	if unmarshalledCVE.CVSSScore != originalCVE.CVSSScore {
		t.Errorf("CVSSScore mismatch: expected %f, got %f",
			originalCVE.CVSSScore, unmarshalledCVE.CVSSScore)
	}
}

func TestCVEDatabaseJSONMarshalling(t *testing.T) {
	// Test that CVEDatabase can be marshalled and unmarshalled correctly
	originalDB := createTestCVEDatabase()

	// Marshal to JSON
	jsonData, err := json.Marshal(originalDB)
	if err != nil {
		t.Fatalf("Failed to marshal CVEDatabase: %v", err)
	}

	// Unmarshal from JSON
	var unmarshalledDB CVEDatabase
	err = json.Unmarshal(jsonData, &unmarshalledDB)
	if err != nil {
		t.Fatalf("Failed to unmarshal CVEDatabase: %v", err)
	}

	// Compare
	if len(unmarshalledDB.CVEs) != len(originalDB.CVEs) {
		t.Errorf("CVE count mismatch: expected %d, got %d",
			len(originalDB.CVEs), len(unmarshalledDB.CVEs))
	}

	// Check first CVE
	if len(unmarshalledDB.CVEs) > 0 && len(originalDB.CVEs) > 0 {
		if unmarshalledDB.CVEs[0].ID != originalDB.CVEs[0].ID {
			t.Errorf("First CVE ID mismatch: expected %s, got %s",
				originalDB.CVEs[0].ID, unmarshalledDB.CVEs[0].ID)
		}
	}
}

// Edge case tests
func TestEmptyDatabase(t *testing.T) {
	db := &CVEDatabase{CVEs: []models.CVE{}}

	// Test operations on empty database
	packages := db.GetPackages()
	if len(packages) != 0 {
		t.Errorf("Expected 0 packages for empty database, got %d", len(packages))
	}

	cves := db.FindByPackage("any.package")
	if len(cves) != 0 {
		t.Errorf("Expected 0 CVEs for any package in empty database, got %d", len(cves))
	}

	cves = db.FindBySeverity(models.SeverityHigh)
	if len(cves) != 0 {
		t.Errorf("Expected 0 CVEs for any severity in empty database, got %d", len(cves))
	}
}

func TestCVEWithEmptyFields(t *testing.T) {
	cve := models.CVE{
		ID:                "CVE-2023-EMPTY",
		VulnerablePackage: "",
		OriginalSeverity:  "",
	}

	// Test that empty severity defaults to Low
	severity := cve.GetSeverity()
	if severity != models.SeverityLow {
		t.Errorf("Expected empty severity to default to Low, got %v", severity)
	}

	// Test JSON marshalling with empty fields
	jsonData, err := json.Marshal(cve)
	if err != nil {
		t.Fatalf("Failed to marshal CVE with empty fields: %v", err)
	}

	var unmarshalledCVE models.CVE
	err = json.Unmarshal(jsonData, &unmarshalledCVE)
	if err != nil {
		t.Fatalf("Failed to unmarshal CVE with empty fields: %v", err)
	}

	if unmarshalledCVE.ID != cve.ID {
		t.Errorf("ID mismatch after marshalling: expected %s, got %s", cve.ID, unmarshalledCVE.ID)
	}
}

// Benchmark tests
func BenchmarkFindByPackage(b *testing.B) {
	db := createTestCVEDatabase()
	packageName := "github.com/example/vulnerable"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.FindByPackage(packageName)
	}
}

func BenchmarkFindBySeverity(b *testing.B) {
	db := createTestCVEDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.FindBySeverity(models.SeverityHigh)
	}
}

func BenchmarkParseSeverity(b *testing.B) {
	severities := []string{"Low", "Medium", "High", "Critical", "Unknown"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		models.ParseSeverity(severities[i%len(severities)])
	}
}

func BenchmarkJSONMarshalling(b *testing.B) {
	cve := createTestCVE()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(cve)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}
