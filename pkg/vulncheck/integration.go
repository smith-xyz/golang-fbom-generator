package vulncheck

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// Integration handles the integration of live vulnerability scanning with FBOM generation
type Integration struct {
	scanner *Scanner
	verbose bool
}

// NewIntegration creates a new CVE integration handler
func NewIntegration(verbose bool) (*Integration, error) {
	scanner, err := NewScanner(verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to create vulnerability scanner: %w", err)
	}

	return &Integration{
		scanner: scanner,
		verbose: verbose,
	}, nil
}

// ScanAndConvert performs vulnerability scanning and converts results to CVE database format
func (i *Integration) ScanAndConvert(packagePath, specificPackage string) (*cveloader.CVEDatabase, error) {
	var results *ScanResults
	var err error

	if specificPackage != "" {
		if i.verbose {
			fmt.Fprintf(os.Stderr, "Performing live CVE scan for package: %s\n", specificPackage)
		}
		results, err = i.scanner.ScanPackage(packagePath, specificPackage)
	} else {
		if i.verbose {
			fmt.Fprintf(os.Stderr, "Performing live CVE scan for project: %s\n", packagePath)
		}
		results, err = i.scanner.ScanProject(packagePath)
	}

	if err != nil {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	i.reportScanResults(results)

	return ConvertToCVEDatabase(results), nil
}

// MergeWithExistingCVEFile merges live scan results with an existing CVE file
func (i *Integration) MergeWithExistingCVEFile(existingFile string, liveCVEData *cveloader.CVEDatabase) (*cveloader.CVEDatabase, error) {
	if i.verbose {
		fmt.Fprintf(os.Stderr, "Merging existing CVE file with live scan results\n")
	}

	existingLoader := cveloader.NewLoader(i.verbose)
	existingDB, err := existingLoader.LoadFromFile(existingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load existing CVE file: %w", err)
	}

	liveResults := i.convertCVEDatabaseToScanResults(liveCVEData)

	mergedDB := IntegrateWithExistingCVEs(existingDB, liveResults)

	if i.verbose {
		fmt.Fprintf(os.Stderr, "Merged CVE database contains %d vulnerabilities\n", len(mergedDB.CVEs))
	}

	return mergedDB, nil
}

// CreateTempCVEFileFromDatabase creates a temporary CVE file from in-memory CVE database
func (i *Integration) CreateTempCVEFileFromDatabase(cveDB *cveloader.CVEDatabase) (string, func(), error) {
	tempFile, err := os.CreateTemp("", "live-cve-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary file: %w", err)
	}

	var fileClosed bool
	cleanup := func() {
		if !fileClosed {
			if err := tempFile.Close(); err != nil {
				// Log close error but don't fail the operation
				fmt.Fprintf(os.Stderr, "Warning: failed to close temp file: %v\n", err)
			}
			fileClosed = true
		}
		if err := os.Remove(tempFile.Name()); err != nil {
			// Log removal error but don't fail the operation
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp file: %v\n", err)
		}
	}

	if err := i.writeCVEDatabaseToFile(cveDB, tempFile); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to write CVE data: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to close temporary file: %w", err)
	}
	fileClosed = true

	return tempFile.Name(), cleanup, nil
}

// reportScanResults reports the vulnerability scan results to stderr
func (i *Integration) reportScanResults(results *ScanResults) {
	fmt.Fprintf(os.Stderr, "Live CVE Scan Results:\n")
	fmt.Fprintf(os.Stderr, "├─ Packages scanned: %d\n", results.PackagesScanned)
	fmt.Fprintf(os.Stderr, "├─ Vulnerabilities found: %d\n", results.TotalIssues)

	if results.TotalIssues > 0 {
		fmt.Fprintf(os.Stderr, "└─ Vulnerabilities will be integrated into FBOM analysis\n")
		for _, vuln := range results.Vulnerabilities {
			fmt.Fprintf(os.Stderr, "   • %s (%s) - %s\n", vuln.ID, vuln.Severity, vuln.Package)
		}
	} else {
		fmt.Fprintf(os.Stderr, "└─ No vulnerabilities found\n")
	}
}

// convertCVEDatabaseToScanResults converts CVE database back to scan results format for merging
func (i *Integration) convertCVEDatabaseToScanResults(cveDB *cveloader.CVEDatabase) *ScanResults {
	results := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{},
		PackagesScanned: len(cveDB.GetPackages()),
		TotalIssues:     len(cveDB.CVEs),
	}

	for _, cveCve := range cveDB.CVEs {
		vuln := VulnerabilityResult{
			ID:        cveCve.ID,
			Package:   cveCve.VulnerablePackage,
			Functions: cveCve.VulnerableFunctions,
			Severity:  cveCve.OriginalSeverity,
			Summary:   cveCve.Description,
			Details:   "",
		}
		results.Vulnerabilities = append(results.Vulnerabilities, vuln)
	}

	return results
}

// writeCVEDatabaseToFile writes CVE database to a file
func (i *Integration) writeCVEDatabaseToFile(cveDB *cveloader.CVEDatabase, file *os.File) error {
	if cveDB == nil {
		cveDB = &cveloader.CVEDatabase{CVEs: []models.CVE{}}
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cveDB)
}
