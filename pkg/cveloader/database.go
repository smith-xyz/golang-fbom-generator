package cveloader

import "github.com/smith-xyz/golang-fbom-generator/pkg/models"

// CVEDatabase represents a collection of CVEs.
type CVEDatabase struct {
	CVEs []models.CVE `json:"cves"`
}

// FindByPackage returns all CVEs affecting the specified package
func (db *CVEDatabase) FindByPackage(packageName string) []models.CVE {
	var matches []models.CVE

	for _, cve := range db.CVEs {
		if cve.VulnerablePackage == packageName {
			matches = append(matches, cve)
		}
	}

	return matches
}

// FindBySeverity returns all CVEs with the specified severity level
func (db *CVEDatabase) FindBySeverity(severity models.Severity) []models.CVE {
	var matches []models.CVE

	for _, cve := range db.CVEs {
		if cve.GetSeverity() == severity {
			matches = append(matches, cve)
		}
	}

	return matches
}

// GetPackages returns a list of all unique vulnerable packages
func (db *CVEDatabase) GetPackages() []string {
	packageSet := make(map[string]bool)

	for _, cve := range db.CVEs {
		packageSet[cve.VulnerablePackage] = true
	}

	var packages []string
	for pkg := range packageSet {
		packages = append(packages, pkg)
	}

	return packages
}
