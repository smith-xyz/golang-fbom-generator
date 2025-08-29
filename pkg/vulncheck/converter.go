package vulncheck

import (
	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// ConvertToCVEDatabase converts vulncheck results to CVE database format
func ConvertToCVEDatabase(results *ScanResults) *cveloader.CVEDatabase {
	if results == nil {
		return &cveloader.CVEDatabase{CVEs: []models.CVE{}}
	}

	var cves []models.CVE

	for _, vuln := range results.Vulnerabilities {
		var cvss float64
		var severity string

		switch vuln.Severity {
		case "LOW":
			cvss = 3.9
			severity = "Low"
		case "MODERATE", "MEDIUM":
			cvss = 6.9
			severity = "Medium"
		case "HIGH":
			cvss = 8.9
			severity = "High"
		case "CRITICAL":
			cvss = 10.0
			severity = "Critical"
		default:
			cvss = 5.0
			severity = "Medium"
		}

		cveEntry := models.CVE{
			ID:                  vuln.ID,
			VulnerablePackage:   vuln.Package,
			VulnerableFunctions: vuln.Functions,
			OriginalSeverity:    severity,
			CVSSScore:           cvss,
			Description:         vuln.Summary + " " + vuln.Details,
			References:          vuln.References,
			Metadata: map[string]string{
				"source":     "govulncheck",
				"introduced": vuln.Introduced,
				"fixed":      vuln.Fixed,
			},
		}

		cves = append(cves, cveEntry)
	}

	return &cveloader.CVEDatabase{CVEs: cves}
}

// IntegrateWithExistingCVEs merges govulncheck results with existing CVE data
func IntegrateWithExistingCVEs(existingDB *cveloader.CVEDatabase, vulnResults *ScanResults) *cveloader.CVEDatabase {
	if existingDB == nil {
		return ConvertToCVEDatabase(vulnResults)
	}

	if vulnResults == nil {
		return existingDB
	}

	mergedCVEs := make([]models.CVE, len(existingDB.CVEs))
	copy(mergedCVEs, existingDB.CVEs)

	vulnDB := ConvertToCVEDatabase(vulnResults)

	existingCVEMap := make(map[string]bool)
	for _, existingCVE := range existingDB.CVEs {
		existingCVEMap[existingCVE.ID] = true
	}

	for _, vulnCVE := range vulnDB.CVEs {
		if !existingCVEMap[vulnCVE.ID] {
			mergedCVEs = append(mergedCVEs, vulnCVE)
		}
	}

	return &cveloader.CVEDatabase{CVEs: mergedCVEs}
}
