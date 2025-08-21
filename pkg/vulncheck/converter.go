package vulncheck

import (
	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
)

// ConvertToCVEDatabase converts vulncheck results to CVE database format
func ConvertToCVEDatabase(results *ScanResults) *cve.CVEDatabase {
	if results == nil {
		return &cve.CVEDatabase{CVEs: []cve.CVE{}}
	}

	var cves []cve.CVE

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

		cveEntry := cve.CVE{
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

	return &cve.CVEDatabase{CVEs: cves}
}

// IntegrateWithExistingCVEs merges govulncheck results with existing CVE data
func IntegrateWithExistingCVEs(existingDB *cve.CVEDatabase, vulnResults *ScanResults) *cve.CVEDatabase {
	if existingDB == nil {
		return ConvertToCVEDatabase(vulnResults)
	}

	if vulnResults == nil {
		return existingDB
	}

	mergedCVEs := make([]cve.CVE, len(existingDB.CVEs))
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

	return &cve.CVEDatabase{CVEs: mergedCVEs}
}
