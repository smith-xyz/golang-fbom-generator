package vulncheck

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
)

// Scanner handles vulnerability scanning using govulncheck
type Scanner struct {
	verbose bool
}

// VulnerabilityResult represents a vulnerability found by the scanner
type VulnerabilityResult struct {
	ID         string   `json:"id"`
	Package    string   `json:"package"`
	Functions  []string `json:"functions,omitempty"`
	Severity   string   `json:"severity"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	References []string `json:"references,omitempty"`
	Introduced string   `json:"introduced,omitempty"`
	Fixed      string   `json:"fixed,omitempty"`
}

// ScanResults contains all vulnerability results
type ScanResults struct {
	Vulnerabilities []VulnerabilityResult `json:"vulnerabilities"`
	PackagesScanned int                   `json:"packages_scanned"`
	TotalIssues     int                   `json:"total_issues"`
}

// GovulncheckOutput represents the JSON output from govulncheck
type GovulncheckOutput struct {
	Vulns []struct {
		OSV struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
			Details string `json:"details"`
		} `json:"osv"`
		Modules []struct {
			Path         string `json:"path"`
			FoundVersion string `json:"found_version,omitempty"`
			FixedVersion string `json:"fixed_version,omitempty"`
			Packages     []struct {
				Path      string `json:"path"`
				CallStack []struct {
					Symbol   string `json:"symbol"`
					Name     string `json:"name"`
					Position struct {
						Filename string `json:"filename"`
						Line     int    `json:"line"`
						Column   int    `json:"column"`
					} `json:"pos"`
				} `json:"call_stacks,omitempty"`
			} `json:"packages,omitempty"`
		} `json:"modules"`
	} `json:"vulns"`
}

// NewScanner creates a new vulnerability scanner using govulncheck
func NewScanner(verbose bool) (*Scanner, error) {
	if err := utils.CheckGovulncheckAvailable(verbose); err != nil {
		return nil, err
	}

	return &Scanner{
		verbose: verbose,
	}, nil
}

// ScanProject scans the entire project for vulnerabilities
func (s *Scanner) ScanProject(projectPath string) (*ScanResults, error) {
	if s.verbose {
		fmt.Fprintf(os.Stderr, "Scanning project for vulnerabilities: %s\n", projectPath)
	}

	result := utils.ExecuteGovulncheck([]string{"-json", "./..."}, projectPath, s.verbose)

	if !utils.IsGovulncheckSuccessOrExpectedFailure(result) {
		return nil, fmt.Errorf("govulncheck failed: %w", result.Error)
	}

	results, err := s.parseGovulncheckOutput(result.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse govulncheck output: %w", err)
	}

	if s.verbose {
		fmt.Fprintf(os.Stderr, "Vulnerability scan completed: %d issues found\n", results.TotalIssues)
	}

	return results, nil
}

// ScanPackage scans a specific package for vulnerabilities within the project context
func (s *Scanner) ScanPackage(projectPath, packageName string) (*ScanResults, error) {
	if s.verbose {
		fmt.Fprintf(os.Stderr, "Scanning package '%s' within project context: %s\n", packageName, projectPath)
	}

	allResults, err := s.ScanProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan project for package filtering: %w", err)
	}

	filteredResults := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{},
		PackagesScanned: allResults.PackagesScanned,
		TotalIssues:     0,
	}

	for _, vuln := range allResults.Vulnerabilities {
		if vuln.Package == packageName || strings.HasPrefix(vuln.Package, packageName+"/") {
			filteredResults.Vulnerabilities = append(filteredResults.Vulnerabilities, vuln)
		}
	}

	filteredResults.TotalIssues = len(filteredResults.Vulnerabilities)

	if s.verbose {
		fmt.Fprintf(os.Stderr, "Package filter completed: %d/%d vulnerabilities match package '%s'\n",
			filteredResults.TotalIssues, allResults.TotalIssues, packageName)
	}

	return filteredResults, nil
}

// parseGovulncheckOutput parses the JSON output from govulncheck
func (s *Scanner) parseGovulncheckOutput(output []byte) (*ScanResults, error) {
	results := &ScanResults{
		Vulnerabilities: []VulnerabilityResult{},
		PackagesScanned: 0,
		TotalIssues:     0,
	}

	seenVulns := make(map[string]bool)
	osvDatabase := make(map[string]map[string]interface{})

	decoder := json.NewDecoder(strings.NewReader(string(output)))

	for {
		var entry map[string]interface{}
		if err := decoder.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			if s.verbose {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse JSON object: %v\n", err)
			}
			continue
		}

		if entry["osv"] != nil {
			osv, ok := entry["osv"].(map[string]interface{})
			if ok && osv["id"] != nil {
				if id, ok := osv["id"].(string); ok {
					// Store the full OSV data including symbol information
					osvDatabase[id] = osv
				}
			}
		}

		if entry["finding"] != nil {
			vuln := s.parseFindingEntry(entry, osvDatabase)
			if vuln != nil && !seenVulns[vuln.ID] {
				results.Vulnerabilities = append(results.Vulnerabilities, *vuln)
				seenVulns[vuln.ID] = true
			}
		}
	}

	results.TotalIssues = len(results.Vulnerabilities)
	results.PackagesScanned = 1

	return results, nil
}

// parseFindingEntry parses a finding entry from govulncheck JSON output
func (s *Scanner) parseFindingEntry(entry map[string]interface{}, osvDatabase map[string]map[string]interface{}) *VulnerabilityResult {
	finding, ok := entry["finding"].(map[string]interface{})
	if !ok {
		return nil
	}

	osvID, ok := finding["osv"].(string)
	if !ok {
		return nil
	}

	osvData, exists := osvDatabase[osvID]
	if !exists {
		osvData = make(map[string]interface{})
	}

	vuln := &VulnerabilityResult{
		ID:         osvID,
		Functions:  []string{},
		References: []string{},
		Severity:   "UNKNOWN",
	}

	if summary, ok := osvData["summary"].(string); ok {
		vuln.Summary = summary
	}

	if details, ok := osvData["details"].(string); ok {
		vuln.Details = details
	}

	if fixedVersion, ok := finding["fixed_version"].(string); ok {
		vuln.Fixed = fixedVersion
	}

	if trace, ok := finding["trace"].([]interface{}); ok && len(trace) > 0 {
		if traceItem, ok := trace[0].(map[string]interface{}); ok {
			if module, ok := traceItem["module"].(string); ok {
				vuln.Package = module
			}
			if version, ok := traceItem["version"].(string); ok {
				vuln.Introduced = version
			}
		}

		// Note: govulncheck trace doesn't contain function names,
		// we extract them from OSV data below
	}

	// Extract vulnerable functions/symbols from OSV data
	if affected, ok := osvData["affected"].([]interface{}); ok {
		for _, affectedItem := range affected {
			if affectedMap, ok := affectedItem.(map[string]interface{}); ok {
				if ecosystemSpecific, ok := affectedMap["ecosystem_specific"].(map[string]interface{}); ok {
					if imports, ok := ecosystemSpecific["imports"].([]interface{}); ok {
						for _, importItem := range imports {
							if importMap, ok := importItem.(map[string]interface{}); ok {
								if symbols, ok := importMap["symbols"].([]interface{}); ok {
									for _, symbol := range symbols {
										if symbolStr, ok := symbol.(string); ok {
											vuln.Functions = append(vuln.Functions, symbolStr)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if strings.Contains(strings.ToUpper(vuln.Summary), "CRITICAL") {
		vuln.Severity = "CRITICAL"
	} else if strings.Contains(strings.ToUpper(vuln.Summary), "HIGH") {
		vuln.Severity = "HIGH"
	} else if strings.Contains(strings.ToUpper(vuln.Summary), "MEDIUM") {
		vuln.Severity = "MEDIUM"
	} else if strings.Contains(strings.ToUpper(vuln.Summary), "LOW") {
		vuln.Severity = "LOW"
	}

	return vuln
}

// parseVulnerabilityEntry parses a single vulnerability entry from govulncheck JSON (legacy method)
func (s *Scanner) parseVulnerabilityEntry(entry map[string]interface{}) *VulnerabilityResult {
	osv, ok := entry["osv"].(map[string]interface{})
	if !ok {
		return nil
	}

	vuln := &VulnerabilityResult{
		Functions:  []string{},
		References: []string{},
	}

	if id, ok := osv["id"].(string); ok {
		vuln.ID = id
	}

	if summary, ok := osv["summary"].(string); ok {
		vuln.Summary = summary
	}

	if details, ok := osv["details"].(string); ok {
		vuln.Details = details
	}

	vuln.Severity = "UNKNOWN"

	if strings.Contains(strings.ToUpper(vuln.Summary), "CRITICAL") {
		vuln.Severity = "CRITICAL"
	} else if strings.Contains(strings.ToUpper(vuln.Summary), "HIGH") {
		vuln.Severity = "HIGH"
	} else if strings.Contains(strings.ToUpper(vuln.Summary), "MEDIUM") {
		vuln.Severity = "MEDIUM"
	} else if strings.Contains(strings.ToUpper(vuln.Summary), "LOW") {
		vuln.Severity = "LOW"
	}

	// Parse modules to extract package and version information
	if modules, ok := entry["modules"].([]interface{}); ok && len(modules) > 0 {
		if module, ok := modules[0].(map[string]interface{}); ok {
			if path, ok := module["path"].(string); ok {
				vuln.Package = path
			}
			if foundVersion, ok := module["found_version"].(string); ok {
				vuln.Introduced = foundVersion
			}
			if fixedVersion, ok := module["fixed_version"].(string); ok {
				vuln.Fixed = fixedVersion
			}
		}
	}

	return vuln
}
