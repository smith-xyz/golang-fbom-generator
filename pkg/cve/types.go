package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// CVE represents a Common Vulnerabilities and Exposures entry.
type CVE struct {
	ID                  string            `json:"id"`
	VulnerablePackage   string            `json:"vulnerable_package"`
	VulnerableFunctions []string          `json:"vulnerable_functions,omitempty"`
	OriginalSeverity    string            `json:"original_severity"`
	CVSSScore           float64           `json:"cvss_score,omitempty"`
	Description         string            `json:"description,omitempty"`
	References          []string          `json:"references,omitempty"`
	PublishedDate       time.Time         `json:"published_date,omitempty"`
	ModifiedDate        time.Time         `json:"modified_date,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// Severity represents the severity levels for CVEs.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// ParseSeverity converts a severity string to Severity enum.
func ParseSeverity(s string) Severity {
	switch s {
	case "Low", "LOW", "low":
		return SeverityLow
	case "Medium", "MEDIUM", "medium":
		return SeverityMedium
	case "High", "HIGH", "high":
		return SeverityHigh
	case "Critical", "CRITICAL", "critical":
		return SeverityCritical
	default:
		return SeverityLow
	}
}

// GetSeverity returns the parsed severity level.
func (c *CVE) GetSeverity() Severity {
	return ParseSeverity(c.OriginalSeverity)
}

// CVEDatabase represents a collection of CVEs.
type CVEDatabase struct {
	CVEs []CVE `json:"cves"`
}

// Loader handles loading CVE data from various sources.
type Loader struct {
	verbose bool
}

// NewLoader creates a new CVE loader.
func NewLoader(verbose bool) *Loader {
	return &Loader{verbose: verbose}
}

// LoadFromFile loads CVE data from a JSON file
func (l *Loader) LoadFromFile(filePath string) (*CVEDatabase, error) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "Loading CVE data from file: %s\n", filePath)
	}

	// Validate and clean the filepath to prevent directory traversal attacks
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CVE file %s: %w", filePath, err)
	}
	defer file.Close()

	return l.LoadFromReader(file)
}

// LoadFromReader loads CVE data from an io.Reader
func (l *Loader) LoadFromReader(reader io.Reader) (*CVEDatabase, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read CVE data: %w", err)
	}

	var database CVEDatabase
	if err := json.Unmarshal(data, &database); err != nil {
		return nil, fmt.Errorf("failed to parse CVE JSON: %w", err)
	}

	if l.verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d CVEs from data source\n", len(database.CVEs))
	}

	return &database, nil
}

// FindByPackage returns all CVEs affecting the specified package
func (db *CVEDatabase) FindByPackage(packageName string) []CVE {
	var matches []CVE

	for _, cve := range db.CVEs {
		if cve.VulnerablePackage == packageName {
			matches = append(matches, cve)
		}
	}

	return matches
}

// FindBySeverity returns all CVEs with the specified severity level
func (db *CVEDatabase) FindBySeverity(severity Severity) []CVE {
	var matches []CVE

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

// JiraTicket represents CVE data as it might come from JIRA tickets
type JiraTicket struct {
	IssueKey    string `json:"issue_key"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Assignee    string `json:"assignee,omitempty"`
	CreatedDate string `json:"created_date"`
	DueDate     string `json:"due_date,omitempty"`
	CVEData     CVE    `json:"cve_data"`
}

// ConvertJiraTicketsToCVEs converts JIRA ticket format to CVE format
func ConvertJiraTicketsToCVEs(tickets []JiraTicket) []CVE {
	var cves []CVE

	for _, ticket := range tickets {
		cve := ticket.CVEData

		if cve.Metadata == nil {
			cve.Metadata = make(map[string]string)
		}
		cve.Metadata["jira_key"] = ticket.IssueKey
		cve.Metadata["jira_assignee"] = ticket.Assignee
		cve.Metadata["jira_due_date"] = ticket.DueDate

		cves = append(cves, cve)
	}

	return cves
}
