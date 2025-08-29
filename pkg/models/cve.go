package models

import (
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
