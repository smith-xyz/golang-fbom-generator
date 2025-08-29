package cve

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// RiskAssessor handles risk assessment for CVEs
type RiskAssessor struct {
	logger  *slog.Logger
	verbose bool
}

// NewRiskAssessor creates a new risk assessor
func NewRiskAssessor(logger *slog.Logger, verbose bool) *RiskAssessor {
	return &RiskAssessor{
		logger:  logger,
		verbose: verbose,
	}
}

// AssessReflectionRisk assesses reflection-based risks for specific paths
func (r *RiskAssessor) AssessReflectionRisk(reflectionUsage map[string]*models.Usage, paths []models.CallPath) models.RiskLevel {
	maxRisk := models.RiskNone

	for i := range paths {
		path := &paths[i]
		for _, step := range path.Steps {
			if usage, exists := reflectionUsage[step]; exists && usage.UsesReflection {
				path.HasReflection = true
				path.ReflectionNodes = append(path.ReflectionNodes, step)
				if usage.ReflectionRisk > maxRisk {
					maxRisk = usage.ReflectionRisk
				}
			}
		}
	}

	return maxRisk
}

// AssessGlobalReflectionRisk assesses global reflection-based risks
func (r *RiskAssessor) AssessGlobalReflectionRisk(reflectionUsage map[string]*models.Usage, vulnerablePackage string) models.RiskLevel {
	maxRisk := models.RiskNone

	for funcName, usage := range reflectionUsage {
		if usage.UsesReflection {
			// Check if this function has high-risk reflection calls
			if usage.ReflectionRisk >= models.RiskHigh {
				if r.verbose {
					r.logger.Debug("High-risk reflection found", "function", funcName, "risk", usage.ReflectionRisk.String(), "could_call", vulnerablePackage)
				}
				maxRisk = usage.ReflectionRisk
			}
		}
	}

	return maxRisk
}

// CalculatePriority calculates CVE priority based on reachability and reflection risk
func (r *RiskAssessor) CalculatePriority(targetCVE models.CVE, reachability models.ReachabilityResult, reflectionRisk models.RiskLevel) string {
	originalSeverity := models.ParseSeverity(targetCVE.OriginalSeverity)

	// Start with original severity
	newSeverity := originalSeverity

	// Adjust based on reachability
	switch reachability.Status {
	case models.NotReachable:
		// Significantly lower priority
		if newSeverity > models.SeverityLow {
			newSeverity = models.SeverityLow
		}
	case models.DirectlyReachable:
		// Keep high priority, possibly increase
		if reachability.MinDistance <= 2 && newSeverity == models.SeverityHigh {
			newSeverity = models.SeverityCritical
		}
	case models.TransitivelyReachable:
		// Adjust based on distance
		if reachability.MinDistance > 5 {
			// Far from entry points, lower priority
			if newSeverity > models.SeverityMedium {
				newSeverity--
			}
		}
	}

	// Factor in reflection risk
	if reflectionRisk >= models.RiskHigh {
		return "UNCERTAIN (High reflection risk - manual review required)"
	} else if reflectionRisk >= models.RiskMedium {
		return newSeverity.String() + " (Caution: Reflection in call path)"
	}

	return newSeverity.String()
}

// GenerateJustification generates human-readable justification for assessment
func (r *RiskAssessor) GenerateJustification(assessment *models.Assessment) string {
	parts := []string{}

	switch assessment.ReachabilityStatus {
	case models.NotReachable:
		parts = append(parts, "Vulnerable functions not found in call graph")
	case models.DirectlyReachable:
		parts = append(parts, fmt.Sprintf("Directly reachable from entry points (distance: %d)", assessment.EntryPointDistance))
	case models.TransitivelyReachable:
		parts = append(parts, fmt.Sprintf("Reachable via %d call paths (min distance: %d)", len(assessment.CallPaths), assessment.EntryPointDistance))
	}

	if assessment.ReflectionRisk > models.RiskNone {
		parts = append(parts, fmt.Sprintf("Reflection risk: %s", assessment.ReflectionRisk.String()))
	}

	if len(parts) == 0 {
		return "Analysis completed"
	}

	return strings.Join(parts, "; ")
}

// AssessPathRisk assesses risk level for attack paths
func (r *RiskAssessor) AssessPathRisk(path []models.PathStep) string {
	score := 0

	for _, step := range path {
		// Base scoring
		switch step.CallType {
		case "reflection":
			score += 3
		case "transitive":
			score += 1
		}

		// Risk indicator scoring
		for _, indicator := range step.RiskIndicators {
			switch indicator {
			case "REFLECTION":
				score += 2
			case "DESERIALIZATION":
				score += 3
			case "NETWORK":
				score += 1
			}
		}
	}

	if score >= 8 {
		return "critical"
	} else if score >= 5 {
		return "high"
	} else if score >= 2 {
		return "medium"
	}
	return "low"
}
