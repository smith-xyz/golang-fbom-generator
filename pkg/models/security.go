package models

// SecurityInfo contains security-relevant information
type SecurityInfo struct {
	VulnerableFunctions        []VulnerableFunction `json:"vulnerable_functions"`
	UnreachableVulnerabilities []string             `json:"unreachable_vulnerabilities"`
	ReflectionCallsCount       int                  `json:"reflection_calls_count"`
	TotalCVEsFound             int                  `json:"total_cves_found"`
	TotalReachableCVEs         int                  `json:"total_reachable_cves"`
}

// VulnerableFunction represents a function with known CVEs
type VulnerableFunction struct {
	FunctionId        string   `json:"function_id"`
	FullName          string   `json:"full_name"` // package.function for clarity when available
	CVEs              []string `json:"cves"`
	ReachabilityPaths []string `json:"reachability_paths"`
	RiskScore         float64  `json:"risk_score"`
	Impact            string   `json:"impact"` // critical, high, medium, low
}

// SecurityHotspot represents a function handling sensitive operations
type SecurityHotspot struct {
	FunctionId       string   `json:"function_id"`
	HotspotType      string   `json:"hotspot_type"`      // crypto, network, file_io, user_input
	SensitivityLevel string   `json:"sensitivity_level"` // low, medium, high, critical
	DataTypes        []string `json:"data_types"`        // pii, credentials, crypto_keys
}

type Assessment struct {
	CVE                  CVE
	OriginalPriority     string
	CalculatedPriority   string
	ReachabilityStatus   ReachabilityStatus
	ReflectionRisk       RiskLevel
	CallPaths            []CallPath
	EntryPointDistance   int
	Justification        string
	RequiresManualReview bool
}

// ReachabilityStatus indicates how a vulnerable function can be reached.
type ReachabilityStatus int

const (
	NotReachable ReachabilityStatus = iota
	DirectlyReachable
	TransitivelyReachable
	ReflectionPossible
	Unknown
)

func (r ReachabilityStatus) String() string {
	switch r {
	case NotReachable:
		return "Not Reachable"
	case DirectlyReachable:
		return "Directly Reachable"
	case TransitivelyReachable:
		return "Transitively Reachable"
	case ReflectionPossible:
		return "Potentially Reachable via Reflection"
	case Unknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// ReachabilityResult represents the result of reachability analysis
type ReachabilityResult struct {
	Status      ReachabilityStatus
	Paths       []CallPath
	MinDistance int
}

// CallPath represents a path from an entry point to a vulnerable function
type CallPath struct {
	EntryPoint      string
	VulnerableFunc  string
	Steps           []string
	Length          int
	HasReflection   bool
	ReflectionNodes []string
}
