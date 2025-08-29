package models

import "go/token"

// AST related types
// Usage represents reflection usage information for a function discovered via AST analysis.
type Usage struct {
	FunctionName    string
	PackageName     string
	FilePath        string
	Position        token.Position
	UsesReflection  bool
	ReflectionCalls []ReflectionCall
	ReflectionRisk  RiskLevel
}

// ReflectionCall represents a specific call to the reflect package.
type ReflectionCall struct {
	Method   string
	Position token.Position
	Context  string
}

// RiskLevel indicates the security risk level of reflection usage.
type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
)

func (r RiskLevel) String() string {
	switch r {
	case RiskNone:
		return "None"
	case RiskLow:
		return "Low"
	case RiskMedium:
		return "Medium"
	case RiskHigh:
		return "High"
	default:
		return "Unknown"
	}
}

// reflection analysis types

// ReflectionAnalysis contains analysis of reflection-based calls and their targets
type ReflectionAnalysis struct {
	// High-level summary for quick overview
	Summary ReflectionSummary `json:"summary"`

	// User-focused reflection functions in your codebase
	UserReflectionFunctions []UserReflectionFunction `json:"user_reflection_functions"`

	// Direct vulnerability exposure from your reflection code
	VulnerabilityExposure []ReflectionVulnerabilityExposure `json:"vulnerability_exposure"`

	// Attack chains from your code to vulnerable functions
	AttackChains []ReflectionAttackChain `json:"attack_chains"`

	// Detailed targets (moved to end to reduce noise)
	DetailedTargets   []ReflectionTarget `json:"detailed_targets,omitempty"`
	TotalTargets      int                `json:"total_targets"`
	HighRiskTargets   int                `json:"high_risk_targets"`
	MediumRiskTargets int                `json:"medium_risk_targets"`
	LowRiskTargets    int                `json:"low_risk_targets"`
}

// ReflectionSummary provides high-level reflection security overview
type ReflectionSummary struct {
	UserReflectionFunctions      int    `json:"user_reflection_functions"`      // Functions in your code using reflection
	VulnerableFunctionsReachable int    `json:"vulnerable_functions_reachable"` // CVE functions reachable via reflection
	HighRiskReflectionPaths      int    `json:"high_risk_reflection_paths"`     // Paths to high-risk functions
	ReflectionComplexity         string `json:"reflection_complexity"`          // "simple", "moderate", "complex"
	RecommendedAction            string `json:"recommended_action"`             // User guidance
}

// UserReflectionFunction represents a function in your codebase that uses reflection
type UserReflectionFunction struct {
	FunctionName             string   `json:"function_name"`             // e.g., "processAdvancedReflectionRequest"
	Package                  string   `json:"package"`                   // e.g., "main" or "internal/processor"
	ReflectionMethods        []string `json:"reflection_methods"`        // e.g., ["reflect.Call", "reflect.MethodByName"]
	ReachableVulnerabilities []string `json:"reachable_vulnerabilities"` // CVE IDs reachable from this function
	RiskScore                int      `json:"risk_score"`                // 1-10 scale
	ReflectionComplexity     string   `json:"reflection_complexity"`     // "direct", "layered", "dynamic"
}

// ReflectionVulnerabilityExposure shows direct CVE exposure via reflection
type ReflectionVulnerabilityExposure struct {
	CVEId                   string   `json:"cve_id"`                    // e.g., "GO-2024-2611"
	VulnerableFunction      string   `json:"vulnerable_function"`       // e.g., "protojson.Unmarshal"
	YourReflectionFunctions []string `json:"your_reflection_functions"` // Your functions that can reach this CVE
	AttackComplexity        string   `json:"attack_complexity"`         // "low", "medium", "high"
	ExploitLikelihood       string   `json:"exploit_likelihood"`        // "low", "medium", "high"
}

// ReflectionAttackChain shows step-by-step attack path
type ReflectionAttackChain struct {
	CVEId            string   `json:"cve_id"`            // Target vulnerability
	EntryPoint       string   `json:"entry_point"`       // e.g., "HTTP /api/advanced-reflection"
	ChainSteps       []string `json:"chain_steps"`       // Step-by-step path
	LayerCount       int      `json:"layer_count"`       // Number of reflection layers
	AttackComplexity string   `json:"attack_complexity"` // Difficulty for attacker
}

// ReflectionTarget represents a function that can be called via reflection
type ReflectionTarget struct {
	TargetPackage     string   `json:"target_package"`     // e.g., "google.golang.org/protobuf/encoding/protojson"
	TargetFunction    string   `json:"target_function"`    // e.g., "Unmarshal"
	FullTargetName    string   `json:"full_target_name"`   // e.g., "google.golang.org/protobuf/encoding/protojson.Unmarshal"
	ReflectionCallers []string `json:"reflection_callers"` // User functions that use reflection to call this
	ReflectionMethods []string `json:"reflection_methods"` // e.g., ["reflect.Call", "reflect.MethodByName"]
	RiskLevel         string   `json:"risk_level"`         // "high", "medium", "low"
	CallCount         int      `json:"call_count"`         // Number of reflection call sites
}
