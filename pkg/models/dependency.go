package models

// Dependency represents a dependency in the project
type Dependency struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Type            string                 `json:"type"`
	SPDXId          string                 `json:"spdx_id"`
	PackageManager  string                 `json:"package_manager"`
	PurlIdentifier  string                 `json:"purl_identifier"`
	UsedFunctions   int                    `json:"used_functions"`
	CalledFunctions []ExternalFunctionCall `json:"called_functions,omitempty"`
}

// DependencyCluster represents a cluster of dependency functions for attack surface analysis
type DependencyCluster struct {
	Name               string             `json:"name"`
	EntryPoints        []DependencyEntry  `json:"entry_points"`
	AttackPaths        []AttackPath       `json:"attack_paths"`
	BlastRadiusSummary BlastRadiusSummary `json:"blast_radius_summary"`
	ClusterFunctions   []string           `json:"cluster_functions,omitempty"` // Deprecated: kept for backward compatibility
	TotalBlastRadius   int                `json:"total_blast_radius"`
}

// AttackPath represents a specific call path from entry point through the dependency
type AttackPath struct {
	EntryFunction    string     `json:"entry_function"`
	PathDepth        int        `json:"path_depth"`
	RiskLevel        string     `json:"risk_level"` // "low", "medium", "high", "critical"
	Path             []PathStep `json:"path"`
	VulnerabilityIDs []string   `json:"vulnerability_ids,omitempty"`
}

// PathStep represents a single step in an attack path
type PathStep struct {
	Function       string   `json:"function"`
	Package        string   `json:"package"`
	CallType       string   `json:"call_type"`                 // "direct", "transitive", "reflection"
	RiskIndicators []string `json:"risk_indicators,omitempty"` // ["CVE-CANDIDATE", "DESERIALIZATION", "REFLECTION"]
}

// BlastRadiusSummary provides high-level statistics about the dependency cluster
type BlastRadiusSummary struct {
	DirectFunctions     int      `json:"direct_functions"`
	TransitiveFunctions int      `json:"transitive_functions"`
	HighRiskPaths       int      `json:"high_risk_paths"`
	PackagesReached     []string `json:"packages_reached"`
	MaxPathDepth        int      `json:"max_path_depth"`
}

// DependencyEntry represents an entry point into a dependency cluster
type DependencyEntry struct {
	Function   string   `json:"function"`
	CalledFrom []string `json:"called_from"`
}
