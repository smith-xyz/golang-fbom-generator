package models

// AnalysisConfig contains configuration options for various analysis features
type AnalysisConfig struct {
	// Attack Path Analysis Configuration
	AttackPathMaxDepth int // Maximum traversal depth for attack paths
	AttackPathMaxEdges int // Maximum edges per node in attack paths

	// Call Graph Analysis Configuration
	CallGraphMaxDepth int // Maximum depth for call graph analysis
	CallGraphMaxEdges int // Maximum edges per function in call graph

	// Reflection Analysis Configuration
	ReflectionAnalysisEnabled bool // Enable/disable reflection analysis
	ReflectionMaxDepth        int  // Maximum depth for reflection analysis

	// CVE Analysis Configuration
	CVEAnalysisEnabled bool // Enable/disable CVE analysis
	LiveCVEScan        bool // Enable live CVE scanning

	// General Configuration
	Verbose bool // Enable verbose logging
}
