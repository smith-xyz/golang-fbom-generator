package models

// CallGraphInfo contains call graph statistics
type CallGraphInfo struct {
	TotalFunctions     int        `json:"total_functions"`
	UsedFunctions      int        `json:"used_functions"`   // Reachable/called functions
	UnusedFunctions    int        `json:"unused_functions"` // Unreachable/uncalled functions
	TotalEdges         int        `json:"total_edges"`
	MaxDepth           int        `json:"max_depth"`
	AvgDepth           float64    `json:"avg_depth"`
	CallEdges          []CallEdge `json:"call_edges"`
	ReachableFunctions int        `json:"reachable_functions"` // Deprecated: use used_functions instead
}

// CallEdge represents a call relationship between functions
type CallEdge struct {
	Caller     string `json:"caller"`
	Callee     string `json:"callee"`
	CallType   string `json:"call_type"` // direct, indirect, virtual, external, stdlib
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
}

// CriticalPath represents a path from entry point to sensitive function
type CriticalPath struct {
	Id         string   `json:"id"`
	EntryPoint string   `json:"entry_point"`
	TargetFunc string   `json:"target_function"`
	PathLength int      `json:"path_length"`
	Functions  []string `json:"functions"`
	RiskScore  float64  `json:"risk_score"`
}
