package models

// Parameter represents a function parameter
type Parameter struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// UsageInfo contains runtime and security metadata
type UsageInfo struct {
	Calls               []string `json:"calls"`
	CalledBy            []string `json:"called_by"`
	ExternalCalls       []string `json:"external_calls"` // Calls to external dependency functions
	StdlibCalls         []string `json:"stdlib_calls"`   // Calls to standard library functions
	IsReachable         bool     `json:"is_reachable"`
	ReachabilityType    string   `json:"reachability_type"` // direct, transitive, unreachable
	DistanceFromEntry   int      `json:"distance_from_entry"`
	InCriticalPath      bool     `json:"in_critical_path"`
	HasReflectionAccess bool     `json:"has_reflection_access"`
	IsEntryPoint        bool     `json:"is_entry_point"`
	CVEReferences       []string `json:"cve_references"`
}

// Function represents a function in the FBOM with rich metadata
type Function struct {
	SPDXId          string      `json:"spdx_id"`
	Name            string      `json:"name"`
	FullName        string      `json:"full_name"`
	Package         string      `json:"package"`
	FilePath        string      `json:"file_path"`
	StartLine       int         `json:"start_line"`
	EndLine         int         `json:"end_line"`
	Signature       string      `json:"signature"`
	Visibility      string      `json:"visibility"`    // "public", "private", "internal"
	FunctionType    string      `json:"function_type"` // "regular", "method", "closure", "init", "main"
	IsExported      bool        `json:"is_exported"`
	Parameters      []Parameter `json:"parameters"`
	ReturnTypes     []string    `json:"return_types"`
	UsageInfo       UsageInfo   `json:"usage_info"`
	SecurityTags    []string    `json:"security_tags,omitempty"`
	SecurityHotspot bool        `json:"security_hotspot,omitempty"`
}

// EntryPoint represents application entry points and exposed APIs
type EntryPoint struct {
	SPDXId             string   `json:"spdx_id"`
	Name               string   `json:"name"`
	Type               string   `json:"type"` // main, http_handler, test, init
	Package            string   `json:"package"`
	AccessibleFrom     []string `json:"accessible_from"`     // ["external", "network", "internal"]
	SecurityLevel      string   `json:"security_level"`      // "public", "internal", "restricted"
	ReachableFunctions int      `json:"reachable_functions"` // Count of functions reachable from this entry point
}

// ExternalFunctionCall represents a call to an external dependency function
type ExternalFunctionCall struct {
	FunctionName     string   `json:"function_name"`      // e.g., "x"
	FullFunctionName string   `json:"full_function_name"` // e.g., "github.com/pkg/a.x"
	CallSites        []string `json:"call_sites"`         // List of user functions that call this
	CallCount        int      `json:"call_count"`         // Number of times called
	CallContext      string   `json:"call_context"`       // "direct", "reflection", "interface", "callback"
}
