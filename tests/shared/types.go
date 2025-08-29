// Package shared contains common test types and utilities used across different test packages
package shared

// TestExpectation represents the expected results for a test case
type TestExpectation struct {
	TestName    string `yaml:"test_name"`
	Description string `yaml:"description"`

	Expectations struct {
		Dependencies       []ExpectedDependency        `yaml:"dependencies"`
		Functions          []ExpectedFunction          `yaml:"functions"`
		SecurityInfo       ExpectedSecurityInfo        `yaml:"security_info"`
		DependencyClusters []ExpectedDependencyCluster `yaml:"dependency_clusters"`
	} `yaml:"expectations"`

	Assertions []Assertion `yaml:"assertions"`
}

type ExpectedDependency struct {
	Name                 string                 `yaml:"name"`
	Version              string                 `yaml:"version"`
	PurlIdentifier       string                 `yaml:"purl_identifier"`
	UsedFunctions        int                    `yaml:"used_functions"`
	CalledFunctionsCount int                    `yaml:"called_functions_count"`
	CalledFunctions      []ExpectedFunctionCall `yaml:"called_functions"`
}

type ExpectedFunctionCall struct {
	FunctionName     string `yaml:"function_name"`
	CallContext      string `yaml:"call_context"`
	CallSitesContain string `yaml:"call_sites_contain"`
}

type ExpectedFunction struct {
	Name                 string   `yaml:"name"`
	HasExternalCalls     bool     `yaml:"has_external_calls"`
	StdlibCallsContain   []string `yaml:"stdlib_calls_contain"`
	ExternalCallsContain []string `yaml:"external_calls_contain"`
	HasReflectionAccess  bool     `yaml:"has_reflection_access"`
}

type ExpectedSecurityInfo struct {
	ReflectionCallsCount      int `yaml:"reflection_calls_count"`
	ExternalDependenciesCount int `yaml:"external_dependencies_count"`
	TotalFunctionsCount       int `yaml:"total_functions_count"`
	UserFunctionsCount        int `yaml:"user_functions_count"`
}

type ExpectedDependencyCluster struct {
	Name               string                    `yaml:"name"`
	MinEntryPoints     int                       `yaml:"min_entry_points"`
	MinBlastRadius     int                       `yaml:"min_blast_radius"`
	EntryPointsContain []ExpectedDependencyEntry `yaml:"entry_points_contain"`
}

type ExpectedDependencyEntry struct {
	Function           string   `yaml:"function"`
	CalledFromContains []string `yaml:"called_from_contains"`
}

type Assertion struct {
	Type            string `yaml:"type"`
	Name            string `yaml:"name"`
	Dependency      string `yaml:"dependency"`
	Function        string `yaml:"function"`
	ExpectedContext string `yaml:"expected_context"`
	ExpectedVersion string `yaml:"expected_version"`
	ExpectedPurl    string `yaml:"expected_purl"`
	MinCount        int    `yaml:"min_count"`
	Caller          string `yaml:"caller"`
	Callee          string `yaml:"callee"`
	StdlibCall      string `yaml:"stdlib_call"`
}

// FBOM structure (simplified for testing)
type FBOM struct {
	Functions          []Function          `json:"functions"`
	Dependencies       []Dependency        `json:"dependencies"`
	DependencyClusters []DependencyCluster `json:"dependency_clusters"`
	EntryPoints        []EntryPoint        `json:"entry_points"`
	SecurityInfo       struct {
		ReflectionCallsCount      int `json:"reflection_calls_count"`
		TotalCVEsFound            int `json:"total_cves_found"`
		TotalExternalDependencies int `json:"total_external_dependencies"`
	} `json:"security_info"`
}

type Function struct {
	Name      string `json:"name"`
	FullName  string `json:"full_name"`
	Package   string `json:"package"`
	UsageInfo struct {
		Calls               []string `json:"calls"`
		ExternalCalls       []string `json:"external_calls"`
		StdlibCalls         []string `json:"stdlib_calls"`
		HasReflectionAccess bool     `json:"has_reflection_access"`
	} `json:"usage_info"`
}

type Dependency struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	PurlIdentifier  string                 `json:"purl_identifier"`
	UsedFunctions   int                    `json:"used_functions"`
	CalledFunctions []ExternalFunctionCall `json:"called_functions"`
	FBOMReference   *FBOMReference         `json:"fbom_reference"`
}

type ExternalFunctionCall struct {
	FunctionName     string   `json:"function_name"`
	CallContext      string   `json:"call_context"`
	CallSites        []string `json:"call_sites"`
	FullFunctionName string   `json:"full_function_name"`
}

type FBOMReference struct {
	FBOMLocation   string `json:"fbom_location"`
	FBOMVersion    string `json:"fbom_version"`
	ResolutionType string `json:"resolution_type"`
	ChecksumSHA256 string `json:"checksum_sha256,omitempty"`
	LastVerified   string `json:"last_verified,omitempty"`
	SPDXDocumentId string `json:"spdx_document_id"`
}

// DependencyCluster represents a cluster of dependency functions for attack surface analysis
type DependencyCluster struct {
	Name             string            `json:"name"`
	EntryPoints      []DependencyEntry `json:"entry_points"`
	ClusterFunctions []string          `json:"cluster_functions"`
	TotalBlastRadius int               `json:"total_blast_radius"`
}

// DependencyEntry represents an entry point into a dependency cluster
type DependencyEntry struct {
	Function   string   `json:"function"`
	CalledFrom []string `json:"called_from"`
}

type EntryPoint struct {
	Name               string `json:"name"`
	Type               string `json:"type"`
	Package            string `json:"package"`
	ReachableFunctions int    `json:"reachable_functions"`
}
