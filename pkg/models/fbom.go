package models

// FBOM represents a complete Function Bill of Materials
type FBOM struct {
	FBOMVersion        string              `json:"fbom_version"`
	SPDXId             string              `json:"spdx_id"`
	CreationInfo       CreationInfo        `json:"creation_info"`
	PackageInfo        PackageInfo         `json:"package_info"`
	Functions          []Function          `json:"functions"`
	CallGraph          CallGraphInfo       `json:"call_graph"`
	EntryPoints        []EntryPoint        `json:"entry_points"`
	Dependencies       []Dependency        `json:"dependencies"`
	DependencyClusters []DependencyCluster `json:"dependency_clusters"`
	ReflectionAnalysis ReflectionAnalysis  `json:"reflection_analysis"`
	SecurityInfo       SecurityInfo        `json:"security_info"`
}

// CreationInfo contains metadata about FBOM generation
type CreationInfo struct {
	Created       string   `json:"created"`
	CreatedBy     string   `json:"created_by"`
	ToolName      string   `json:"tool_name"`
	ToolVersion   string   `json:"tool_version"`
	Creators      []string `json:"creators"`
	LicenseListID string   `json:"license_list_id"`
}

// PackageInfo describes the analyzed package
type PackageInfo struct {
	Name       string `json:"name"`
	SPDXId     string `json:"spdx_id"`
	SourceInfo string `json:"source_info"`
}

// ExternalFBOMReference represents a reference to an external FBOM
type ExternalFBOMReference struct {
	SerialNumber string `json:"serial_number"`
	URL          string `json:"url,omitempty"`
	Hash         string `json:"hash,omitempty"`
}
