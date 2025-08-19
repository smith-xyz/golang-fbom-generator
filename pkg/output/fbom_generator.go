package output

import (
	"encoding/json"
	"fmt"
	"go/types"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis"
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
)

// FBOMGenerator handles FBOM generation for user applications
type FBOMGenerator struct {
	logger                *slog.Logger
	verbose               bool
	config                *config.Config
	contextAwareConfig    *config.ContextAwareConfig
	additionalEntryPoints []string
	generatedFBOM         *FBOM // Store the last generated FBOM
}

// NewFBOMGenerator creates a new FBOM generator
func NewFBOMGenerator(verbose bool) *FBOMGenerator {
	// Create logger that outputs to stderr to avoid contaminating JSON output
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			if verbose {
				return slog.LevelDebug
			}
			return slog.LevelInfo
		}(),
	}))

	cfg, err := config.DefaultConfig()
	if err != nil {
		// Fallback to a basic config if default config fails to load
		cfg = &config.Config{}
	}

	// Try to detect root package for context-aware configuration
	var contextAwareConfig *config.ContextAwareConfig
	rootPackage, err := utils.GetCurrentGoModule()
	if err != nil {
		if verbose {
			logger.Debug("Failed to detect root package, using non-context-aware config", "error", err)
		}
		// Fall back to non-context-aware config (original behavior)
		contextAwareConfig = nil
	} else {
		contextAwareConfig, err = config.NewContextAwareConfig(rootPackage)
		if err != nil {
			if verbose {
				logger.Debug("Failed to create context-aware config, using non-context-aware config", "error", err)
			}
			contextAwareConfig = nil
		} else if verbose {
			logger.Debug("Using context-aware config", "rootPackage", rootPackage)
		}
	}

	return &FBOMGenerator{
		logger:                logger,
		verbose:               verbose,
		config:                cfg,
		contextAwareConfig:    contextAwareConfig,
		additionalEntryPoints: make([]string, 0),
	}
}

// SetAdditionalEntryPoints configures additional entry point patterns beyond main and init
func (g *FBOMGenerator) SetAdditionalEntryPoints(entryPoints []string) error {
	if entryPoints == nil {
		g.additionalEntryPoints = make([]string, 0)
		return nil
	}

	// Validate and store the entry point patterns
	g.additionalEntryPoints = utils.TrimSpaceSlice(entryPoints)
	g.logger.Debug("Set additional entry points", "patterns", g.additionalEntryPoints)
	return nil
}

// Generate produces FBOM output for user applications only
func (g *FBOMGenerator) Generate(assessments []analysis.Assessment, reflectionUsage map[string]*reflection.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program, mainPackageName string) error {
	g.logger.Debug("Generate function called")

	fbom := g.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, mainPackageName)

	// Store the generated FBOM for later access
	g.generatedFBOM = &fbom

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(fbom)
}

// GetFBOM returns the last generated FBOM
func (g *FBOMGenerator) GetFBOM() *FBOM {
	return g.generatedFBOM
}

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

// Dependency represents a dependency package
type Dependency struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Type            string                 `json:"type"`
	SPDXId          string                 `json:"spdx_id"`
	PackageManager  string                 `json:"package_manager"`
	PurlIdentifier  string                 `json:"purl_identifier"`
	UsedFunctions   int                    `json:"used_functions"`
	FBOMReference   *ExternalFBOMReference `json:"fbom_reference,omitempty"`
	CalledFunctions []ExternalFunctionCall `json:"called_functions,omitempty"`
}

// ExternalFBOMReference represents a reference to an external FBOM
type ExternalFBOMReference struct {
	FBOMLocation   string `json:"fbom_location"`   // URL, file path, or registry reference
	FBOMVersion    string `json:"fbom_version"`    // Version of the external FBOM
	ResolutionType string `json:"resolution_type"` // "url", "file", "registry", "computed"
	ChecksumSHA256 string `json:"checksum_sha256,omitempty"`
	LastVerified   string `json:"last_verified,omitempty"`
	SPDXDocumentId string `json:"spdx_document_id"` // Reference to external SPDX document
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

// ExternalFunctionCall represents a call to an external dependency function
type ExternalFunctionCall struct {
	FunctionName     string   `json:"function_name"`      // e.g., "x"
	FullFunctionName string   `json:"full_function_name"` // e.g., "github.com/pkg/a.x"
	CallSites        []string `json:"call_sites"`         // List of user functions that call this
	CallCount        int      `json:"call_count"`         // Number of times called
	CallContext      string   `json:"call_context"`       // "direct", "reflection", "interface", "callback"
}

// SecurityInfo contains security-relevant information
type SecurityInfo struct {
	VulnerableFunctions        []VulnerableFunction `json:"vulnerable_functions"`
	SecurityHotspots           []SecurityHotspot    `json:"security_hotspots"`
	CriticalPaths              []CriticalPath       `json:"critical_paths"`
	UnreachableVulnerabilities []string             `json:"unreachable_vulnerabilities"`
	ReflectionCallsCount       int                  `json:"reflection_calls_count"`
	TotalCVEsFound             int                  `json:"total_cves_found"`
	TotalReachableCVEs         int                  `json:"total_reachable_cves"`
}

// VulnerableFunction represents a function with known CVEs
type VulnerableFunction struct {
	FunctionId        string   `json:"function_id"`
	CVEs              []string `json:"cves"`
	IsReachable       bool     `json:"is_reachable"`
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

// buildFBOM constructs the complete FBOM structure
func (g *FBOMGenerator) buildFBOM(assessments []analysis.Assessment, reflectionUsage map[string]*reflection.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program, mainPackageName string) FBOM {
	g.logger.Debug("buildFBOM function called")

	// Extract packages and build function inventory
	packages := g.extractAllPackages(ssaProgram)
	allFunctions := g.buildUserFunctionInventory(reflectionUsage, callGraph, ssaProgram)
	callGraphInfo := g.buildCallGraphInfo(callGraph, allFunctions)
	entryPoints := g.buildEntryPoints(callGraph)

	// Build security information
	securityInfo := g.buildSecurityInfo(assessments, reflectionUsage)

	// Get the actual module name instead of using mainPackageName
	actualModuleName := g.extractMainModuleName(ssaProgram, mainPackageName)

	// Build dependency clusters for attack surface analysis
	dependencyClusters := g.buildDependencyClusters(callGraph, allFunctions)

	return FBOM{
		FBOMVersion: "0.1.0",
		SPDXId:      "SPDXRef-FBOM-ROOT",
		CreationInfo: CreationInfo{
			Created:       strconv.FormatInt(time.Now().Unix(), 10),
			CreatedBy:     "golang-fbom-generator Function Bill of Materials Generator",
			ToolName:      "golang-fbom-generator",
			ToolVersion:   "v1.0.0-beta", // TODO: get from version package
			Creators:      []string{"Tool: golang-fbom-generator"},
			LicenseListID: "MIT",
		},
		PackageInfo: PackageInfo{
			Name:       actualModuleName,
			SPDXId:     "SPDXRef-Package-" + actualModuleName,
			SourceInfo: "Local Go Package Analysis",
		},
		Functions:          allFunctions,
		CallGraph:          callGraphInfo,
		EntryPoints:        entryPoints,
		Dependencies:       g.extractDependencies(packages, allFunctions, callGraph),
		DependencyClusters: dependencyClusters,
		SecurityInfo:       securityInfo,
	}
}

// extractAllPackages extracts package names from SSA program
func (g *FBOMGenerator) extractAllPackages(ssaProgram *ssa.Program) []string {
	g.logger.Debug("extractAllPackages called")
	var packages []string
	if ssaProgram != nil {
		for _, pkg := range ssaProgram.AllPackages() {
			packages = append(packages, pkg.Pkg.Path())
		}
	}
	g.logger.Debug("extracted packages", "count", len(packages))
	sort.Strings(packages)
	return packages
}

// extractMainModuleName extracts the main module name using Go's module system
func (g *FBOMGenerator) extractMainModuleName(ssaProgram *ssa.Program, fallback string) string {
	// Try to find and parse go.mod using Go's modfile package
	if moduleName := g.findModuleNameFromGoMod(); moduleName != "" {
		return moduleName
	}

	// Fallback: analyze SSA program to find user-defined packages
	if ssaProgram == nil {
		return fallback
	}

	// Look for user-defined packages and extract the module name
	for _, pkg := range ssaProgram.AllPackages() {
		if pkg.Pkg != nil {
			packagePath := pkg.Pkg.Path()
			// Skip standard library and known dependency packages
			if !g.isStandardLibraryPackage(packagePath) && !g.isDependencyPackage(packagePath) {
				// For user packages, return the package path which should be the module name
				return packagePath
			}
		}
	}

	return fallback
}

// findModuleNameFromGoMod uses Go's modfile package to find the module name
func (g *FBOMGenerator) findModuleNameFromGoMod() string {
	// Start from current directory and walk up to find go.mod
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if content, err := os.ReadFile(goModPath); err == nil {
			// Parse go.mod using Go's official parser
			parsed, err := modfile.Parse(goModPath, content, nil)
			if err == nil && parsed.Module != nil {
				return parsed.Module.Mod.Path
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return ""
}

// buildUserFunctionInventory builds inventory of user-defined functions only
func (g *FBOMGenerator) buildUserFunctionInventory(reflectionUsage map[string]*reflection.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program) []Function {
	g.logger.Debug("buildUserFunctionInventory called")
	functionMap := make(map[string]Function)

	if callGraph != nil {
		totalNodes := len(callGraph.Nodes)
		processedNodes := 0
		g.logger.Debug("Processing call graph functions", "total_nodes", totalNodes)
		for fn := range callGraph.Nodes {
			processedNodes++
			if fn == nil {
				continue
			}
			if !g.isUserDefinedFunction(fn) {
				if g.verbose {
					pkg := "unknown"
					if fn.Pkg != nil && fn.Pkg.Pkg != nil {
						pkg = fn.Pkg.Pkg.Path()
					}
					remaining := totalNodes - processedNodes
					g.logger.Debug("Skipping non-user function", "function", fn.Name(), "package", pkg, "processed", processedNodes, "remaining", remaining)
				}
				continue
			}

			// This function passed filtering - include it
			if g.verbose {
				pkg := "unknown"
				if fn.Pkg != nil && fn.Pkg.Pkg != nil {
					pkg = fn.Pkg.Pkg.Path()
				}
				remaining := totalNodes - processedNodes
				g.logger.Debug("Including user function", "function", fn.Name(), "package", pkg, "processed", processedNodes, "remaining", remaining)
			}

			functionID := g.generateFunctionID(fn)
			isReachable := g.isFunctionReachable(fn, callGraph)
			packagePath := "unknown"
			if fn.Pkg != nil {
				packagePath = fn.Pkg.Pkg.Path()
			}

			function := Function{
				SPDXId:       g.generateSPDXId("Function", fn),
				Name:         fn.Name(),
				FullName:     functionID,
				Package:      packagePath,
				FilePath:     g.extractFilePath(fn),
				StartLine:    g.extractStartLine(fn),
				EndLine:      g.extractEndLine(fn),
				Signature:    g.extractFunctionSignature(fn),
				Visibility:   g.inferVisibility(fn),
				FunctionType: g.inferFunctionType(fn),
				IsExported:   g.isFunctionExported(fn),
				Parameters:   g.extractParameters(fn),
				ReturnTypes:  g.extractReturnTypes(fn),
				UsageInfo: UsageInfo{
					IsReachable:         isReachable,
					ReachabilityType:    g.determineReachabilityType(fn, callGraph),
					DistanceFromEntry:   g.calculateDistanceFromEntry(fn, callGraph),
					InCriticalPath:      false,
					HasReflectionAccess: false,
					IsEntryPoint:        g.isEntryPoint(fn),
					CVEReferences:       []string{},
					Calls:               []string{},
					CalledBy:            []string{},
				},
			}

			functionMap[functionID] = function
		}
	}

	g.populateCallRelationships(functionMap, callGraph)

	// Process unreachable functions from SSA program (user-defined packages only)
	if ssaProgram != nil {
		for _, pkg := range ssaProgram.AllPackages() {
			if pkg.Pkg == nil {
				continue
			}

			packagePath := pkg.Pkg.Path()
			if g.isStandardLibraryPackage(packagePath) || g.isDependencyPackage(packagePath) {
				continue
			}

			for _, member := range pkg.Members {
				if fn, ok := member.(*ssa.Function); ok {
					functionID := g.generateFunctionID(fn)

					if _, exists := functionMap[functionID]; exists {
						continue
					}
					function := Function{
						SPDXId:       g.generateSPDXId("Function", fn),
						Name:         fn.Name(),
						FullName:     functionID,
						Package:      packagePath,
						FilePath:     g.extractFilePath(fn),
						StartLine:    g.extractStartLine(fn),
						EndLine:      g.extractEndLine(fn),
						Signature:    g.extractFunctionSignature(fn),
						Visibility:   g.inferVisibility(fn),
						FunctionType: g.inferFunctionType(fn),
						IsExported:   g.isFunctionExported(fn),
						Parameters:   g.extractParameters(fn),
						ReturnTypes:  g.extractReturnTypes(fn),
						UsageInfo: UsageInfo{
							IsReachable:         false, // Unreachable since not in call graph
							ReachabilityType:    "unreachable",
							DistanceFromEntry:   -1, // Unreachable
							InCriticalPath:      false,
							HasReflectionAccess: false,
							IsEntryPoint:        false,
							CVEReferences:       []string{},
							Calls:               []string{},
							CalledBy:            []string{},
						},
					}

					functionMap[functionID] = function
				}

				if typ, ok := member.(*ssa.Type); ok {
					g.processMethods(typ, packagePath, functionMap, callGraph, ssaProgram)
				}
			}
		}
	}

	g.populateCallRelationships(functionMap, callGraph)

	// Debug: log reflection usage information
	if g.verbose {
		g.logger.Debug("Reflection usage mapping", "reflection_functions_count", len(reflectionUsage))
		for funcId, usage := range reflectionUsage {
			g.logger.Debug("Reflection function", "id", funcId, "uses_reflection", usage.UsesReflection, "risk", usage.ReflectionRisk)
		}

		g.logger.Debug("User function mapping", "user_functions_count", len(functionMap))
		// Show test-project functions specifically
		count := 0
		for funcId := range functionMap {
			if strings.Contains(funcId, "test-project") {
				g.logger.Debug("Test-project function", "id", funcId)
				count++
			}
		}
		g.logger.Debug("Found test-project functions", "count", count)
	}

	for funcId, usage := range reflectionUsage {
		if function, exists := functionMap[funcId]; exists {
			function.UsageInfo.HasReflectionAccess = g.hasReflectionRisk(usage)
			functionMap[funcId] = function
			if g.verbose {
				g.logger.Debug("Applied reflection access", "function", funcId, "has_reflection_access", function.UsageInfo.HasReflectionAccess)
			}
		} else if g.verbose {
			g.logger.Debug("Reflection function not found in user functions", "reflection_function", funcId)
		}
	}

	// Convert map to slice
	functions := make([]Function, 0, len(functionMap))
	for _, function := range functionMap {
		functions = append(functions, function)
	}

	g.logger.Info("buildUserFunctionInventory completed", "count", len(functions))
	return functions
}

// processMethods processes all methods of a given type and adds them to the function map
func (g *FBOMGenerator) processMethods(typ *ssa.Type, packagePath string, functionMap map[string]Function, callGraph *callgraph.Graph, ssaProgram *ssa.Program) {
	if typ == nil || typ.Type() == nil {
		return
	}

	// Get the method set for this type (both value and pointer receivers)
	methodSet := ssaProgram.MethodSets.MethodSet(typ.Type())
	if methodSet != nil {
		for i := 0; i < methodSet.Len(); i++ {
			selection := methodSet.At(i)

			// Get the method function from the SSA program
			methodFunc := ssaProgram.MethodValue(selection)
			if methodFunc == nil {
				continue
			}

			// Only process user-defined methods (skip if from other packages)
			if !g.isUserDefinedFunction(methodFunc) {
				continue
			}

			functionID := g.generateFunctionID(methodFunc)

			// Skip if we already processed this method from call graph
			if _, exists := functionMap[functionID]; exists {
				continue
			}

			// Check if this method is reachable via the call graph
			isReachable := g.isFunctionReachable(methodFunc, callGraph)

			function := Function{
				SPDXId:       g.generateSPDXId("Function", methodFunc),
				Name:         methodFunc.Name(),
				FullName:     functionID,
				Package:      packagePath,
				FilePath:     g.extractFilePath(methodFunc),
				StartLine:    g.extractStartLine(methodFunc),
				EndLine:      g.extractEndLine(methodFunc),
				Signature:    g.extractFunctionSignature(methodFunc),
				Visibility:   g.inferVisibility(methodFunc),
				FunctionType: g.inferFunctionType(methodFunc),
				IsExported:   g.isFunctionExported(methodFunc),
				Parameters:   g.extractParameters(methodFunc),
				ReturnTypes:  g.extractReturnTypes(methodFunc),
				UsageInfo: UsageInfo{
					IsReachable:         isReachable,
					ReachabilityType:    g.determineReachabilityType(methodFunc, callGraph),
					DistanceFromEntry:   g.calculateDistanceFromEntry(methodFunc, callGraph),
					InCriticalPath:      false,
					HasReflectionAccess: false,
					IsEntryPoint:        g.isEntryPoint(methodFunc),
					CVEReferences:       []string{},
					Calls:               []string{},
					CalledBy:            []string{},
				},
			}

			functionMap[functionID] = function
		}
	}

	// Also check pointer type methods if this is not already a pointer type
	if !isPointer(typ.Type()) {
		ptrType := types.NewPointer(typ.Type())
		ptrMethodSet := ssaProgram.MethodSets.MethodSet(ptrType)
		if ptrMethodSet != nil {
			for i := 0; i < ptrMethodSet.Len(); i++ {
				selection := ptrMethodSet.At(i)

				// Get the method function from the SSA program
				methodFunc := ssaProgram.MethodValue(selection)
				if methodFunc == nil {
					continue
				}

				// Only process user-defined methods
				if !g.isUserDefinedFunction(methodFunc) {
					continue
				}

				functionID := g.generateFunctionID(methodFunc)

				// Skip if we already processed this method
				if _, exists := functionMap[functionID]; exists {
					continue
				}

				// Check if this method is reachable via the call graph
				isReachable := g.isFunctionReachable(methodFunc, callGraph)

				function := Function{
					SPDXId:       g.generateSPDXId("Function", methodFunc),
					Name:         methodFunc.Name(),
					FullName:     functionID,
					Package:      packagePath,
					FilePath:     g.extractFilePath(methodFunc),
					StartLine:    g.extractStartLine(methodFunc),
					EndLine:      g.extractEndLine(methodFunc),
					Signature:    g.extractFunctionSignature(methodFunc),
					Visibility:   g.inferVisibility(methodFunc),
					FunctionType: g.inferFunctionType(methodFunc),
					IsExported:   g.isFunctionExported(methodFunc),
					Parameters:   g.extractParameters(methodFunc),
					ReturnTypes:  g.extractReturnTypes(methodFunc),
					UsageInfo: UsageInfo{
						IsReachable:         isReachable,
						ReachabilityType:    g.determineReachabilityType(methodFunc, callGraph),
						DistanceFromEntry:   g.calculateDistanceFromEntry(methodFunc, callGraph),
						InCriticalPath:      false,
						HasReflectionAccess: false,
						IsEntryPoint:        g.isEntryPoint(methodFunc),
						CVEReferences:       []string{},
						Calls:               []string{}, // Initialize as empty slice
						CalledBy:            []string{}, // Initialize as empty slice
					},
				}

				functionMap[functionID] = function
			}
		}
	}
}

// isPointer checks if a type is a pointer type
func isPointer(t types.Type) bool {
	_, ok := t.(*types.Pointer)
	return ok
}

// isUserDefinedFunction determines if a function should be included (user-defined only)
func (g *FBOMGenerator) isUserDefinedFunction(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}

	packagePath := fn.Pkg.Pkg.Path()

	// Use context-aware package classification if available
	if g.contextAwareConfig != nil {
		return g.contextAwareConfig.IsUserDefined(packagePath)
	}

	// Fallback to original behavior for backward compatibility
	// Exclude standard library packages
	if g.isStandardLibraryPackage(packagePath) {
		return false
	}

	// Exclude known third-party dependencies
	if g.isDependencyPackage(packagePath) {
		return false
	}

	// Include everything else (user-defined code)
	return true
}

// isStandardLibraryPackage checks if a package is part of Go's standard library
func (g *FBOMGenerator) isStandardLibraryPackage(packagePath string) bool {
	// Use context-aware config if available, otherwise fall back to base config
	if g.contextAwareConfig != nil {
		return g.contextAwareConfig.IsStandardLibrary(packagePath)
	}
	return g.config.IsStandardLibrary(packagePath)
}

// isDependencyPackage checks if a package is a third-party dependency.
func (g *FBOMGenerator) isDependencyPackage(packagePath string) bool {
	// Use context-aware config if available, otherwise fall back to base config
	if g.contextAwareConfig != nil {
		return g.contextAwareConfig.IsDependency(packagePath)
	}
	return g.config.IsDependency(packagePath)
}

// isUserDefinedPackage checks if a package is user-defined.
func (g *FBOMGenerator) isUserDefinedPackage(packagePath string) bool {
	// Use context-aware config if available, otherwise fall back to base config
	if g.contextAwareConfig != nil {
		return g.contextAwareConfig.IsUserDefined(packagePath)
	}
	return g.config.IsUserDefined(packagePath)
}

func (g *FBOMGenerator) generateFunctionID(fn *ssa.Function) string {
	if fn.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Path(), fn.Name())
	}
	return fn.Name()
}

func (g *FBOMGenerator) generateSPDXId(prefix string, fn *ssa.Function) string {
	return fmt.Sprintf("SPDXRef-%s-%s", prefix, fn.Name())
}

func (g *FBOMGenerator) isFunctionReachable(fn *ssa.Function, callGraph *callgraph.Graph) bool {
	if callGraph == nil {
		return g.isEntryPoint(fn)
	}

	node := callGraph.Nodes[fn]
	if node == nil {
		return false
	}

	// If it's an entry point, it's reachable
	if g.isEntryPoint(fn) {
		return true
	}

	// If it has incoming edges, it's reachable
	return len(node.In) > 0
}

// matchesEntryPointPattern checks if a function name matches any of the entry point patterns
func (g *FBOMGenerator) matchesEntryPointPattern(functionName string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchesPattern(functionName, pattern) {
			return true
		}
	}
	return false
}

// matchesPattern checks if a string matches a pattern with basic wildcard support
func matchesPattern(str, pattern string) bool {
	// Handle exact matches
	if str == pattern {
		return true
	}

	// Handle simple wildcard patterns
	if strings.Contains(pattern, "*") {
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			// Pattern like "*User*" - contains match
			middle := pattern[1 : len(pattern)-1]
			return strings.Contains(str, middle)
		} else if strings.HasPrefix(pattern, "*") {
			// Pattern like "*User" - suffix match
			suffix := pattern[1:]
			return strings.HasSuffix(str, suffix)
		} else if strings.HasSuffix(pattern, "*") {
			// Pattern like "Get*" - prefix match
			prefix := pattern[:len(pattern)-1]
			return strings.HasPrefix(str, prefix)
		}
	}

	return false
}

func (g *FBOMGenerator) isEntryPoint(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}

	// Main function is always an entry point
	if fn.Name() == "main" && fn.Pkg != nil && fn.Pkg.Pkg.Name() == "main" {
		return true
	}

	// Init functions are entry points
	if fn.Name() == "init" {
		return true
	}

	// Check if the function matches any additional entry point patterns
	if len(g.additionalEntryPoints) > 0 {
		functionName := fn.Name()
		if g.matchesEntryPointPattern(functionName, g.additionalEntryPoints) {
			g.logger.Debug("Function matches additional entry point pattern", "function", functionName, "patterns", g.additionalEntryPoints)
			return true
		}
	}

	// For application analysis (not library analysis), only main and init should be entry points by default
	// Exported functions in packages are NOT entry points for applications unless explicitly specified
	// Note: This is appropriate for application FBOM analysis where we want to trace from main/init
	// For library analysis, this logic would need to be different

	return false
}

// Simple implementations for basic functionality
func (g *FBOMGenerator) extractFilePath(fn *ssa.Function) string {
	if fn.Prog != nil && fn.Prog.Fset != nil && fn.Pos().IsValid() {
		pos := fn.Prog.Fset.Position(fn.Pos())
		return pos.Filename
	}
	return "unknown"
}

func (g *FBOMGenerator) extractStartLine(fn *ssa.Function) int {
	if fn.Prog != nil && fn.Prog.Fset != nil && fn.Pos().IsValid() {
		pos := fn.Prog.Fset.Position(fn.Pos())
		return pos.Line
	}
	return 0
}

func (g *FBOMGenerator) extractEndLine(fn *ssa.Function) int {
	// For simplicity, return start line + estimated length
	return g.extractStartLine(fn) + 10
}

func (g *FBOMGenerator) extractFunctionSignature(fn *ssa.Function) string {
	if fn.Signature != nil {
		return fn.Signature.String()
	}
	return "unknown"
}

func (g *FBOMGenerator) inferVisibility(fn *ssa.Function) string {
	if len(fn.Name()) > 0 && fn.Name()[0] >= 'A' && fn.Name()[0] <= 'Z' {
		return "public"
	}
	return "private"
}

func (g *FBOMGenerator) inferFunctionType(fn *ssa.Function) string {
	name := fn.Name()
	switch {
	case name == "main":
		return "main"
	case name == "init":
		return "init"
	case fn.Parent() != nil:
		return "closure"
	case fn.Signature != nil && fn.Signature.Recv() != nil:
		return "method"
	default:
		return "regular"
	}
}

func (g *FBOMGenerator) isFunctionExported(fn *ssa.Function) bool {
	return len(fn.Name()) > 0 && fn.Name()[0] >= 'A' && fn.Name()[0] <= 'Z'
}

func (g *FBOMGenerator) extractParameters(fn *ssa.Function) []Parameter {
	var params []Parameter
	if fn.Signature != nil && fn.Signature.Params() != nil {
		for i := 0; i < fn.Signature.Params().Len(); i++ {
			param := fn.Signature.Params().At(i)
			params = append(params, Parameter{
				Name: param.Name(),
				Type: param.Type().String(),
			})
		}
	}
	return params
}

func (g *FBOMGenerator) extractReturnTypes(fn *ssa.Function) []string {
	var returns []string
	if fn.Signature != nil && fn.Signature.Results() != nil {
		for i := 0; i < fn.Signature.Results().Len(); i++ {
			result := fn.Signature.Results().At(i)
			returns = append(returns, result.Type().String())
		}
	}
	return returns
}

func (g *FBOMGenerator) determineReachabilityType(fn *ssa.Function, callGraph *callgraph.Graph) string {
	if g.isEntryPoint(fn) {
		return "direct"
	}

	// Check if function is called directly by an entry point
	if callGraph != nil {
		fnNode := callGraph.Nodes[fn]
		if fnNode != nil {
			for _, edge := range fnNode.In {
				if g.isEntryPoint(edge.Caller.Func) {
					return "direct"
				}
			}
		}
	}

	return "transitive"
}

// determineCallType determines if a call is "direct" or "transitive" based on the callee's distance from entry points
func (g *FBOMGenerator) determineCallType(callee *ssa.Function, allFunctions []Function) string {
	calleeID := g.generateFunctionID(callee)

	// Find the callee function in our function list to get its reachability type
	for _, fn := range allFunctions {
		if fn.FullName == calleeID {
			// If the callee has "transitive" reachability, then this call is transitive
			if fn.UsageInfo.ReachabilityType == "transitive" {
				return "transitive"
			}
			// Otherwise, it's a direct call
			return "direct"
		}
	}

	// Default to direct if we can't determine
	return "direct"
}

// extractCallSiteInfo extracts file path and line number from a call graph edge
func (g *FBOMGenerator) extractCallSiteInfo(edge *callgraph.Edge) (string, int) {
	if edge == nil || edge.Site == nil {
		return "", 0
	}

	// Get the position information from the call site instruction
	pos := edge.Site.Pos()
	if !pos.IsValid() {
		return "", 0
	}

	// Get the file set from the caller function to resolve position
	if edge.Caller != nil && edge.Caller.Func != nil &&
		edge.Caller.Func.Prog != nil && edge.Caller.Func.Prog.Fset != nil {
		position := edge.Caller.Func.Prog.Fset.Position(pos)
		return position.Filename, position.Line
	}

	return "", 0
}

func (g *FBOMGenerator) calculateDistanceFromEntry(fn *ssa.Function, callGraph *callgraph.Graph) int {
	if fn == nil {
		return -1
	}

	if g.isEntryPoint(fn) {
		return 0
	}

	if callGraph == nil {
		return -1
	}

	// Use the same logic as calculateDepthMetrics to find minimum distance
	functionID := g.generateFunctionID(fn)

	// Find all entry points
	entryPoints := make([]*ssa.Function, 0)
	for entryFn := range callGraph.Nodes {
		if g.isEntryPoint(entryFn) && g.isUserDefinedFunction(entryFn) {
			entryPoints = append(entryPoints, entryFn)
		}
	}

	minDistance := -1 // -1 means unreachable

	for _, entryPoint := range entryPoints {
		depths := make(map[string]int)
		g.calculateFunctionDepths(callGraph, entryPoint, 0, depths)

		if distance, found := depths[functionID]; found {
			if minDistance == -1 || distance < minDistance {
				minDistance = distance
			}
		}
	}

	return minDistance
}

func (g *FBOMGenerator) hasReflectionRisk(usage *reflection.Usage) bool {
	if usage == nil {
		return false
	}
	return usage.ReflectionRisk == reflection.RiskMedium || usage.ReflectionRisk == reflection.RiskHigh
}

func (g *FBOMGenerator) populateCallRelationships(functionMap map[string]Function, callGraph *callgraph.Graph) {
	// Initialize all functions with empty slices first
	for functionID, function := range functionMap {
		if function.UsageInfo.Calls == nil {
			function.UsageInfo.Calls = []string{}
		}
		if function.UsageInfo.ExternalCalls == nil {
			function.UsageInfo.ExternalCalls = []string{}
		}
		if function.UsageInfo.StdlibCalls == nil {
			function.UsageInfo.StdlibCalls = []string{}
		}
		if function.UsageInfo.CalledBy == nil {
			function.UsageInfo.CalledBy = []string{}
		}
		functionMap[functionID] = function
	}

	// Populate call relationships from call graph
	if callGraph == nil {
		return
	}

	for fn, node := range callGraph.Nodes {
		if !g.isUserDefinedFunction(fn) {
			continue
		}

		callerID := g.generateFunctionID(fn)
		if callerFunc, exists := functionMap[callerID]; exists {
			// Initialize with empty slices (not nil slices)
			calls := []string{}
			externalCalls := []string{}
			stdlibCalls := []string{}
			calledBy := []string{}

			// Outgoing edges (calls)
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					calleeFunc := edge.Callee.Func
					calleeID := g.generateFunctionID(calleeFunc)

					if g.isUserDefinedFunction(calleeFunc) {
						// User-defined function call
						calls = append(calls, calleeID)
					} else {
						// External or stdlib function call
						packagePath := ""
						if calleeFunc.Pkg != nil && calleeFunc.Pkg.Pkg != nil {
							packagePath = calleeFunc.Pkg.Pkg.Path()
						}

						if g.isStandardLibraryPackage(packagePath) {
							// Standard library call
							stdlibCall := g.formatStdlibCall(calleeFunc)
							stdlibCalls = append(stdlibCalls, stdlibCall)
						} else if g.isDependencyPackage(packagePath) {
							// External dependency call
							externalCall := g.formatExternalCall(calleeFunc)
							externalCalls = append(externalCalls, externalCall)
						}
					}
				}
			}

			// Incoming edges (called by) - only from user-defined functions
			for _, edge := range node.In {
				if edge.Caller != nil && edge.Caller.Func != nil && g.isUserDefinedFunction(edge.Caller.Func) {
					callerIDIn := g.generateFunctionID(edge.Caller.Func)
					calledBy = append(calledBy, callerIDIn)
				}
			}

			callerFunc.UsageInfo.Calls = calls
			callerFunc.UsageInfo.ExternalCalls = externalCalls
			callerFunc.UsageInfo.StdlibCalls = stdlibCalls
			callerFunc.UsageInfo.CalledBy = calledBy
			functionMap[callerID] = callerFunc
		}
	}
}

// formatStdlibCall formats a standard library function call for tracking
func (g *FBOMGenerator) formatStdlibCall(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		packagePath := fn.Pkg.Pkg.Path()
		return fmt.Sprintf("%s.%s", packagePath, fn.Name())
	}
	return fn.Name()
}

// formatExternalCall formats an external dependency function call for tracking
func (g *FBOMGenerator) formatExternalCall(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		packagePath := fn.Pkg.Pkg.Path()
		return fmt.Sprintf("%s.%s", packagePath, fn.Name())
	}
	return fn.Name()
}

// Simplified implementations for remaining required methods
func (g *FBOMGenerator) buildCallGraphInfo(callGraph *callgraph.Graph, allFunctions []Function) CallGraphInfo {
	var userEdges []CallEdge
	userNodeCount := 0

	// Count functions in call graph (reachable ones)
	if callGraph != nil {
		for fn, node := range callGraph.Nodes {
			if !g.isUserDefinedFunction(fn) {
				continue
			}
			userNodeCount++

			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					calleeFunc := edge.Callee.Func
					filePath, lineNumber := g.extractCallSiteInfo(edge)
					callerID := g.generateFunctionID(fn)

					if g.isUserDefinedFunction(calleeFunc) {
						// User-to-user call
						callType := g.determineCallType(calleeFunc, allFunctions)
						userEdges = append(userEdges, CallEdge{
							Caller:     callerID,
							Callee:     g.generateFunctionID(calleeFunc),
							CallType:   callType,
							FilePath:   filePath,
							LineNumber: lineNumber,
						})
					} else {
						// User-to-external or user-to-stdlib call
						packagePath := ""
						if calleeFunc.Pkg != nil && calleeFunc.Pkg.Pkg != nil {
							packagePath = calleeFunc.Pkg.Pkg.Path()
						}

						var callType string
						var calleeID string

						if g.isStandardLibraryPackage(packagePath) {
							callType = "stdlib"
							calleeID = g.formatStdlibCall(calleeFunc)
						} else if g.isDependencyPackage(packagePath) {
							callType = "external"
							calleeID = g.formatExternalCall(calleeFunc)
						} else {
							// Unknown package type, skip
							continue
						}

						userEdges = append(userEdges, CallEdge{
							Caller:     callerID,
							Callee:     calleeID,
							CallType:   callType,
							FilePath:   filePath,
							LineNumber: lineNumber,
						})
					}
				}
			}
		}
	}

	// Count total functions, used functions, and unused functions
	totalFunctions := len(allFunctions)
	usedFunctions := 0
	for _, fn := range allFunctions {
		if fn.UsageInfo.IsReachable {
			usedFunctions++
		}
	}
	unusedFunctions := totalFunctions - usedFunctions

	// Calculate actual reachable functions from entry points
	reachableFunctions := g.calculateReachableFunctions(callGraph)

	// Calculate actual depth metrics
	maxDepth, avgDepth := g.calculateDepthMetrics(callGraph)

	return CallGraphInfo{
		TotalFunctions:     totalFunctions,
		UsedFunctions:      usedFunctions,
		UnusedFunctions:    unusedFunctions,
		TotalEdges:         len(userEdges),
		MaxDepth:           maxDepth,
		AvgDepth:           avgDepth,
		CallEdges:          userEdges,
		ReachableFunctions: reachableFunctions,
	}
}

// calculateReachableFunctions calculates the number of functions reachable from entry points
func (g *FBOMGenerator) calculateReachableFunctions(callGraph *callgraph.Graph) int {
	if callGraph == nil {
		return 0
	}

	reachableSet := make(map[string]bool)

	// Find all entry points
	entryPoints := make([]*ssa.Function, 0)
	for fn := range callGraph.Nodes {
		if g.isEntryPoint(fn) && g.isUserDefinedFunction(fn) {
			entryPoints = append(entryPoints, fn)
		}
	}

	// Traverse from each entry point to find all reachable functions
	for _, entryPoint := range entryPoints {
		g.markReachableFunctions(callGraph, entryPoint, reachableSet)
	}

	return len(reachableSet)
}

// calculateDepthMetrics calculates max depth and average depth from entry points
func (g *FBOMGenerator) calculateDepthMetrics(callGraph *callgraph.Graph) (int, float64) {
	if callGraph == nil {
		return 0, 0.0
	}

	// Find all entry points
	entryPoints := make([]*ssa.Function, 0)
	for fn := range callGraph.Nodes {
		if g.isEntryPoint(fn) && g.isUserDefinedFunction(fn) {
			entryPoints = append(entryPoints, fn)
		}
	}

	if len(entryPoints) == 0 {
		return 0, 0.0
	}

	// Calculate depths for all reachable functions
	allDepths := make(map[string]int)

	for _, entryPoint := range entryPoints {
		depths := make(map[string]int)
		g.calculateFunctionDepths(callGraph, entryPoint, 0, depths)

		// Merge depths, taking minimum depth for each function (closest path)
		for funcID, depth := range depths {
			if existingDepth, exists := allDepths[funcID]; !exists || depth < existingDepth {
				allDepths[funcID] = depth
			}
		}
	}

	if len(allDepths) == 0 {
		return 0, 0.0
	}

	// Calculate max and average depth
	maxDepth := 0
	totalDepth := 0

	for _, depth := range allDepths {
		if depth > maxDepth {
			maxDepth = depth
		}
		totalDepth += depth
	}

	avgDepth := float64(totalDepth) / float64(len(allDepths))
	return maxDepth, avgDepth
}

// calculateFunctionDepths performs DFS to calculate depths from an entry point
func (g *FBOMGenerator) calculateFunctionDepths(callGraph *callgraph.Graph, fn *ssa.Function, currentDepth int, depths map[string]int) {
	if fn == nil || !g.isUserDefinedFunction(fn) {
		return
	}

	functionID := g.generateFunctionID(fn)

	// If we've seen this function at a shallower depth, don't continue
	if existingDepth, exists := depths[functionID]; exists && existingDepth <= currentDepth {
		return
	}

	depths[functionID] = currentDepth

	// Traverse to all callees with increased depth
	if node := callGraph.Nodes[fn]; node != nil {
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				g.calculateFunctionDepths(callGraph, edge.Callee.Func, currentDepth+1, depths)
			}
		}
	}
}

// markReachableFunctions performs DFS to mark all functions reachable from a given function
func (g *FBOMGenerator) markReachableFunctions(callGraph *callgraph.Graph, fn *ssa.Function, reachableSet map[string]bool) {
	if fn == nil || !g.isUserDefinedFunction(fn) {
		return
	}

	functionID := g.generateFunctionID(fn)
	if reachableSet[functionID] {
		return // Already visited
	}

	reachableSet[functionID] = true

	// Traverse to all callees
	if node := callGraph.Nodes[fn]; node != nil {
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				g.markReachableFunctions(callGraph, edge.Callee.Func, reachableSet)
			}
		}
	}
}

// calculateReachableFromEntryPoint calculates functions reachable from a specific entry point
func (g *FBOMGenerator) calculateReachableFromEntryPoint(callGraph *callgraph.Graph, entryPoint *ssa.Function) int {
	if callGraph == nil || entryPoint == nil {
		return 0
	}

	reachableSet := make(map[string]bool)
	g.markReachableFunctions(callGraph, entryPoint, reachableSet)
	return len(reachableSet)
}

func (g *FBOMGenerator) buildEntryPoints(callGraph *callgraph.Graph) []EntryPoint {
	entryPoints := make([]EntryPoint, 0)

	if callGraph != nil {
		for fn := range callGraph.Nodes {
			if g.isEntryPoint(fn) && g.isUserDefinedFunction(fn) {
				// Calculate reachable functions from this specific entry point
				reachableFromEntry := g.calculateReachableFromEntryPoint(callGraph, fn)

				entryPoints = append(entryPoints, EntryPoint{
					SPDXId:             g.generateSPDXId("EntryPoint", fn),
					Name:               fn.Name(),
					Type:               g.inferEntryPointType(fn),
					Package:            g.inferPackageFromFunction(fn),
					AccessibleFrom:     g.inferAccessibility(fn),
					SecurityLevel:      g.inferSecurityLevel(fn),
					ReachableFunctions: reachableFromEntry,
				})
			}
		}
	}

	return entryPoints
}

func (g *FBOMGenerator) inferEntryPointType(fn *ssa.Function) string {
	switch fn.Name() {
	case "main":
		return "main"
	case "init":
		return "init"
	default:
		if g.isFunctionExported(fn) {
			return "exported"
		}
		return "internal"
	}
}

func (g *FBOMGenerator) inferPackageFromFunction(fn *ssa.Function) string {
	if fn.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	return "unknown"
}

func (g *FBOMGenerator) inferAccessibility(fn *ssa.Function) []string {
	if fn.Name() == "main" {
		return []string{"external"}
	}
	if fn.Name() == "init" {
		return []string{"internal"}
	}
	if g.isFunctionExported(fn) {
		return []string{"external"}
	}
	return []string{"internal"}
}

func (g *FBOMGenerator) inferSecurityLevel(fn *ssa.Function) string {
	if fn.Name() == "init" {
		return "internal"
	}
	if fn.Name() == "main" {
		return "public"
	}
	if g.isFunctionExported(fn) {
		return "public"
	}
	return "internal"
}

func (g *FBOMGenerator) buildSecurityInfo(assessments []analysis.Assessment, reflectionUsage map[string]*reflection.Usage) SecurityInfo {
	vulnerableFunctions := make([]VulnerableFunction, 0)
	unreachableVulnerabilities := make([]string, 0)
	reachableCount := 0

	// Process each CVE assessment
	for _, assessment := range assessments {
		if assessment.ReachabilityStatus == analysis.NotReachable {
			unreachableVulnerabilities = append(unreachableVulnerabilities, assessment.CVE.ID)
		} else {
			reachableCount++

			// Create vulnerable function entries for reachable CVEs
			for _, path := range assessment.CallPaths {
				vulnFunc := VulnerableFunction{
					FunctionId:        path.VulnerableFunc,
					CVEs:              []string{assessment.CVE.ID},
					IsReachable:       true,
					ReachabilityPaths: []string{path.EntryPoint},
					RiskScore:         g.calculateRiskScore(assessment),
					Impact:            strings.ToLower(assessment.CalculatedPriority),
				}
				vulnerableFunctions = append(vulnerableFunctions, vulnFunc)
			}
		}
	}

	return SecurityInfo{
		VulnerableFunctions:        vulnerableFunctions,
		SecurityHotspots:           []SecurityHotspot{},
		CriticalPaths:              []CriticalPath{},
		UnreachableVulnerabilities: unreachableVulnerabilities,
		ReflectionCallsCount:       len(reflectionUsage),
		TotalCVEsFound:             len(assessments),
		TotalReachableCVEs:         reachableCount,
	}
}

// calculateRiskScore calculates a risk score based on the assessment
func (g *FBOMGenerator) calculateRiskScore(assessment analysis.Assessment) float64 {
	baseScore := 5.0 // Default medium risk

	// Adjust based on reachability
	switch assessment.ReachabilityStatus {
	case analysis.DirectlyReachable:
		baseScore += 3.0
	case analysis.TransitivelyReachable:
		baseScore += 1.0
	case analysis.ReflectionPossible:
		baseScore += 0.5
	}

	// Adjust based on distance from entry points
	if assessment.EntryPointDistance > 0 {
		distancePenalty := float64(assessment.EntryPointDistance) * 0.2
		baseScore = baseScore - distancePenalty
	}

	// Ensure score is within 0-10 range
	if baseScore > 10.0 {
		baseScore = 10.0
	}
	if baseScore < 0.0 {
		baseScore = 0.0
	}

	return baseScore
}

func (g *FBOMGenerator) extractDependencies(packages []string, allFunctions []Function, callGraph *callgraph.Graph) []Dependency {
	deps := make([]Dependency, 0)

	// Track which external functions are called by which user functions
	externalCallMap := make(map[string][]ExternalFunctionCall)

	// Analyze function calls to build external call tracking
	for _, userFunc := range allFunctions {
		for _, externalCall := range userFunc.UsageInfo.ExternalCalls {
			packageName := g.extractPackageFromCall(externalCall)
			functionName := g.extractFunctionFromCall(externalCall)

			if packageName != "" && functionName != "" {
				if externalCallMap[packageName] == nil {
					externalCallMap[packageName] = []ExternalFunctionCall{}
				}

				// Check if this function is already tracked
				found := false
				for i := range externalCallMap[packageName] {
					if externalCallMap[packageName][i].FunctionName == functionName {
						// Add to call sites and increment count
						externalCallMap[packageName][i].CallSites = append(externalCallMap[packageName][i].CallSites, userFunc.Name)
						externalCallMap[packageName][i].CallCount++
						found = true
						break
					}
				}

				if !found {
					// Create new external function call entry
					externalCallMap[packageName] = append(externalCallMap[packageName], ExternalFunctionCall{
						FunctionName:     functionName,
						FullFunctionName: externalCall,
						CallSites:        []string{userFunc.Name},
						CallCount:        1,
						CallContext:      g.determineCallContext(userFunc.Name, functionName, callGraph),
					})
				}
			}
		}
	}

	// Build dependencies with enhanced metadata
	for _, pkg := range packages {
		if g.isDependencyPackage(pkg) {
			version := g.extractVersionFromGoMod(pkg)
			dep := Dependency{
				Name:           pkg,
				Version:        g.extractVersionFromGoMod(pkg),
				Type:           "go-module",
				SPDXId:         fmt.Sprintf("SPDXRef-Package-%s", strings.ReplaceAll(pkg, "/", "-")),
				PackageManager: "go",
				PurlIdentifier: g.generatePurlIdentifier(pkg, version),
				UsedFunctions:  0, // Will be calculated after CalledFunctions is set
			}

			if calledFunctions, exists := externalCallMap[pkg]; exists {
				dep.CalledFunctions = calledFunctions
			}

			// Calculate function counts (used and total)
			g.calculateFunctionCounts(&dep)

			deps = append(deps, dep)
		}
	}

	return deps
}

// extractPackageFromCall extracts package name from a formatted call like "github.com/pkg/a.functionName"
func (g *FBOMGenerator) extractPackageFromCall(call string) string {
	lastDot := strings.LastIndex(call, ".")
	if lastDot == -1 {
		return ""
	}
	return call[:lastDot]
}

// extractFunctionFromCall extracts function name from a formatted call like "github.com/pkg/a.functionName"
func (g *FBOMGenerator) extractFunctionFromCall(call string) string {
	lastDot := strings.LastIndex(call, ".")
	if lastDot == -1 {
		return call
	}
	return call[lastDot+1:]
}

// determineCallContext determines the call context (direct, reflection, callback, interface)
func (g *FBOMGenerator) determineCallContext(userFuncName, externalFuncName string, callGraph *callgraph.Graph) string {
	// For now, default to "direct" - in future iterations we can analyze:
	// - Reflection usage patterns
	// - Anonymous functions/closures (callback)
	// - Interface calls
	return "direct"
}

// generateFBOMLocation generates a location reference for an external package's FBOM
func (g *FBOMGenerator) generateFBOMLocation(packageName string) string {
	// Convention-based location - could be made configurable
	// Replace both slashes and dots with hyphens to create valid filenames
	safeName := strings.ReplaceAll(packageName, "/", "-")
	safeName = strings.ReplaceAll(safeName, ".", "-")

	// Use absolute path for consistency and portability
	relativePath := fmt.Sprintf("./fboms/%s.fbom.json", safeName)
	absPath, err := filepath.Abs(relativePath)
	if err != nil {
		g.logger.Debug("Failed to convert placeholder path to absolute", "path", relativePath, "error", err)
		return relativePath // Fallback to relative if absolute conversion fails
	}
	return absPath
}

// determineFBOMResolutionType determines how to resolve the external FBOM
func (g *FBOMGenerator) determineFBOMResolutionType(packageName string) string {
	// For now, default to "file" - could be extended to support:
	// - "registry" for FBOM registries
	// - "url" for HTTP-accessible FBOMs
	// - "computed" for generated FBOMs
	return "file"
}

// extractVersionFromGoMod extracts the version information for a package using go list
func (g *FBOMGenerator) extractVersionFromGoMod(packageName string) string {
	// Get module versions using go list command
	moduleVersions, err := g.getModuleVersions()
	if err != nil {
		g.logger.Debug("Failed to get module versions using go list", "error", err)
		return "unknown"
	}

	// Extract root package name for lookup
	rootPackage := g.extractRootPackageForVersionLookup(packageName)

	// Look up version in the module versions map
	if version, exists := moduleVersions[rootPackage]; exists {
		g.logger.Debug("Found version for package", "package", packageName, "root_package", rootPackage, "version", version)
		return version
	}

	g.logger.Debug("No version found for package", "package", packageName, "root_package", rootPackage)
	return "unknown"
}

// getModuleVersions executes 'go list -m all' to get all module versions
func (g *FBOMGenerator) getModuleVersions() (map[string]string, error) {
	// Check if vendor directory exists to determine the right approach
	useVendorMode := g.hasVendorDirectory()
	if useVendorMode {
		g.logger.Debug("Vendor directory detected, using -mod=mod flag")
	}

	lines, err := utils.GetModuleVersions(useVendorMode)
	if err != nil {
		return nil, err
	}

	moduleVersions := make(map[string]string)

	for _, line := range lines {

		// Parse line format: "module version"
		// Example: "github.com/gin-gonic/gin v1.9.1"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			module := parts[0]
			version := parts[1]
			moduleVersions[module] = version
		} else if len(parts) == 1 {
			// Main module has no version
			moduleVersions[parts[0]] = ""
		}
	}

	return moduleVersions, nil
}

// hasVendorDirectory checks if the current working directory contains a vendor directory
func (g *FBOMGenerator) hasVendorDirectory() bool {
	if _, err := os.Stat("vendor"); err == nil {
		return true
	}
	return false
}

// extractRootPackageForVersionLookup extracts the root package name for version lookup
func (g *FBOMGenerator) extractRootPackageForVersionLookup(packageName string) string {
	// First, strip vendor/ prefix if present
	originalPackage := packageName
	if strings.HasPrefix(packageName, "vendor/") {
		packageName = strings.TrimPrefix(packageName, "vendor/")
		g.logger.Debug("Stripped vendor prefix", "original", originalPackage, "stripped", packageName)
	}

	// Handle special cases for version lookup
	if strings.HasPrefix(packageName, "golang.org/x/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
	}

	if strings.HasPrefix(packageName, "google.golang.org/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
	}

	if strings.HasPrefix(packageName, "gopkg.in/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
	}

	// For GitHub packages: github.com/owner/repo
	if strings.HasPrefix(packageName, "github.com/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
	}

	// Default: return the package name as-is
	return packageName
}

// generatePurlIdentifier generates a Package URL (PURL) identifier for a Go module
// according to the PURL specification: https://github.com/package-url/purl-spec
func (g *FBOMGenerator) generatePurlIdentifier(packageName, version string) string {
	// Return empty PURL for unknown or empty versions
	if version == "" || version == "unknown" {
		return ""
	}

	// Extract the root package name for consistent PURL generation
	rootPackage := g.extractRootPackageForVersionLookup(packageName)

	// Generate PURL in the format: pkg:golang/namespace/name@version
	// For Go modules, the namespace and name are combined as the full module path
	return fmt.Sprintf("pkg:golang/%s@%s", rootPackage, version)
}

// calculateFunctionCounts calculates and sets the used_functions for a dependency
func (g *FBOMGenerator) calculateFunctionCounts(dep *Dependency) {
	// Calculate used functions: count unique function names in CalledFunctions
	uniqueFunctions := make(map[string]bool)
	for _, fn := range dep.CalledFunctions {
		uniqueFunctions[fn.FunctionName] = true
	}
	dep.UsedFunctions = len(uniqueFunctions)

	g.logger.Debug("Calculated function counts for dependency",
		"package", dep.Name,
		"used_functions", dep.UsedFunctions,
		"called_functions", len(dep.CalledFunctions))
}

// buildDependencyClusters creates dependency clusters for attack surface analysis
func (g *FBOMGenerator) buildDependencyClusters(callGraph *callgraph.Graph, allFunctions []Function) []DependencyCluster {
	g.logger.Debug("Building dependency clusters")

	if callGraph == nil {
		g.logger.Debug("No call graph available for clustering")
		return []DependencyCluster{}
	}

	// Map to collect dependency functions by package
	packageClusters := make(map[string]*DependencyCluster)

	// Iterate through call graph nodes to find dependencies
	for fn, node := range callGraph.Nodes {
		if fn == nil || node == nil {
			continue
		}

		callerPkg := g.getPackageName(fn)

		// Only process user-defined functions as callers
		if !g.isUserDefinedPackage(callerPkg) {
			continue
		}

		// Iterate through outgoing edges to find dependency calls
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			calleePkg := g.getPackageName(edge.Callee.Func)

			// Check if callee is a dependency or stdlib
			if g.isDependencyOrStdlib(calleePkg) {
				// Initialize cluster for this dependency package
				if packageClusters[calleePkg] == nil {
					packageClusters[calleePkg] = &DependencyCluster{
						Name:             calleePkg,
						EntryPoints:      []DependencyEntry{},
						ClusterFunctions: []string{},
						TotalBlastRadius: 0,
					}
				}

				cluster := packageClusters[calleePkg]

				// Add entry point if not already present
				calleeFuncName := g.getFunctionName(edge.Callee.Func)
				callerFuncName := g.getFunctionName(fn)

				g.addEntryPoint(cluster, calleeFuncName, callerFuncName)

				// Add all reachable functions from this entry point
				g.addReachableFunctions(cluster, edge.Callee, callGraph)
			}
		}
	}

	// Convert map to slice and calculate final blast radius
	clusters := make([]DependencyCluster, 0, len(packageClusters))
	for _, cluster := range packageClusters {
		// Remove duplicates and set final blast radius
		cluster.ClusterFunctions = g.removeDuplicateStrings(cluster.ClusterFunctions)
		cluster.TotalBlastRadius = len(cluster.ClusterFunctions)
		clusters = append(clusters, *cluster)
	}

	g.logger.Debug("Built dependency clusters", "count", len(clusters))
	return clusters
}

// Helper functions for dependency clustering

// getPackageName extracts package name from SSA function
func (g *FBOMGenerator) getPackageName(fn *ssa.Function) string {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return ""
	}
	return fn.Pkg.Pkg.Path()
}

// getFunctionName extracts function name from SSA function
func (g *FBOMGenerator) getFunctionName(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	return fn.Name()
}

// isDependencyOrStdlib checks if package is a dependency or stdlib
func (g *FBOMGenerator) isDependencyOrStdlib(pkgPath string) bool {
	return g.isStandardLibraryPackage(pkgPath) || g.isDependencyPackage(pkgPath)
}

// addEntryPoint adds an entry point to the cluster
func (g *FBOMGenerator) addEntryPoint(cluster *DependencyCluster, entryFunc, callerFunc string) {
	// Find existing entry point or create new one
	for i := range cluster.EntryPoints {
		if cluster.EntryPoints[i].Function == entryFunc {
			// Add caller if not already present
			for _, caller := range cluster.EntryPoints[i].CalledFrom {
				if caller == callerFunc {
					return // Already exists
				}
			}
			cluster.EntryPoints[i].CalledFrom = append(cluster.EntryPoints[i].CalledFrom, callerFunc)
			return
		}
	}

	// Create new entry point
	cluster.EntryPoints = append(cluster.EntryPoints, DependencyEntry{
		Function:   entryFunc,
		CalledFrom: []string{callerFunc},
	})
}

// addReachableFunctions adds all functions reachable from the given node to the cluster
func (g *FBOMGenerator) addReachableFunctions(cluster *DependencyCluster, startNode *callgraph.Node, callGraph *callgraph.Graph) {
	visited := make(map[*callgraph.Node]bool)
	g.traverseReachableFunctions(cluster, startNode, callGraph, visited)
}

// traverseReachableFunctions recursively traverses and adds reachable functions
func (g *FBOMGenerator) traverseReachableFunctions(cluster *DependencyCluster, node *callgraph.Node, callGraph *callgraph.Graph, visited map[*callgraph.Node]bool) {
	if visited[node] || node == nil || node.Func == nil {
		return
	}

	visited[node] = true

	// Add this function to cluster if it's from the same dependency package
	nodePkg := g.getPackageName(node.Func)
	if nodePkg == cluster.Name {
		funcName := g.getFunctionName(node.Func)
		cluster.ClusterFunctions = append(cluster.ClusterFunctions, funcName)

		// Continue traversing from this node
		for _, edge := range node.Out {
			if edge != nil && edge.Callee != nil {
				g.traverseReachableFunctions(cluster, edge.Callee, callGraph, visited)
			}
		}
	}
}

// removeDuplicateStrings removes duplicate strings from a slice
func (g *FBOMGenerator) removeDuplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	sort.Strings(result)
	return result
}
