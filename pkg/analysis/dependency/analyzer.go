package dependency

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
	"golang.org/x/tools/go/callgraph"
)

// Analyzer handles dependency discovery, clustering, and attack path analysis
type Analyzer struct {
	logger  *slog.Logger
	verbose bool
	config  *Config
}

// Config holds configuration for dependency analysis
type Config struct {
	Verbose            bool
	MaxAttackPathDepth int // Maximum depth for attack path traversal
	MaxAttackPathEdges int // Maximum edges per attack path
}

// NewAnalyzer creates a new dependency analyzer
func NewAnalyzer(logger *slog.Logger, config *Config) *Analyzer {
	if config == nil {
		config = &Config{
			MaxAttackPathDepth: 5,
			MaxAttackPathEdges: 10,
		}
	}
	return &Analyzer{
		logger:  logger,
		verbose: config.Verbose,
		config:  config,
	}
}

// ExtractDependencies extracts dependencies from packages and builds external function call maps
func (a *Analyzer) ExtractDependencies(packages []string, allFunctions []models.Function, callGraph *callgraph.Graph, classifier rules.Classifier) []models.Dependency {
	deps := make([]models.Dependency, 0)

	// Track which external functions are called by which user functions
	externalCallMap := make(map[string][]models.ExternalFunctionCall)

	// Analyze function calls to build external call tracking
	for _, userFunc := range allFunctions {
		for _, externalCall := range userFunc.UsageInfo.ExternalCalls {
			packageName := rules.ExtractPackageFromCall(externalCall)
			functionName := rules.ExtractFunctionFromCall(externalCall)

			if packageName != "" && functionName != "" {
				if externalCallMap[packageName] == nil {
					externalCallMap[packageName] = []models.ExternalFunctionCall{}
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
					externalCallMap[packageName] = append(externalCallMap[packageName], models.ExternalFunctionCall{
						FunctionName:     functionName,
						FullFunctionName: externalCall,
						CallSites:        []string{userFunc.Name},
						CallCount:        1,
						CallContext:      rules.DetermineCallContext(userFunc.Name, functionName, callGraph),
					})
				}
			}
		}
	}

	// Cache module versions once to avoid repeated expensive go list calls
	moduleVersions, err := a.GetModuleVersions()
	if err != nil {
		a.logger.Debug("Failed to get module versions using go list", "error", err)
		moduleVersions = make(map[string]string) // Use empty map as fallback
	}

	// Build dependencies with enhanced metadata
	for _, pkg := range packages {
		if classifier.IsDependencyPackage(pkg) {
			version := a.extractVersionFromCache(pkg, moduleVersions)
			dep := models.Dependency{
				Name:           pkg,
				Version:        version,
				Type:           "go-module",
				SPDXId:         fmt.Sprintf("SPDXRef-Package-%s", strings.ReplaceAll(pkg, "/", "-")),
				PackageManager: "go",
				PurlIdentifier: a.GeneratePurlIdentifier(pkg, version),
				UsedFunctions:  0, // Will be calculated after CalledFunctions is set
			}

			if calledFunctions, exists := externalCallMap[pkg]; exists {
				dep.CalledFunctions = calledFunctions
			}

			// Calculate function counts (used and total)
			a.CalculateFunctionCounts(&dep)

			deps = append(deps, dep)
		}
	}

	return deps
}

// BuildDependencyClusters creates dependency clusters for attack surface analysis
func (a *Analyzer) BuildDependencyClusters(callGraph *callgraph.Graph, allFunctions []models.Function, classifier *rules.Classifier, attackPathAnalyzer *AttackPathAnalyzer, blastRadiusAnalyzer *AttackPathAnalyzer) []models.DependencyCluster {
	a.logger.Debug("Building dependency clusters")

	if callGraph == nil {
		a.logger.Debug("No call graph available for clustering")
		return []models.DependencyCluster{}
	}

	// Map to collect dependency functions by package
	packageClusters := make(map[string]*models.DependencyCluster)

	// Iterate through call graph nodes to find dependencies
	for fn, node := range callGraph.Nodes {
		if fn == nil || node == nil {
			continue
		}

		callerPkg := rules.GetPackageName(fn)

		// Only process user-defined functions as callers
		if !classifier.IsUserDefinedPackage(callerPkg) {
			continue
		}

		// Iterate through outgoing edges to find dependency calls
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			calleePkg := rules.GetPackageName(edge.Callee.Func)

			// Check if callee is a dependency or stdlib
			if classifier.IsDependencyOrStdlib(calleePkg) {
				// Initialize cluster for this dependency package
				if packageClusters[calleePkg] == nil {
					packageClusters[calleePkg] = &models.DependencyCluster{
						Name:               calleePkg,
						EntryPoints:        []models.DependencyEntry{},
						AttackPaths:        []models.AttackPath{},
						BlastRadiusSummary: models.BlastRadiusSummary{},
						ClusterFunctions:   []string{}, // Keep for backward compatibility
						TotalBlastRadius:   0,
					}
				}

				cluster := packageClusters[calleePkg]

				// Add entry point if not already present
				calleeFuncName := rules.GetFunctionName(edge.Callee.Func)
				callerFuncName := rules.GetFunctionName(fn)

				a.AddEntryPoint(cluster, calleeFuncName, callerFuncName)

				// Build attack path from this entry point with enhanced traversal
				attackPath := attackPathAnalyzer.BuildAttackPath(edge.Callee, callGraph, calleeFuncName, a.config.MaxAttackPathDepth)
				if attackPath != nil && len(attackPath.Path) > 0 {
					cluster.AttackPaths = append(cluster.AttackPaths, *attackPath)
				}

				// Add all reachable functions from this entry point (backward compatibility)
				a.AddReachableFunctions(cluster, edge.Callee, callGraph)
			}
		}
	}

	// Convert map to slice and calculate final statistics
	clusters := make([]models.DependencyCluster, 0, len(packageClusters))
	for _, cluster := range packageClusters {
		// Remove duplicates and set final blast radius (backward compatibility)
		cluster.ClusterFunctions = a.removeDuplicateStrings(cluster.ClusterFunctions)
		cluster.TotalBlastRadius = len(cluster.ClusterFunctions)

		// Build enhanced summary
		if len(cluster.AttackPaths) > 0 {
			cluster.BlastRadiusSummary = blastRadiusAnalyzer.BuildBlastRadiusSummary(cluster.AttackPaths)
		} else {
			// Provide a basic summary when no attack paths are available
			cluster.BlastRadiusSummary = models.BlastRadiusSummary{
				DirectFunctions:     len(cluster.ClusterFunctions),
				TransitiveFunctions: 0,
				HighRiskPaths:       0,
				PackagesReached:     []string{cluster.Name},
				MaxPathDepth:        1,
			}
		}

		clusters = append(clusters, *cluster)
	}

	a.logger.Debug("Built dependency clusters", "count", len(clusters))
	return clusters
}

// CalculateFunctionCounts calculates and sets the used_functions for a dependency
func (a *Analyzer) CalculateFunctionCounts(dep *models.Dependency) {
	// Calculate used functions: count unique function names in CalledFunctions
	uniqueFunctions := make(map[string]bool)
	for _, fn := range dep.CalledFunctions {
		uniqueFunctions[fn.FunctionName] = true
	}
	dep.UsedFunctions = len(uniqueFunctions)

	a.logger.Debug("Calculated function counts for dependency",
		"package", dep.Name,
		"used_functions", dep.UsedFunctions,
		"called_functions", len(dep.CalledFunctions))
}

// AddEntryPoint adds an entry point to the cluster
func (a *Analyzer) AddEntryPoint(cluster *models.DependencyCluster, entryFunc, callerFunc string) {
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
	cluster.EntryPoints = append(cluster.EntryPoints, models.DependencyEntry{
		Function:   entryFunc,
		CalledFrom: []string{callerFunc},
	})
}

// AddReachableFunctions adds all functions reachable from the given node to the cluster
func (a *Analyzer) AddReachableFunctions(cluster *models.DependencyCluster, startNode *callgraph.Node, callGraph *callgraph.Graph) {
	visited := make(map[*callgraph.Node]bool)
	a.traverseReachableFunctions(cluster, startNode, callGraph, visited)
}

// traverseReachableFunctions recursively traverses and adds reachable functions
func (a *Analyzer) traverseReachableFunctions(cluster *models.DependencyCluster, node *callgraph.Node, callGraph *callgraph.Graph, visited map[*callgraph.Node]bool) {
	if visited[node] || node == nil || node.Func == nil {
		return
	}

	visited[node] = true

	// Add this function to cluster if it's from the same dependency package
	nodePkg := rules.GetPackageName(node.Func)
	if nodePkg == cluster.Name {
		funcName := rules.GetFunctionName(node.Func)
		cluster.ClusterFunctions = append(cluster.ClusterFunctions, funcName)

		// Continue traversing from this node
		for _, edge := range node.Out {
			if edge != nil && edge.Callee != nil {
				a.traverseReachableFunctions(cluster, edge.Callee, callGraph, visited)
			}
		}
	}
}

// extractVersionFromCache looks up version from a pre-loaded module versions cache
func (a *Analyzer) extractVersionFromCache(packageName string, moduleVersions map[string]string) string {
	// Extract root package name for lookup
	rootPackage := a.ExtractRootPackageForVersionLookup(packageName)

	// Look up version in the module versions map
	if version, exists := moduleVersions[rootPackage]; exists {
		a.logger.Debug("Found version for package", "package", packageName, "root_package", rootPackage, "version", version)
		return version
	}

	a.logger.Debug("No version found for package", "package", packageName, "root_package", rootPackage)
	return "unknown"
}

func (a *Analyzer) GetModuleVersions() (map[string]string, error) {
	// Check if vendor directory exists to determine the right approach
	useVendorMode := a.HasVendorDirectory()
	if useVendorMode {
		a.logger.Debug("Vendor directory detected, using -mod=mod flag")
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

func (a *Analyzer) ExtractRootPackageForVersionLookup(packageName string) string {
	// First, strip vendor/ prefix if present
	originalPackage := packageName
	if strings.HasPrefix(packageName, "vendor/") {
		packageName = strings.TrimPrefix(packageName, "vendor/")
		a.logger.Debug("Stripped vendor prefix", "original", originalPackage, "stripped", packageName)
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

// GeneratePurlIdentifier generates a Package URL (PURL) identifier for Go modules
func (a *Analyzer) GeneratePurlIdentifier(packageName, version string) string {
	// Return empty string for invalid/unknown versions (per test requirements)
	if version == "" || version == "unknown" {
		return ""
	}
	// Generate PURL in the format: pkg:golang/namespace/name@version
	// For Go modules, the namespace and name are combined as the full module path
	rootPackage := a.ExtractRootPackageForVersionLookup(packageName)
	return fmt.Sprintf("pkg:golang/%s@%s", rootPackage, version)
}

// hasVendorDirectory checks if a vendor directory exists in the current working directory
func (a *Analyzer) HasVendorDirectory() bool {
	return utils.DirectoryExists("vendor")
}

// removeDuplicateStrings removes duplicate strings from a slice
func (a *Analyzer) removeDuplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, str := range slice {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}
