package callgraph

import (
	"log/slog"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/shared"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Analyzer handles call graph analysis and metrics
type Analyzer struct {
	logger         *slog.Logger
	verbose        bool
	config         *Config
	rules          *rules.Rules
	sharedAnalyzer *shared.SharedAnalyzer
}

// Config holds configuration for call graph analysis
type Config struct {
	Verbose               bool
	AdditionalEntryPoints []string // Additional entry points to consider
	MaxDepthAnalysis      int      // Maximum depth for call graph analysis
}

// NewAnalyzer creates a new call graph analyzer
func NewAnalyzer(logger *slog.Logger, config *Config, analysisConfig *models.AnalysisConfig, rules *rules.Rules, sharedAnalyzer *shared.SharedAnalyzer) *Analyzer {
	if config == nil {
		config = &Config{
			Verbose:               false,
			AdditionalEntryPoints: []string{},
			MaxDepthAnalysis:      50,
		}
	}
	return &Analyzer{
		logger:         logger,
		verbose:        config.Verbose,
		config:         config,
		rules:          rules,
		sharedAnalyzer: sharedAnalyzer,
	}
}

// BuildCallGraphInfo builds comprehensive call graph information and statistics
func (a *Analyzer) BuildCallGraphInfo(callGraph *callgraph.Graph, allFunctions []models.Function) models.CallGraphInfo {
	var userEdges []models.CallEdge
	userNodeCount := 0

	// Count functions in call graph (reachable ones)
	if callGraph != nil {
		for fn, node := range callGraph.Nodes {
			if !a.rules.Classifier.IsUserDefinedFunction(fn) {
				continue
			}
			userNodeCount++

			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					calleeFunc := edge.Callee.Func
					filePath, lineNumber := rules.ExtractCallSiteInfo(edge)
					callerID := rules.GenerateFunctionID(fn)

					if a.rules.Classifier.IsUserDefinedFunction(calleeFunc) {
						// User-to-user call
						callType := rules.DetermineCallType(calleeFunc, allFunctions)
						userEdges = append(userEdges, models.CallEdge{
							Caller:     callerID,
							Callee:     rules.GenerateFunctionID(calleeFunc),
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

						if a.rules.Classifier.IsStandardLibraryPackage(packagePath) {
							callType = "stdlib"
							calleeID = rules.FormatFunctionCall(calleeFunc)
						} else if a.rules.Classifier.IsDependencyPackage(packagePath) {
							callType = "external"
							calleeID = rules.FormatFunctionCall(calleeFunc)
						} else {
							// Unknown package type, skip
							continue
						}

						userEdges = append(userEdges, models.CallEdge{
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
	reachableFunctions := a.CalculateReachableFunctions(callGraph)

	// Calculate actual depth metrics
	maxDepth, avgDepth := a.CalculateDepthMetrics(callGraph)

	return models.CallGraphInfo{
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

// CalculateReachableFunctions calculates the number of reachable functions in the call graph
func (a *Analyzer) CalculateReachableFunctions(callGraph *callgraph.Graph) int {
	if callGraph == nil {
		return 0
	}

	reachableSet := make(map[string]bool)

	// Find all entry points
	entryPoints := make([]*ssa.Function, 0)
	for fn := range callGraph.Nodes {
		if a.rules.Classifier.IsEntryPoint(fn) && a.rules.Classifier.IsUserDefinedFunction(fn) {
			entryPoints = append(entryPoints, fn)
		}
	}

	// Traverse from each entry point to find all reachable functions
	for _, entryPoint := range entryPoints {
		a.MarkReachableFunctions(callGraph, entryPoint, reachableSet)
	}

	return len(reachableSet)
}

// CalculateDepthMetrics calculates depth-related metrics for the call graph
func (a *Analyzer) CalculateDepthMetrics(callGraph *callgraph.Graph) (int, float64) {
	if callGraph == nil {
		return 0, 0.0
	}

	// Find all entry points
	entryPoints := make([]*ssa.Function, 0)
	for fn := range callGraph.Nodes {
		if a.rules.Classifier.IsEntryPoint(fn) && a.rules.Classifier.IsUserDefinedFunction(fn) {
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
		a.CalculateFunctionDepths(callGraph, entryPoint, 0, depths)

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

// CalculateFunctionDepths calculates depths of functions from entry points
func (a *Analyzer) CalculateFunctionDepths(callGraph *callgraph.Graph, fn *ssa.Function, currentDepth int, depths map[string]int) {
	if fn == nil || !a.rules.Classifier.IsUserDefinedFunction(fn) {
		return
	}

	functionID := rules.GenerateFunctionID(fn)

	// If we've seen this function at a shallower depth, don't continue
	if existingDepth, exists := depths[functionID]; exists && existingDepth <= currentDepth {
		return
	}

	depths[functionID] = currentDepth

	// Traverse to all callees with increased depth
	if node := callGraph.Nodes[fn]; node != nil {
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				a.CalculateFunctionDepths(callGraph, edge.Callee.Func, currentDepth+1, depths)
			}
		}
	}
}

// CalculateDistanceFromEntry calculates the distance of a function from entry points
func (a *Analyzer) CalculateDistanceFromEntry(fn *ssa.Function, callGraph *callgraph.Graph) int {
	// Delegate to the shared analyzer which has the authoritative implementation
	if a.sharedAnalyzer != nil {
		return a.sharedAnalyzer.CalculateDistanceFromEntry(fn, callGraph)
	}

	// Fallback implementation (should rarely be used)
	if fn == nil {
		return -1
	}

	if a.rules.Classifier.IsEntryPoint(fn) {
		return 0
	}

	return -1 // Conservative fallback
}

// MarkReachableFunctions marks all functions reachable from a given function
func (a *Analyzer) MarkReachableFunctions(callGraph *callgraph.Graph, fn *ssa.Function, reachableSet map[string]bool) {
	if fn == nil || !a.rules.Classifier.IsUserDefinedFunction(fn) {
		return
	}

	functionID := rules.GenerateFunctionID(fn)
	if reachableSet[functionID] {
		return // Already visited
	}

	reachableSet[functionID] = true

	// Traverse to all callees
	if node := callGraph.Nodes[fn]; node != nil {
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				a.MarkReachableFunctions(callGraph, edge.Callee.Func, reachableSet)
			}
		}
	}
}

// CalculateReachableFromEntryPoint delegates to the shared analyzer for consistency
func (a *Analyzer) CalculateReachableFromEntryPoint(callGraph *callgraph.Graph, entryPoint *ssa.Function) int {
	if a.sharedAnalyzer != nil {
		return a.sharedAnalyzer.CalculateReachableFromEntryPoint(callGraph, entryPoint)
	}

	// Fallback implementation
	if callGraph == nil || entryPoint == nil {
		return 0
	}

	reachableSet := make(map[string]bool)
	a.MarkReachableFunctions(callGraph, entryPoint, reachableSet)
	return len(reachableSet)
}
