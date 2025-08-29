package shared

import (
	"log/slog"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// SharedAnalyzer provides common analysis functionality that's shared across multiple analyzers
type SharedAnalyzer struct {
	logger *slog.Logger
	rules  *rules.Rules
}

// NewSharedAnalyzer creates a new shared analyzer
func NewSharedAnalyzer(logger *slog.Logger, rules *rules.Rules) *SharedAnalyzer {
	return &SharedAnalyzer{
		logger: logger,
		rules:  rules,
	}
}

// CalculateDistanceFromEntry calculates the distance of a function from entry points
// This is the authoritative implementation that other analyzers can use
func (s *SharedAnalyzer) CalculateDistanceFromEntry(fn *ssa.Function, callGraph *callgraph.Graph) int {
	if fn == nil {
		return -1
	}

	// If it's an entry point, distance is 0
	if s.rules.Classifier.IsEntryPoint(fn) {
		return 0
	}

	if callGraph == nil {
		return -1
	}

	// Find all entry points and calculate depths from each
	minDistance := -1
	for entryFn := range callGraph.Nodes {
		if s.rules.Classifier.IsEntryPoint(entryFn) && s.rules.Classifier.IsUserDefinedFunction(entryFn) {
			depths := make(map[string]int)
			s.calculateFunctionDepths(callGraph, entryFn, 0, depths)

			functionID := rules.GenerateFunctionID(fn)
			if distance, found := depths[functionID]; found {
				if minDistance == -1 || distance < minDistance {
					minDistance = distance
				}
			}
		}
	}

	return minDistance
}

// calculateFunctionDepths calculates depths of functions from entry points (internal implementation)
func (s *SharedAnalyzer) calculateFunctionDepths(callGraph *callgraph.Graph, fn *ssa.Function, currentDepth int, depths map[string]int) {
	if fn == nil || !s.rules.Classifier.IsUserDefinedFunction(fn) {
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
				s.calculateFunctionDepths(callGraph, edge.Callee.Func, currentDepth+1, depths)
			}
		}
	}
}

// CalculateReachableFromEntryPoint calculates functions reachable from a specific entry point
func (a *SharedAnalyzer) CalculateReachableFromEntryPoint(callGraph *callgraph.Graph, entryPoint *ssa.Function) int {
	if callGraph == nil || entryPoint == nil {
		return 0
	}

	reachableSet := make(map[string]bool)
	a.markReachableFunctions(callGraph, entryPoint, reachableSet)
	return len(reachableSet)
}

// markReachableFunctions marks all functions reachable from a given function
func (a *SharedAnalyzer) markReachableFunctions(callGraph *callgraph.Graph, fn *ssa.Function, reachableSet map[string]bool) {
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
				a.markReachableFunctions(callGraph, edge.Callee.Func, reachableSet)
			}
		}
	}
}

// CalculateAllDistancesFromEntryPoints calculates distances for all functions from entry points
// Returns a map of functionID -> distance for efficient lookup
func (s *SharedAnalyzer) CalculateAllDistancesFromEntryPoints(callGraph *callgraph.Graph) map[string]int {
	allDistances := make(map[string]int)

	if callGraph == nil {
		return allDistances
	}

	// Find all entry points and calculate depths from each
	for entryFn := range callGraph.Nodes {
		if s.rules.Classifier.IsEntryPoint(entryFn) && s.rules.Classifier.IsUserDefinedFunction(entryFn) {
			depths := make(map[string]int)
			s.calculateFunctionDepths(callGraph, entryFn, 0, depths)

			// Merge depths, keeping minimum distance for each function
			for functionID, distance := range depths {
				if existingDistance, exists := allDistances[functionID]; !exists || distance < existingDistance {
					allDistances[functionID] = distance
				}
			}
		}
	}

	return allDistances
}

// IsReachableFromEntry determines if a function is reachable from any entry point
func (s *SharedAnalyzer) IsReachableFromEntry(fn *ssa.Function, callGraph *callgraph.Graph) bool {
	return s.CalculateDistanceFromEntry(fn, callGraph) >= 0
}
