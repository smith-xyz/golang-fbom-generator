package rules

import (
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// DetermineCallType determines the type of call relationship between functions
func DetermineCallType(callee *ssa.Function, allFunctions []models.Function) string {
	calleeID := GenerateFunctionID(callee)

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

// MatchesEntryPointPattern checks if function matches entry point patterns
func MatchesEntryPointPattern(functionName string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchesPattern(functionName, pattern) {
			return true
		}
	}
	return false
}

// MatchesPattern checks if a string matches given patterns
func MatchesPattern(str string, pattern string) bool {
	// Handle exact matches
	if str == pattern {
		return true
	}

	// Handle simple wildcard patterns
	if strings.Contains(pattern, "*") {
		// Special case: single wildcard matches everything
		if pattern == "*" {
			return true
		}

		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			// Pattern like "*User*" - contains match
			if len(pattern) == 2 { // Pattern is "**" - matches everything
				return true
			}
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

// IsEntryPoint determines if a function is a basic entry point (main, init)
// DEPRECATED: IsEntryPoint - This function is redundant now that we have ClassificationPolicy.IsEntryPoint()
// Use Classifier.IsEntryPoint() instead for proper entry point detection with additional patterns.
// This function remains for backward compatibility but should be removed in future refactoring.
func IsEntryPoint(fn *ssa.Function) bool {
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

	// For basic detection, only main and init are considered entry points
	// Use Classifier.IsEntryPoint() for additional patterns and exported function detection
	return false
}

// DetermineReachabilityType determines the type of reachability for a function
// This function requires a call graph to properly determine direct vs transitive reachability
func DetermineReachabilityType(fn *ssa.Function, callGraph *callgraph.Graph, isEntryPointFunc func(*ssa.Function) bool) string {
	if fn == nil {
		return "unreachable"
	}

	if isEntryPointFunc(fn) {
		return "direct"
	}

	// Check if function is called directly by an entry point
	if callGraph != nil {
		fnNode := callGraph.Nodes[fn]
		if fnNode != nil {
			for _, edge := range fnNode.In {
				if edge.Caller != nil && edge.Caller.Func != nil && isEntryPointFunc(edge.Caller.Func) {
					return "direct"
				}
			}
		}
	}

	return "transitive"
}

// IsFunctionReachable checks if a function is reachable from entry points
// This uses a simple heuristic: entry points are reachable, and functions with incoming edges are reachable
func IsFunctionReachable(fn *ssa.Function, callGraph *callgraph.Graph) bool {
	if fn == nil {
		return false
	}

	if callGraph == nil {
		return IsEntryPoint(fn)
	}

	node := callGraph.Nodes[fn]
	if node == nil {
		return false
	}

	// If it's an entry point, it's reachable
	if IsEntryPoint(fn) {
		return true
	}

	// If it has incoming edges, it's reachable
	return len(node.In) > 0
}

// determineCallContext determines the call context (direct, reflection, callback, interface)
func DetermineCallContext(userFuncName, externalFuncName string, callGraph *callgraph.Graph) string {
	// For now, default to "direct" - in future iterations we can analyze:
	// - Reflection usage patterns
	// - Anonymous functions/closures (callback)
	// - Interface calls
	return "direct"
}

// NOTE: Reflection risk logic is scattered across multiple modules.
// Future improvement: consolidate all reflection analysis into a centralized policy struct
// to avoid duplication and improve consistency.
func HasReflectionRisk(usage *models.Usage) bool {
	if usage == nil {
		return false
	}
	return usage.ReflectionRisk == models.RiskMedium || usage.ReflectionRisk == models.RiskHigh
}
