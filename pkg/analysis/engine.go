package analysis

import (
	"fmt"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Engine coordinates the analysis of CVE impact based on call graphs and reflection usage.
type Engine struct {
	verbose bool
}

// NewEngine creates a new analysis engine.
func NewEngine(verbose bool) *Engine {
	return &Engine{verbose: verbose}
}

// Assessment represents the analysis result for a CVE.
type Assessment struct {
	CVE                  cve.CVE
	OriginalPriority     string
	CalculatedPriority   string
	ReachabilityStatus   ReachabilityStatus
	ReflectionRisk       reflection.RiskLevel
	CallPaths            []CallPath
	EntryPointDistance   int
	Justification        string
	RequiresManualReview bool
}

// ReachabilityStatus indicates how a vulnerable function can be reached.
type ReachabilityStatus int

const (
	NotReachable ReachabilityStatus = iota
	DirectlyReachable
	TransitivelyReachable
	ReflectionPossible
	Unknown
)

func (r ReachabilityStatus) String() string {
	switch r {
	case NotReachable:
		return "Not Reachable"
	case DirectlyReachable:
		return "Directly Reachable"
	case TransitivelyReachable:
		return "Transitively Reachable"
	case ReflectionPossible:
		return "Potentially Reachable via Reflection"
	case Unknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// CallPath represents a path from an entry point to a vulnerable function
type CallPath struct {
	EntryPoint      string
	VulnerableFunc  string
	Steps           []string
	Length          int
	HasReflection   bool
	ReflectionNodes []string
}

// AnalysisContext contains all the data needed for analysis
type AnalysisContext struct {
	CallGraph       *callgraph.Graph
	SSAProgram      *ssa.Program
	ReflectionUsage map[string]*reflection.Usage
	CVEDatabase     *cve.CVEDatabase
	EntryPoints     []string
}

// AnalyzeAll performs analysis on all CVEs in the database
func (e *Engine) AnalyzeAll(ctx *AnalysisContext) ([]Assessment, error) {
	if e.verbose {
		fmt.Printf("Starting analysis of %d CVEs\n", len(ctx.CVEDatabase.CVEs))
	}

	var assessments []Assessment

	for _, vulnCVE := range ctx.CVEDatabase.CVEs {
		assessment, err := e.AnalyzeCVE(ctx, vulnCVE)
		if err != nil {
			if e.verbose {
				fmt.Printf("Warning: Failed to analyze CVE %s: %v\n", vulnCVE.ID, err)
			}
			continue
		}
		assessments = append(assessments, *assessment)
	}

	if e.verbose {
		fmt.Printf("Completed analysis of %d CVEs\n", len(assessments))
	}

	return assessments, nil
}

// AnalyzeCVE performs detailed analysis on a single CVE
func (e *Engine) AnalyzeCVE(ctx *AnalysisContext, targetCVE cve.CVE) (*Assessment, error) {
	if e.verbose {
		fmt.Printf("Analyzing CVE %s for package %s\n", targetCVE.ID, targetCVE.VulnerablePackage)
	}

	assessment := &Assessment{
		CVE:              targetCVE,
		OriginalPriority: targetCVE.OriginalSeverity,
	}

	// Step 1: Find vulnerable functions in the call graph
	vulnerableNodes := e.findVulnerableFunctions(ctx.CallGraph, targetCVE)
	if len(vulnerableNodes) == 0 {
		assessment.ReachabilityStatus = NotReachable

		// ENHANCED: Check for high reflection risk even when functions aren't directly reachable
		// This is critical for cases where vulnerable functions might be called via reflection
		maxReflectionRisk := e.assessGlobalReflectionRisk(ctx.ReflectionUsage, targetCVE.VulnerablePackage)
		assessment.ReflectionRisk = maxReflectionRisk

		if maxReflectionRisk >= reflection.RiskHigh {
			assessment.CalculatedPriority = "UNCERTAIN (High reflection risk - manual review required)"
			assessment.Justification = "Vulnerable functions not in static call graph, but high-risk reflection detected"
			assessment.RequiresManualReview = true
		} else {
			assessment.CalculatedPriority = "Low (Vulnerable function not found in call graph)"
			assessment.Justification = "Vulnerable functions not found in call graph"
		}
		return assessment, nil
	}

	// Step 2: Analyze reachability from entry points
	reachability := e.analyzeReachability(ctx, vulnerableNodes)
	assessment.ReachabilityStatus = reachability.Status
	assessment.CallPaths = reachability.Paths
	assessment.EntryPointDistance = reachability.MinDistance

	// Step 3: Check for reflection usage in call paths
	reflectionRisk := e.assessReflectionRisk(ctx.ReflectionUsage, reachability.Paths)
	assessment.ReflectionRisk = reflectionRisk

	// Step 4: Calculate final priority
	assessment.CalculatedPriority = e.calculatePriority(targetCVE, reachability, reflectionRisk)
	assessment.Justification = e.generateJustification(assessment)
	assessment.RequiresManualReview = e.requiresManualReview(assessment)

	return assessment, nil
}

// findVulnerableFunctions locates functions mentioned in the CVE within the call graph
func (e *Engine) findVulnerableFunctions(graph *callgraph.Graph, targetCVE cve.CVE) []*callgraph.Node {
	var vulnerableNodes []*callgraph.Node

	for _, node := range graph.Nodes {
		if node.Func == nil || node.Func.Pkg == nil {
			continue
		}

		packagePath := node.Func.Pkg.Pkg.Path()
		functionName := node.Func.Name()

		// Check if this function belongs to the vulnerable package
		if !strings.HasPrefix(packagePath, targetCVE.VulnerablePackage) {
			continue
		}

		// If specific vulnerable functions are listed, check for matches
		if len(targetCVE.VulnerableFunctions) > 0 {
			found := false
			for _, vulnFunc := range targetCVE.VulnerableFunctions {
				if strings.Contains(functionName, vulnFunc) ||
					strings.Contains(node.Func.String(), vulnFunc) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		vulnerableNodes = append(vulnerableNodes, node)
		if e.verbose {
			fmt.Printf("Found vulnerable function: %s\n", node.Func.String())
		}
	}

	return vulnerableNodes
}

// ReachabilityResult contains the results of reachability analysis
type ReachabilityResult struct {
	Status      ReachabilityStatus
	Paths       []CallPath
	MinDistance int
}

// analyzeReachability determines how vulnerable functions can be reached from entry points
func (e *Engine) analyzeReachability(ctx *AnalysisContext, vulnerableNodes []*callgraph.Node) ReachabilityResult {
	result := ReachabilityResult{
		Status:      NotReachable,
		MinDistance: -1,
	}

	// For each vulnerable function, find paths from entry points
	for _, vulnNode := range vulnerableNodes {
		paths := e.findPathsToFunction(ctx.EntryPoints, vulnNode)
		result.Paths = append(result.Paths, paths...)

		if len(paths) > 0 {
			// Update reachability status
			if result.Status == NotReachable {
				result.Status = TransitivelyReachable
			}

			// Check for direct reachability (path length = 1)
			for _, path := range paths {
				if path.Length == 1 {
					result.Status = DirectlyReachable
				}
				if result.MinDistance == -1 || path.Length < result.MinDistance {
					result.MinDistance = path.Length
				}
			}
		}
	}

	return result
}

// findPathsToFunction finds call paths from entry points to a target function
func (e *Engine) findPathsToFunction(entryPoints []string, target *callgraph.Node) []CallPath {
	var paths []CallPath

	// Simplified BFS to find paths (in a real implementation, you might want to limit depth)
	type pathNode struct {
		node  *callgraph.Node
		path  []string
		depth int
	}

	queue := []*pathNode{}
	visited := make(map[*callgraph.Node]bool)

	// Start from the target and work backwards to entry points
	queue = append(queue, &pathNode{
		node:  target,
		path:  []string{target.Func.String()},
		depth: 0,
	})

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.node] {
			continue
		}
		visited[current.node] = true

		// Check if this is an entry point
		if e.isEntryPoint(current.node, entryPoints) {
			// Found a path from entry point to target
			path := CallPath{
				EntryPoint:     current.node.Func.String(),
				VulnerableFunc: target.Func.String(),
				Steps:          current.path,
				Length:         current.depth,
			}
			paths = append(paths, path)
			continue
		}

		// Add callers to the queue
		for _, caller := range current.node.In {
			if caller.Caller != nil && !visited[caller.Caller] {
				newPath := make([]string, len(current.path)+1)
				newPath[0] = caller.Caller.Func.String()
				copy(newPath[1:], current.path)

				queue = append(queue, &pathNode{
					node:  caller.Caller,
					path:  newPath,
					depth: current.depth + 1,
				})
			}
		}
	}

	return paths
}

// isEntryPoint checks if a function is considered an entry point
func (e *Engine) isEntryPoint(node *callgraph.Node, entryPoints []string) bool {
	if node.Func == nil {
		return false
	}

	funcString := node.Func.String()

	// Default entry point: any main function (package.main)
	// This handles both "main.main" and "package-name.main" patterns
	if strings.HasSuffix(funcString, ".main") {
		return true
	}

	// Check user-defined entry points
	for _, ep := range entryPoints {
		if strings.Contains(funcString, ep) {
			return true
		}
	}

	return false
}

// assessReflectionRisk evaluates reflection risk in the call paths
func (e *Engine) assessReflectionRisk(reflectionUsage map[string]*reflection.Usage, paths []CallPath) reflection.RiskLevel {
	maxRisk := reflection.RiskNone

	for i := range paths {
		path := &paths[i]
		for _, step := range path.Steps {
			if usage, exists := reflectionUsage[step]; exists && usage.UsesReflection {
				path.HasReflection = true
				path.ReflectionNodes = append(path.ReflectionNodes, step)
				if usage.ReflectionRisk > maxRisk {
					maxRisk = usage.ReflectionRisk
				}
			}
		}
	}

	return maxRisk
}

// calculatePriority determines the final priority based on all factors
func (e *Engine) calculatePriority(targetCVE cve.CVE, reachability ReachabilityResult, reflectionRisk reflection.RiskLevel) string {
	originalSeverity := cve.ParseSeverity(targetCVE.OriginalSeverity)

	// Start with original severity
	newSeverity := originalSeverity

	// Adjust based on reachability
	switch reachability.Status {
	case NotReachable:
		// Significantly lower priority
		if newSeverity > cve.SeverityLow {
			newSeverity = cve.SeverityLow
		}
	case DirectlyReachable:
		// Keep high priority, possibly increase
		if reachability.MinDistance <= 2 && newSeverity == cve.SeverityHigh {
			newSeverity = cve.SeverityCritical
		}
	case TransitivelyReachable:
		// Adjust based on distance
		if reachability.MinDistance > 5 {
			// Far from entry points, lower priority
			if newSeverity > cve.SeverityMedium {
				newSeverity--
			}
		}
	}

	// Factor in reflection risk
	if reflectionRisk >= reflection.RiskHigh {
		return "UNCERTAIN (High reflection risk - manual review required)"
	} else if reflectionRisk >= reflection.RiskMedium {
		return newSeverity.String() + " (Caution: Reflection in call path)"
	}

	return newSeverity.String()
}

// generateJustification creates a human-readable explanation for the assessment
func (e *Engine) generateJustification(assessment *Assessment) string {
	parts := []string{}

	switch assessment.ReachabilityStatus {
	case NotReachable:
		parts = append(parts, "Vulnerable functions not found in call graph")
	case DirectlyReachable:
		parts = append(parts, fmt.Sprintf("Directly reachable from entry points (distance: %d)", assessment.EntryPointDistance))
	case TransitivelyReachable:
		parts = append(parts, fmt.Sprintf("Reachable via %d call paths (min distance: %d)", len(assessment.CallPaths), assessment.EntryPointDistance))
	}

	if assessment.ReflectionRisk > reflection.RiskNone {
		parts = append(parts, fmt.Sprintf("Reflection risk: %s", assessment.ReflectionRisk.String()))
	}

	if len(parts) == 0 {
		return "Analysis completed"
	}

	return strings.Join(parts, "; ")
}

// assessGlobalReflectionRisk checks for reflection usage that might call vulnerable packages
func (e *Engine) assessGlobalReflectionRisk(reflectionUsage map[string]*reflection.Usage, vulnerablePackage string) reflection.RiskLevel {
	maxRisk := reflection.RiskNone

	for funcName, usage := range reflectionUsage {
		if usage.UsesReflection {
			// Check if this function has high-risk reflection calls
			if usage.ReflectionRisk >= reflection.RiskHigh {
				if e.verbose {
					fmt.Printf("High-risk reflection found in %s (risk: %s) - could potentially call %s\n",
						funcName, usage.ReflectionRisk.String(), vulnerablePackage)
				}
				maxRisk = usage.ReflectionRisk
			}
		}
	}

	return maxRisk
}

// requiresManualReview determines if manual review is needed
func (e *Engine) requiresManualReview(assessment *Assessment) bool {
	return assessment.ReflectionRisk >= reflection.RiskHigh ||
		strings.Contains(assessment.CalculatedPriority, "UNCERTAIN")
}
