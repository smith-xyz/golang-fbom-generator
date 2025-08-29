package dependency

import (
	"log/slog"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"golang.org/x/tools/go/callgraph"
)

// AttackPathAnalyzer handles attack path construction and blast radius analysis
type AttackPathAnalyzer struct {
	logger  *slog.Logger
	verbose bool
	config  *Config
	rules   *rules.Rules
}

// NewAttackPathAnalyzer creates a new attack path analyzer
func NewAttackPathAnalyzer(logger *slog.Logger, verbose bool, config *Config, rules *rules.Rules) *AttackPathAnalyzer {
	return &AttackPathAnalyzer{
		logger:  logger,
		verbose: verbose,
		config:  config,
		rules:   rules,
	}
}

// BuildAttackPath creates an enhanced attack path with transitive call tracking
func (a *AttackPathAnalyzer) BuildAttackPath(startNode *callgraph.Node, callGraph *callgraph.Graph, entryFunction string, maxDepth int) *models.AttackPath {
	if startNode == nil || startNode.Func == nil {
		return nil
	}

	attackPath := &models.AttackPath{
		EntryFunction:    entryFunction,
		PathDepth:        0,
		RiskLevel:        "low",
		Path:             []models.PathStep{},
		VulnerabilityIDs: []string{},
	}

	visited := make(map[*callgraph.Node]bool)
	packagesReached := make(map[string]bool)

	// Build the path through transitive calls
	a.BuildPathSteps(startNode, callGraph, visited, &attackPath.Path, packagesReached, 0, maxDepth)

	riskAssessor := cve.NewRiskAssessor(a.logger, a.verbose)
	// Calculate path metrics
	attackPath.PathDepth = len(attackPath.Path)
	attackPath.RiskLevel = riskAssessor.AssessPathRisk(attackPath.Path)

	return attackPath
}

// BuildPathSteps recursively builds the attack path steps with cross-package traversal
func (a *AttackPathAnalyzer) BuildPathSteps(node *callgraph.Node, callGraph *callgraph.Graph, visited map[*callgraph.Node]bool, path *[]models.PathStep, packagesReached map[string]bool, currentDepth int, maxDepth int) {
	if visited[node] || node == nil || node.Func == nil || currentDepth >= maxDepth {
		return
	}

	visited[node] = true

	nodePkg := rules.GetPackageName(node.Func)
	nodeFunc := rules.GetFunctionName(node.Func)
	packagesReached[nodePkg] = true

	// Determine call type and risk indicators
	callType := "direct"
	riskIndicators := []string{}

	if currentDepth > 0 {
		callType = "transitive"
	}

	// Check for reflection usage
	if nodePkg == "reflect" {
		callType = "reflection"
		riskIndicators = append(riskIndicators, "REFLECTION")
	}

	// Check for known risky patterns
	if a.rules.Classifier.IsDeserializationFunction(nodeFunc) {
		riskIndicators = append(riskIndicators, "DESERIALIZATION")
	}

	if a.rules.Classifier.IsNetworkFunction(nodeFunc) {
		riskIndicators = append(riskIndicators, "NETWORK")
	}

	// Add path step
	*path = append(*path, models.PathStep{
		Function:       nodeFunc,
		Package:        nodePkg,
		CallType:       callType,
		RiskIndicators: riskIndicators,
	})

	// Continue traversing outgoing edges with depth limit
	// Only traverse a subset to avoid infinite paths
	edgeCount := 0
	maxEdges := a.config.MaxAttackPathEdges // Limit edges per node to avoid explosion

	for _, edge := range node.Out {
		if edge != nil && edge.Callee != nil && edge.Callee.Func != nil && edgeCount < maxEdges {
			a.BuildPathSteps(edge.Callee, callGraph, visited, path, packagesReached, currentDepth+1, maxDepth)
			edgeCount++
		}
	}
}

// BuildBlastRadiusSummary creates a summary of the attack paths for human readability
func (a *AttackPathAnalyzer) BuildBlastRadiusSummary(attackPaths []models.AttackPath) models.BlastRadiusSummary {
	packagesReached := make(map[string]bool)
	directFunctions := 0
	transitiveFunctions := 0
	highRiskPaths := 0
	maxDepth := 0

	for _, path := range attackPaths {
		if path.RiskLevel == "high" || path.RiskLevel == "critical" {
			highRiskPaths++
		}

		if path.PathDepth > maxDepth {
			maxDepth = path.PathDepth
		}

		for _, step := range path.Path {
			packagesReached[step.Package] = true

			if step.CallType == "direct" {
				directFunctions++
			} else {
				transitiveFunctions++
			}
		}
	}

	// Convert packages map to slice
	packages := make([]string, 0, len(packagesReached))
	for pkg := range packagesReached {
		packages = append(packages, pkg)
	}

	return models.BlastRadiusSummary{
		DirectFunctions:     directFunctions,
		TransitiveFunctions: transitiveFunctions,
		HighRiskPaths:       highRiskPaths,
		PackagesReached:     packages,
		MaxPathDepth:        maxDepth,
	}
}
