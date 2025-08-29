package cve

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"

	"golang.org/x/tools/go/callgraph"
)

// ReachabilityAnalyzer handles reachability analysis for CVEs
type ReachabilityAnalyzer struct {
	logger  *slog.Logger
	verbose bool
}

// NewReachabilityAnalyzer creates a new reachability analyzer
func NewReachabilityAnalyzer(logger *slog.Logger, verbose bool) *ReachabilityAnalyzer {
	return &ReachabilityAnalyzer{
		logger:  logger,
		verbose: verbose,
	}
}

// AnalyzeReachabilityWithClusters uses dependency clusters for reachability analysis
func (r *ReachabilityAnalyzer) AnalyzeReachabilityWithClusters(vulnerableNodes []*callgraph.Node, targetCVE models.CVE, dependencyClusters []models.DependencyCluster) models.ReachabilityResult {
	result := models.ReachabilityResult{
		Status:      models.NotReachable,
		MinDistance: -1,
	}

	if r.verbose {
		r.logger.Debug("Using cluster-based reachability analysis", "cve_id", targetCVE.ID, "vulnerable_nodes", len(vulnerableNodes), "dependency_clusters", len(dependencyClusters))
	}

	// For each vulnerable function, check if it's in any dependency cluster
	for _, vulnNode := range vulnerableNodes {
		vulnFuncName := vulnNode.Func.Name()
		vulnPackage := vulnNode.Func.Pkg.Pkg.Path()

		if r.verbose {
			r.logger.Debug("Checking reachability for vulnerable function", "function", vulnFuncName, "package", vulnPackage)
		}

		// Check each dependency cluster
		for _, cluster := range dependencyClusters {
			// Skip if cluster is not for the vulnerable package
			if !strings.HasPrefix(cluster.Name, targetCVE.VulnerablePackage) {
				continue
			}

			if r.verbose {
				r.logger.Debug("Checking cluster", "cluster", cluster.Name, "functions", len(cluster.ClusterFunctions), "entry_points", len(cluster.EntryPoints))
			}

			// Check if the vulnerable function is in this cluster's functions
			isInCluster := false
			for _, clusterFunc := range cluster.ClusterFunctions {
				if strings.Contains(clusterFunc, vulnFuncName) {
					isInCluster = true
					break
				}
			}

			if !isInCluster {
				continue
			}

			// If the cluster has entry points, the function is reachable
			if len(cluster.EntryPoints) > 0 {
				if r.verbose {
					r.logger.Debug("Found reachable vulnerable function", "function", vulnFuncName, "cluster", cluster.Name, "entry_points", len(cluster.EntryPoints))
				}

				// Create call paths showing reachability via cluster
				for _, entryPoint := range cluster.EntryPoints {
					callPath := models.CallPath{
						EntryPoint:     fmt.Sprintf("USER_CODE -> %s", entryPoint.Function),
						VulnerableFunc: vulnFuncName,
						Steps:          []string{entryPoint.Function, vulnFuncName},
						Length:         2, // Entry point -> vulnerable function
						HasReflection:  false,
					}
					result.Paths = append(result.Paths, callPath)
				}

				// Mark as reachable
				result.Status = models.TransitivelyReachable
				result.MinDistance = 2 // Conservative estimate

				// If there are multiple entry points, it's highly reachable
				if len(cluster.EntryPoints) > 1 {
					result.Status = models.DirectlyReachable
					result.MinDistance = 1
				}
			}
		}
	}

	return result
}

// AnalyzeReachability determines how vulnerable functions can be reached from entry points (traditional approach)
func (r *ReachabilityAnalyzer) AnalyzeReachability(callGraph *callgraph.Graph, vulnerableNodes []*callgraph.Node, entryPoints []string) models.ReachabilityResult {
	result := models.ReachabilityResult{
		Status:      models.NotReachable,
		MinDistance: -1,
	}

	// For each vulnerable function, find paths from entry points
	for _, vulnNode := range vulnerableNodes {
		paths := r.FindPathsToFunction(entryPoints, vulnNode, callGraph)
		result.Paths = append(result.Paths, paths...)

		if len(paths) > 0 {
			// Update reachability status
			if result.Status == models.NotReachable {
				result.Status = models.TransitivelyReachable
			}

			// Check for direct reachability (path length = 1)
			for _, path := range paths {
				if path.Length == 1 {
					result.Status = models.DirectlyReachable
				}
				if result.MinDistance == -1 || path.Length < result.MinDistance {
					result.MinDistance = path.Length
				}
			}
		}
	}

	return result
}

// FindPathsToFunction finds call paths from entry points to a target function
func (r *ReachabilityAnalyzer) FindPathsToFunction(entryPoints []string, target *callgraph.Node, callGraph *callgraph.Graph) []models.CallPath {
	var paths []models.CallPath

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
		if r.IsEntryPointForCVE(current.node, entryPoints) {
			// Found a path from entry point to target
			path := models.CallPath{
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

// IsEntryPointForCVE checks if a node is an entry point for CVE analysis
func (r *ReachabilityAnalyzer) IsEntryPointForCVE(node *callgraph.Node, entryPoints []string) bool {
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
