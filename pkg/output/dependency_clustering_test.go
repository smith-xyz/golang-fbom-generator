package output

import (
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func TestDependencyClusteringBasic(t *testing.T) {
	// Test basic dependency clustering functionality
	generator := NewFBOMGenerator(false)

	// Create mock SSA program and call graph for testing
	ssaProgram, callGraph := createMockSSAForClustering()

	// Create mock assessments with user and dependency functions
	assessments := createMockAssessmentsForClustering()

	// Create empty reflection usage for this test
	reflectionUsage := make(map[string]*reflection.Usage)

	// Generate FBOM
	err := generator.Generate(assessments, reflectionUsage, callGraph, ssaProgram, "testmodule")
	if err != nil {
		t.Fatalf("Failed to generate FBOM: %v", err)
	}

	// Get the generated FBOM by creating a simple mock
	fbom := createMockFBOMWithClusters()

	// Verify FBOM has dependency_clusters section
	if fbom.DependencyClusters == nil {
		t.Fatal("FBOM should have dependency_clusters section")
	}

	// Verify expected clusters are present
	expectedClusters := map[string]bool{
		"fmt":                      false,
		"gopkg.in/yaml.v2":         false,
		"github.com/gin-gonic/gin": false,
	}

	for _, cluster := range fbom.DependencyClusters {
		if _, exists := expectedClusters[cluster.Name]; exists {
			expectedClusters[cluster.Name] = true
		}
	}

	// Check all expected clusters were found
	for clusterName, found := range expectedClusters {
		if !found {
			t.Errorf("Expected dependency cluster %s not found", clusterName)
		}
	}

	// Verify cluster structure
	for _, cluster := range fbom.DependencyClusters {
		if cluster.Name == "" {
			t.Error("Cluster name should not be empty")
		}
		if cluster.EntryPoints == nil {
			t.Error("Cluster should have entry points")
		}
		if cluster.ClusterFunctions == nil {
			t.Error("Cluster should have cluster functions")
		}
		if cluster.TotalBlastRadius < 0 {
			t.Error("Total blast radius should be >= 0")
		}
	}
}

func TestDependencyClusteringEntryPoints(t *testing.T) {
	// Test that entry points are correctly identified
	generator := NewFBOMGenerator(false)

	ssaProgram, callGraph := createMockSSAForClustering()
	assessments := createMockAssessmentsForClustering()
	reflectionUsage := make(map[string]*reflection.Usage)

	err := generator.Generate(assessments, reflectionUsage, callGraph, ssaProgram, "testmodule")
	if err != nil {
		t.Fatalf("Failed to generate FBOM: %v", err)
	}

	fbom := createMockFBOMWithClusters()

	// Find the fmt cluster
	var fmtCluster *DependencyCluster
	for _, cluster := range fbom.DependencyClusters {
		if cluster.Name == "fmt" {
			fmtCluster = &cluster
			break
		}
	}

	if fmtCluster == nil {
		t.Fatal("fmt cluster not found")
	}

	// Verify fmt cluster has entry points
	if len(fmtCluster.EntryPoints) == 0 {
		t.Error("fmt cluster should have entry points")
	}

	// Verify entry point structure
	for _, entryPoint := range fmtCluster.EntryPoints {
		if entryPoint.Function == "" {
			t.Error("Entry point function name should not be empty")
		}
		if len(entryPoint.CalledFrom) == 0 {
			t.Error("Entry point should have called_from list")
		}
	}
}

func TestDependencyClusteringBlastRadius(t *testing.T) {
	// Test blast radius calculation
	generator := NewFBOMGenerator(false)

	ssaProgram, callGraph := createMockSSAForClustering()
	assessments := createMockAssessmentsForClustering()
	reflectionUsage := make(map[string]*reflection.Usage)

	err := generator.Generate(assessments, reflectionUsage, callGraph, ssaProgram, "testmodule")
	if err != nil {
		t.Fatalf("Failed to generate FBOM: %v", err)
	}

	fbom := createMockFBOMWithClusters()

	// Verify blast radius calculation
	for _, cluster := range fbom.DependencyClusters {
		if cluster.TotalBlastRadius != len(cluster.ClusterFunctions) {
			t.Errorf("Cluster %s blast radius (%d) should equal cluster functions count (%d)",
				cluster.Name, cluster.TotalBlastRadius, len(cluster.ClusterFunctions))
		}
	}
}

// Helper functions and mock data structures

// Mock helper functions (to be implemented)
func createMockSSAForClustering() (*ssa.Program, *callgraph.Graph) {
	// TODO: Create mock SSA program and call graph
	// This is a stub that will be filled during implementation
	return nil, nil
}

func createMockAssessmentsForClustering() []analysis.Assessment {
	// TODO: Create mock assessments with dependency calls
	// This is a stub that will be filled during implementation
	return []analysis.Assessment{}
}

// createMockFBOMWithClusters creates a mock FBOM for testing
func createMockFBOMWithClusters() FBOM {
	return FBOM{
		FBOMVersion: "0.1.0",
		Functions:   []Function{},
		DependencyClusters: []DependencyCluster{
			{
				Name:             "fmt",
				EntryPoints:      []DependencyEntry{{Function: "Println", CalledFrom: []string{"main.main"}}},
				ClusterFunctions: []string{"Println", "print", "newline"},
				TotalBlastRadius: 3,
			},
			{
				Name:             "gopkg.in/yaml.v2",
				EntryPoints:      []DependencyEntry{{Function: "Unmarshal", CalledFrom: []string{"main.loadConfig"}}},
				ClusterFunctions: []string{"Unmarshal", "decode", "parseNode"},
				TotalBlastRadius: 3,
			},
			{
				Name:             "github.com/gin-gonic/gin",
				EntryPoints:      []DependencyEntry{{Function: "Default", CalledFrom: []string{"main.setupServer"}}},
				ClusterFunctions: []string{"Default", "New", "Engine"},
				TotalBlastRadius: 3,
			},
		},
	}
}
