package feature

import (
	"encoding/json"
	"os/exec"
	"testing"

	"golang-fbom-generator/tests/shared"
)

// TestDependencyClusteringIntegration tests the dependency clustering functionality
func TestDependencyClusteringIntegration(t *testing.T) {
	// Build the binary
	binaryPath := shared.GetBinaryPath(t)
	// Clean up the test binary

	// Test on the test-project which has multiple dependencies
	testCase := "test-project"
	examplePath := "../../examples/" + testCase

	// Build command
	args := []string{"-package", "."}
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = examplePath

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Binary execution failed: %v", err)
	}

	// Parse the JSON output
	var fbom shared.FBOM
	if err := json.Unmarshal(output, &fbom); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Verify dependency_clusters section exists
	if fbom.DependencyClusters == nil {
		t.Fatal("FBOM should have dependency_clusters section")
	}

	// Verify we have a reasonable number of clusters (should be > 0)
	if len(fbom.DependencyClusters) == 0 {
		t.Error("Expected at least some dependency clusters")
	}

	t.Logf("Generated %d dependency clusters", len(fbom.DependencyClusters))

	// Verify key dependencies are present
	expectedDeps := map[string]bool{
		"github.com/gin-gonic/gin": false,
		"gopkg.in/yaml.v2":         false,
	}

	for _, cluster := range fbom.DependencyClusters {
		if _, exists := expectedDeps[cluster.Name]; exists {
			expectedDeps[cluster.Name] = true
		}

		// Verify cluster structure
		if cluster.Name == "" {
			t.Error("Cluster should have a name")
		}
		if cluster.EntryPoints == nil {
			t.Errorf("Cluster %s should have entry_points array", cluster.Name)
		}
		if cluster.ClusterFunctions == nil {
			t.Errorf("Cluster %s should have cluster_functions array", cluster.Name)
		}
		if cluster.TotalBlastRadius <= 0 {
			t.Errorf("Cluster %s should have positive blast radius, got %d", cluster.Name, cluster.TotalBlastRadius)
		}

		// Verify total_blast_radius matches cluster_functions length
		if cluster.TotalBlastRadius != len(cluster.ClusterFunctions) {
			t.Errorf("Cluster %s: total_blast_radius (%d) should match cluster_functions length (%d)",
				cluster.Name, cluster.TotalBlastRadius, len(cluster.ClusterFunctions))
		}

		// Verify entry points have proper structure
		for _, entry := range cluster.EntryPoints {
			if entry.Function == "" {
				t.Errorf("Cluster %s: entry point should have function name", cluster.Name)
			}
			if len(entry.CalledFrom) == 0 {
				t.Errorf("Cluster %s: entry point %s should have called_from array", cluster.Name, entry.Function)
			}
		}
	}

	// Check that key dependencies were found
	for dep, found := range expectedDeps {
		if !found {
			t.Errorf("Expected dependency cluster for %s was not found", dep)
		}
	}

	// Detailed validation for specific clusters
	for _, cluster := range fbom.DependencyClusters {
		switch cluster.Name {
		case "gopkg.in/yaml.v2":
			// YAML should have specific characteristics
			if len(cluster.EntryPoints) < 3 {
				t.Errorf("yaml.v2 cluster should have at least 3 entry points, got %d", len(cluster.EntryPoints))
			}
			if cluster.TotalBlastRadius < 100 {
				t.Errorf("yaml.v2 cluster should have substantial blast radius (>100), got %d", cluster.TotalBlastRadius)
			}
			t.Logf("yaml.v2 cluster validated: %d entry points, %d blast radius", len(cluster.EntryPoints), cluster.TotalBlastRadius)

		case "github.com/gin-gonic/gin":
			// Gin should have HTTP-related functions
			if len(cluster.EntryPoints) < 2 {
				t.Errorf("gin cluster should have at least 2 entry points, got %d", len(cluster.EntryPoints))
			}
			if cluster.TotalBlastRadius < 50 {
				t.Errorf("gin cluster should have substantial blast radius (>50), got %d", cluster.TotalBlastRadius)
			}
		}
	}

	// Count user functions for validation
	userFunctionCount := 0
	for _, fn := range fbom.Functions {
		// Simple heuristic: user functions are typically from the main package
		if fn.Package == testCase || fn.Package == "main" {
			userFunctionCount++
		}
	}

	t.Logf("Integration test passed: %d clusters, %d user functions", len(fbom.DependencyClusters), userFunctionCount)
}
