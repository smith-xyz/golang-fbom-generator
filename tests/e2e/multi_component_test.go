package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"
)

// TestMultiComponentProjectExplicitPackage tests explicit package analysis on multi-component projects
func TestMultiComponentProjectExplicitPackage(t *testing.T) {
	binaryPath := shared.GetBinaryPath(t)

	// Verify the multi-component project exists
	projectPath := filepath.Join("../../examples", "multi-component-project")
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		t.Skipf("Multi-component project not found at %s, skipping explicit package test", projectPath)
	}

	// Test explicit package analysis
	cmd := exec.Command(binaryPath, "github.com/example/multi-component-project/cmd/cli", "-algo", "rta")
	cmd.Dir = projectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run with explicit package name: %v\nOutput: %s", err, output)
	}

	// Just verify it doesn't fail - the actual validation is done by the main integration test
	// which runs automatically via the testcases/multi-component-project/expected.yaml
	t.Log("Multi-component project explicit package test passed (context-aware fix validated)")
}

// TestMultiComponentProjectAutoDiscovery tests the auto-discovery functionality
func TestMultiComponentProjectAutoDiscovery(t *testing.T) {
	// Build the binary first
	binaryPath := shared.GetBinaryPath(t)

	// Verify the multi-component project exists
	projectPath := filepath.Join("../../examples", "multi-component-project")
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		t.Skipf("Multi-component project not found at %s, skipping auto-discovery test", projectPath)
	}

	// Test auto-discovery mode (output FBOM JSON to stdout)
	cmd := exec.Command(binaryPath, "--auto-discover", "-algo", "rta", "-v")
	cmd.Dir = projectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run with auto-discovery: %v\nOutput: %s", err, output)
	}

	// Verify key indicators of successful auto-discovery in stderr
	outputStr := string(output)
	if !strings.Contains(outputStr, "Discovered 6 main functions") {
		t.Errorf("Expected 'Discovered 6 main functions' in output, got: %s", outputStr)
	}

	if !strings.Contains(outputStr, "Performing unified analysis of module: github.com/example/multi-component-project/...") {
		t.Errorf("Expected unified analysis message in output, got: %s", outputStr)
	}

	// Validate FBOM structure by checking for key patterns (much simpler than full JSON parsing)
	if !strings.Contains(outputStr, `"call_graph"`) {
		t.Error("Expected call_graph in FBOM output")
	}

	if !strings.Contains(outputStr, `"total_functions": 55`) {
		t.Errorf("Expected 'total_functions: 55' from unified analysis in FBOM output, got: %s", outputStr)
	} else {
		t.Log("✅ Auto-discovery found expected 55 user functions from unified analysis")
	}

	t.Log("Multi-component project auto-discovery test passed")
}
