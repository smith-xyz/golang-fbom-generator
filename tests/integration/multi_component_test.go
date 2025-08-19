package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMultiComponentProjectExplicitPackage tests the context-aware fix using explicit package name
// This is a separate test that validates the context-aware configuration fix
func TestMultiComponentProjectExplicitPackage(t *testing.T) {
	// Build the binary first
	binaryPath := buildBinary(t)
	defer os.Remove(binaryPath)

	// Verify the multi-component project exists
	projectPath := filepath.Join("..", "..", "examples", "multi-component-project")
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		t.Skipf("Multi-component project not found at %s, skipping explicit package test", projectPath)
	}

	// Test explicit package name (tests context-aware fix)
	// This was broken before our context-aware configuration fix
	cmd := exec.Command(binaryPath, "-package", "github.com/example/multi-component-project", "-algo", "rta")
	cmd.Dir = projectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run with explicit package name: %v\nOutput: %s", err, output)
	}

	// Just verify it doesn't fail - the actual validation is done by the main integration test
	// which runs automatically via the testcases/multi-component-project/expected.yaml
	t.Log("Multi-component project explicit package test passed (context-aware fix validated)")
}
