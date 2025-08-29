package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"gopkg.in/yaml.v2"
)

// TestVulnerableProjectLiveCVE tests live CVE scanning against the vulnerable project
func TestVulnerableProjectLiveCVE(t *testing.T) {
	// Check if govulncheck is available
	if _, err := exec.LookPath("govulncheck"); err != nil {
		t.Skip("govulncheck not available, skipping CVE integration test")
	}

	// Build the binary using the shared function
	binaryPath := shared.GetBinaryPath(t)

	// Get example project path
	examplePath := filepath.Join("../../examples", "vulnerable-project")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Fatalf("Example project not found: %s", examplePath)
	}

	// Change to the vulnerable project directory for testing
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	if err := os.Chdir(examplePath); err != nil {
		t.Fatalf("Failed to change to example directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Logf("Warning: failed to restore directory: %v", err)
		}
	}()

	// Run FBOM generator with live CVE scanning
	cmd := exec.Command(binaryPath, "--live-cve-scan", "-package", ".")

	// Capture stdout and stderr separately since JSON goes to stdout and CVE info to stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("FBOM generator failed: %v\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	// Parse the FBOM output from stdout (handle potential duplicate JSON objects)
	stdoutStr := stdout.String()

	// Find the first complete JSON object
	decoder := json.NewDecoder(strings.NewReader(stdoutStr))
	var fbom map[string]interface{}
	if err := decoder.Decode(&fbom); err != nil {
		t.Fatalf("Failed to parse FBOM JSON: %v", err)
	}

	// Load expected results (need to go back to integration test directory)
	expectationPath := filepath.Join(originalDir, "testcases", "vulnerable-project", "expected.yaml")
	expectedData, err := os.ReadFile(expectationPath)
	if err != nil {
		t.Fatalf("Failed to read expected results: %v", err)
	}

	var expected map[string]interface{}
	if err := yaml.Unmarshal(expectedData, &expected); err != nil {
		t.Fatalf("Failed to parse expected YAML: %v", err)
	}

	// Validate CVE scanning results
	validateCVEResults(t, fbom, expected)

	t.Log("Vulnerable project live CVE integration test passed")
}

func validateCVEResults(t *testing.T, fbom map[string]interface{}, expected map[string]interface{}) {
	// Get security info from FBOM
	securityInfo, ok := fbom["security_info"].(map[string]interface{})
	if !ok {
		t.Fatal("Missing security_info in FBOM output")
	}

	// Get live CVE assertions from expected results
	assertions, ok := expected["live_cve_assertions"].(map[interface{}]interface{})
	if !ok {
		t.Fatal("Missing live_cve_assertions in expected results")
	}

	// Validate total CVEs found
	if expectedTotal, ok := assertions["total_cves"].(int); ok {
		totalCVEs, ok := securityInfo["total_cves_found"].(float64)
		if !ok {
			t.Error("Missing total_cves_found in security_info")
		} else if int(totalCVEs) != expectedTotal {
			t.Errorf("Expected exactly %d total CVEs, found %d", expectedTotal, int(totalCVEs))
		} else {
			t.Logf("Total CVEs found: %d (matches expected)", int(totalCVEs))
		}
	}

	// Validate reachable CVEs
	if expectedReachable, ok := assertions["reachable_cves"].(int); ok {
		reachableCVEs, ok := securityInfo["total_reachable_cves"].(float64)
		if !ok {
			t.Error("Missing total_reachable_cves in security_info")
		} else if int(reachableCVEs) != expectedReachable {
			t.Errorf("Expected exactly %d reachable CVEs, found %d", expectedReachable, int(reachableCVEs))
		} else {
			t.Logf("Reachable CVEs found: %d (matches expected)", int(reachableCVEs))
		}
	}

	// Validate vulnerable functions exist
	if hasVulnFuncs, ok := assertions["vulnerable_functions_exist"].(bool); ok && hasVulnFuncs {
		vulnFuncs, ok := securityInfo["vulnerable_functions"].([]interface{})
		if !ok || len(vulnFuncs) == 0 {
			t.Error("Expected vulnerable functions but found none")
		} else {
			t.Logf("Found %d vulnerable functions", len(vulnFuncs))
		}
	}

	// Validate user function count (from call_graph.total_functions)
	if expectedUserFuncs, ok := assertions["user_functions_count"].(int); ok {
		callGraph, ok := fbom["call_graph"].(map[string]interface{})
		if !ok {
			t.Error("Missing call_graph in FBOM")
		} else {
			userFuncsCount, ok := callGraph["total_functions"].(float64)
			if !ok {
				t.Error("Missing total_functions in call_graph")
			} else if int(userFuncsCount) != expectedUserFuncs {
				t.Errorf("Expected exactly %d user functions, found %d", expectedUserFuncs, int(userFuncsCount))
			} else {
				t.Logf("User functions count: %d (matches expected)", int(userFuncsCount))
			}
		}
	}
}
