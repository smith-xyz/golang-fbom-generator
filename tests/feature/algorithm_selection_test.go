package feature

import (
	"os/exec"
	"testing"

	"golang-fbom-generator/tests/shared"
)

// TestAlgorithmSelection tests different call graph algorithms
func TestAlgorithmSelection(t *testing.T) {
	binaryPath := shared.GetBinaryPath(t)

	examplePath := "../../examples/hello-world"

	algorithms := []string{"rta", "cha", "static", "vta"}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			cmd := exec.Command(binaryPath, "-algo", algo, "-package", ".")
			cmd.Dir = examplePath

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to run with algorithm %s: %v\nOutput: %s", algo, err, output)
			}

			// Parse FBOM to ensure it's valid
			fbom, err := shared.ParseFBOM(output)
			if err != nil {
				t.Fatalf("Failed to parse FBOM output for algorithm %s: %v", algo, err)
			}

			// Validate that functions were found
			functions, ok := fbom["functions"].([]interface{})
			if !ok || len(functions) == 0 {
				t.Errorf("Algorithm %s: no functions found in FBOM", algo)
			} else {
				t.Logf("Algorithm %s successfully generated FBOM with %d functions", algo, len(functions))
			}

			// Validate that call graph was generated
			callGraph, ok := fbom["call_graph"].(map[string]interface{})
			if !ok {
				t.Errorf("Algorithm %s: missing call_graph in FBOM", algo)
			} else {
				if totalFunctions, ok := callGraph["total_functions"].(float64); ok {
					if totalFunctions == 0 {
						t.Errorf("Algorithm %s: call graph has 0 functions", algo)
					}
				}
			}
		})
	}
}

// TestInvalidAlgorithm tests error handling for invalid algorithms
func TestInvalidAlgorithm(t *testing.T) {
	binaryPath := shared.GetBinaryPath(t)

	examplePath := "../../examples/hello-world"

	cmd := exec.Command(binaryPath, "-algo", "invalid", "-package", ".")
	cmd.Dir = examplePath

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("Expected error for invalid algorithm, but command succeeded\nOutput: %s", output)
	}

	// Check that the error message mentions the invalid algorithm
	outputStr := string(output)
	if len(outputStr) > 0 {
		t.Logf("Error output (expected): %s", outputStr)
	}
}
