package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug5_ReachableFunctionsCount tests that ReachableFunctions counts actual reachable functions
//
// Bug Description:
// ReachableFunctions was defaulting to 1, instead of calculating the actual number of functions
// reachable from entry points. This made the FBOM metrics inaccurate.
//
// Expected: Should calculate the actual number of functions reachable from entry points
// Actual (buggy): ReachableFunctions always defaulted to 1
func TestBug5_ReachableFunctionsCount(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world! Sum of 1 and 2 is", sum(1, 2))
	fmt.Println("Hello world! Transitive multiplication of 1 and 2 is", multiplication(1, 2))
}

// This function is called directly by the main function
func sum(a int, b int) int {
	return a + b
}

// This function is called directly by the main function
func multiplication(a int, b int) int {
	return transitiveMultiplication(a, b)
}

// This function is called transitively by the multiplication function
func transitiveMultiplication(a int, b int) int {
	return a * b
}

func notCalled() {
	fmt.Println("This function is not called")
}
`

	callGraph, ssaProgram, tmpDir, err := shared.BuildCallGraphFromCodeWithDir(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory and change to test module directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change to test directory: %v", err)
	}

	// Create the generator in the context of the temporary module
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Expected reachable functions: main, sum, multiplication, transitiveMultiplication, init = 5
	// Note: "notCalled" should NOT be counted as reachable, but init is reachable
	expectedReachableFunctions := 5
	actualReachableFunctions := fbom.CallGraph.ReachableFunctions

	if actualReachableFunctions != expectedReachableFunctions {
		t.Errorf("Bug 5 - Reachable functions count incorrect: expected %d, got %d", expectedReachableFunctions, actualReachableFunctions)

		// Debug: Print all functions and their reachability
		t.Logf("Functions found in FBOM:")
		for _, fn := range fbom.Functions {
			t.Logf("  %s (reachable: %t, distance: %d)", fn.Name, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
		}
	}

	// Verify that the unreachable function is not counted in reachable functions
	var notCalledFunction *models.Function
	for _, fn := range fbom.Functions {
		if fn.Name == "notCalled" {
			notCalledFunction = &fn
			break
		}
	}

	if notCalledFunction != nil && notCalledFunction.UsageInfo.IsReachable {
		t.Errorf("Bug 5 - Function 'notCalled' should not be marked as reachable")
	}
}
