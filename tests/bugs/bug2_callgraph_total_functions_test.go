package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug2_CallGraphTotalFunctions tests that call graph counts all functions including uncalled ones
//
// Bug Description:
// The callgraph total_function count was incorrect when adding new uncalled functions to a project.
// The count would not include standalone functions that were not called by any entry point.
//
// Expected: Should count all user-defined functions, including unreachable ones
// Actual (buggy): Only counted functions reachable from entry points
func TestBug2_CallGraphTotalFunctions(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world!")
	called()
}

func called() {
	// This function is called
}

func notCalled() {
	// This function is NOT called - but should still be counted
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

	// Count expected user functions: main, called, notCalled, init = 4
	// Note: init functions are automatically created by Go
	expectedFunctionCount := 4
	actualFunctionCount := fbom.CallGraph.TotalFunctions

	if actualFunctionCount != expectedFunctionCount {
		t.Errorf("Bug 2 - Call graph total functions incorrect: expected %d, got %d", expectedFunctionCount, actualFunctionCount)

		// Debug: Print all functions found
		t.Logf("Functions found in FBOM:")
		for _, fn := range fbom.Functions {
			t.Logf("  %s", fn.Name)
		}
	}

	// Also verify the functions list includes the uncalled function
	var foundNotCalled bool
	for _, fn := range fbom.Functions {
		if fn.Name == "notCalled" {
			foundNotCalled = true
			break
		}
	}

	if !foundNotCalled {
		t.Errorf("Bug 2 - Uncalled function 'notCalled' not included in FBOM functions list")
	}
}
