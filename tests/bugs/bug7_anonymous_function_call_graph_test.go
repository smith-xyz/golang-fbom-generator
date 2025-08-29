package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug7_AnonymousFunctionCallGraph tests that anonymous functions are tracked in call graph
//
// Bug Description:
// Anonymous functions were not being added to the call graph, making it impossible to track
// calls that happen through anonymous function execution. This created blind spots in the
// analysis where function calls through anonymous functions were not visible.
//
// Expected: Anonymous functions should be tracked and their calls should be visible in call graph
// Actual (buggy): Anonymous functions were completely invisible in the call graph
func TestBug7_AnonymousFunctionCallGraph(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	// Anonymous function that calls dummyFunction
	anonymousFunc := func() {
		fmt.Println("In anonymous function")
		dummyFunction()
	}
	
	// Execute the anonymous function
	anonymousFunc()
	
	// Also test inline anonymous function
	func() {
		fmt.Println("Inline anonymous")
		anotherDummyFunction()
	}()
}

func dummyFunction() {
	fmt.Println("Dummy function called")
}

func anotherDummyFunction() {
	fmt.Println("Another dummy function called")
}

// This function should be unreachable since no anonymous function calls it
func unreachableFunction() {
	fmt.Println("This should not be reachable")
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

	// Debug: List all functions found
	t.Logf("Bug 7 Debug - All functions in FBOM:")
	functionNames := make(map[string]bool)
	reachableFunctions := make(map[string]bool)
	for _, fn := range fbom.Functions {
		functionNames[fn.Name] = true
		if fn.UsageInfo.IsReachable {
			reachableFunctions[fn.Name] = true
		}
		t.Logf("  %s: reachable=%t, distance=%d", fn.Name, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
	}

	// Debug: List call graph edges
	t.Logf("Bug 7 Debug - Call graph edges:")
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("  %s -> %s", edge.Caller, edge.Callee)
	}

	// Test 1: dummyFunction should be reachable (called by anonymous function)
	if !reachableFunctions["dummyFunction"] {
		t.Errorf("Bug 7 - dummyFunction should be reachable via anonymous function call")
	}

	// Test 2: anotherDummyFunction should be reachable (called by inline anonymous function)
	if !reachableFunctions["anotherDummyFunction"] {
		t.Errorf("Bug 7 - anotherDummyFunction should be reachable via inline anonymous function call")
	}

	// Test 3: unreachableFunction should NOT be reachable
	if reachableFunctions["unreachableFunction"] {
		t.Errorf("Bug 7 - unreachableFunction should NOT be reachable")
	}

	// Test 4: Check that call edges exist for anonymous function calls
	// We should see edges that show the flow through anonymous functions
	dummyFunctionReachableFromMain := false
	anotherDummyReachableFromMain := false

	// Look for any path that shows these functions are reachable from main
	// This might be through anonymous functions or direct edges
	for _, edge := range fbom.CallGraph.CallEdges {
		if edge.Callee == "testmodule.dummyFunction" {
			dummyFunctionReachableFromMain = true
		}
		if edge.Callee == "testmodule.anotherDummyFunction" {
			anotherDummyReachableFromMain = true
		}
	}

	if !dummyFunctionReachableFromMain {
		t.Errorf("Bug 7 - No call edge found for dummyFunction (should be reachable through anonymous function)")
	}

	if !anotherDummyReachableFromMain {
		t.Errorf("Bug 7 - No call edge found for anotherDummyFunction (should be reachable through anonymous function)")
	}
}
