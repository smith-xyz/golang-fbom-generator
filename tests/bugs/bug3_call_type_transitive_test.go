package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug3_CallTypeTransitive tests that call edges are correctly marked as transitive
//
// Bug Description:
// The callgraph call edges properties call_type incorrectly marked a transitive function as a direct call.
// Functions that are called through multiple hops from entry points should be marked as "transitive".
//
// Expected: Calls should be marked as "transitive" when they are to functions at distance 2+ from entry points
// Actual (buggy): All calls were being marked as "direct" regardless of their distance from entry points
func TestBug3_CallTypeTransitive(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world!")
	directCall()
}

func directCall() {
	transitiveCall()
}

func transitiveCall() {
	// This is called transitively: main -> directCall -> transitiveCall
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

	// Find the call edge from directCall to transitiveCall
	var foundTransitiveCallEdge bool
	var foundDirectCallEdge bool

	for _, edge := range fbom.CallGraph.CallEdges {
		// Debug logging
		t.Logf("Call edge: %s -> %s (type: %s)", edge.Caller, edge.Callee, edge.CallType)

		if edge.Caller == "testmodule.directCall" && edge.Callee == "testmodule.transitiveCall" {
			foundTransitiveCallEdge = true
			// Bug: This should be marked as "transitive" because transitiveCall is at distance 2 from main
			expectedCallType := "transitive"
			if edge.CallType != expectedCallType {
				t.Errorf("Bug 3 - Call type incorrect for transitive call: expected %q, got %q", expectedCallType, edge.CallType)
			}
		}

		if edge.Caller == "testmodule.main" && edge.Callee == "testmodule.directCall" {
			foundDirectCallEdge = true
			// This should be marked as "direct" because directCall is at distance 1 from main
			expectedCallType := "direct"
			if edge.CallType != expectedCallType {
				t.Errorf("Bug 3 - Call type incorrect for direct call: expected %q, got %q", expectedCallType, edge.CallType)
			}
		}
	}

	if !foundTransitiveCallEdge {
		t.Errorf("Bug 3 - Transitive call edge not found: directCall -> transitiveCall")
	}

	if !foundDirectCallEdge {
		t.Errorf("Bug 3 - Direct call edge not found: main -> directCall")
	}
}
