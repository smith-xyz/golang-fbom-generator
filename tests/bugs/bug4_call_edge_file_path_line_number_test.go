package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug4_CallEdgeFilePathAndLineNumber tests that call edges include file path and line number
//
// Bug Description:
// The call graph file path and line number were not being set correctly for call edges.
// This made it difficult to trace where specific function calls originated in the source code.
//
// Expected: Each call edge should have the file_path and line_number where the call occurs
// Actual (buggy): Call edges had empty file_path and 0 line_number values
func TestBug4_CallEdgeFilePathAndLineNumber(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world!")
	helper() // This call should have file path and line number
}

func helper() {
	// Helper function
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

	// Find the call edge from main to helper
	var foundCallEdge bool
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("Call edge: %s -> %s (file: %s, line: %d)", edge.Caller, edge.Callee, edge.FilePath, edge.LineNumber)

		if edge.Caller == "testmodule.main" && edge.Callee == "testmodule.helper" {
			foundCallEdge = true

			// Bug: file_path should not be empty
			if edge.FilePath == "" {
				t.Error("Bug 4 - Call edge file_path is empty, should contain the file path")
			}

			// Bug: line_number should not be 0 (should be around line 8 where helper() is called)
			if edge.LineNumber == 0 {
				t.Error("Bug 4 - Call edge line_number is 0, should contain the line number where the call occurs")
			}

			break
		}
	}

	if !foundCallEdge {
		t.Error("Bug 4 - Call edge from main to helper not found")
	}
}
