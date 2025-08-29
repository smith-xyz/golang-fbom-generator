package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug6_UnusedFunctionInclusion tests that unused functions are included in FBOM
//
// Bug Description:
// Unused standalone functions were not being added to the FBOM at all. This made it impossible
// to get a complete picture of all functions in a codebase, which is important for security
// analysis and code coverage metrics.
//
// Expected: Even unreachable functions should exist in the FBOM with distance -1 and reachable=false
// Actual (buggy): Unused functions were completely omitted from the FBOM
func TestBug6_UnusedFunctionInclusion(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world")
}

// This function is never called and should still appear in FBOM
func unusedStandaloneFunction() {
	fmt.Println("This is never called")
}

// This function is also never called
func anotherUnusedFunction(x int) string {
	return fmt.Sprintf("Value: %d", x)
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

	// Debug: Print all functions found
	t.Logf("Bug 6 Debug - All functions found in FBOM:")
	functionNames := make(map[string]bool)
	for _, fn := range fbom.Functions {
		functionNames[fn.Name] = true
		t.Logf("  %s: reachable=%t, distance=%d, type=%s", fn.Name, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry, fn.UsageInfo.ReachabilityType)
	}

	expectedUnusedFunctions := []string{"unusedStandaloneFunction", "anotherUnusedFunction"}

	for _, funcName := range expectedUnusedFunctions {
		if !functionNames[funcName] {
			t.Errorf("Bug 6 - Unused function %s is missing from FBOM, should be included with reachable=false", funcName)
		}
	}

	// Also verify their properties if they exist
	for _, fn := range fbom.Functions {
		if fn.Name == "unusedStandaloneFunction" || fn.Name == "anotherUnusedFunction" {
			if fn.UsageInfo.IsReachable {
				t.Errorf("Bug 6 - Unused function %s should have IsReachable=false", fn.Name)
			}
			if fn.UsageInfo.DistanceFromEntry != -1 {
				t.Errorf("Bug 6 - Unused function %s should have DistanceFromEntry=-1, got %d", fn.Name, fn.UsageInfo.DistanceFromEntry)
			}
			if fn.UsageInfo.ReachabilityType != "unreachable" {
				t.Errorf("Bug 6 - Unused function %s should have ReachabilityType='unreachable', got '%s'", fn.Name, fn.UsageInfo.ReachabilityType)
			}
		}
	}
}
