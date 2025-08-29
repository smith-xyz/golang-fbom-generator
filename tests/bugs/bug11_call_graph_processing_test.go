package bugs

import (
	"os"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug11_CallGraphProcessing tests that call graph edges are properly processed and matched to our functions
//
// Bug Description:
// Call graph edges were not being properly processed and matched to FBOM functions.
// This reproduces the issue where NewServer -> setupRoutes exists in callgraph CLI but not in our FBOM.
// The raw call graph from golang.org/x/tools would have the edge, but it wouldn't appear in the final FBOM.
//
// Expected: Call graph edges should be properly processed and appear in FBOM call graph
// Actual (buggy): Call edges were missing from FBOM even when present in raw call graph
func TestBug11_CallGraphProcessing(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	server := NewServer()
	server.Start()
}

func NewServer() *Server {
	s := &Server{}
	s.setupRoutes()  // This should create edge: NewServer -> setupRoutes  
	return s
}

type Server struct{}

func (s *Server) Start() {
	fmt.Println("Starting")
}

func (s *Server) setupRoutes() {
	fmt.Println("Setting up routes")
	// Anonymous function calling another function
	anonymousFunc := func() {
		dummyFunction()
	}
	anonymousFunc()
}

func dummyFunction() {
	fmt.Println("Dummy function")
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

	// Debug: Show what the raw call graph contains
	t.Logf("Bug 11 Debug - Raw call graph edges from golang.org/x/tools:")
	for fn, node := range callGraph.Nodes {
		if fn != nil && node != nil {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					t.Logf("  %s -> %s", fn.String(), edge.Callee.Func.String())
				}
			}
		}
	}

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Show what our FBOM call edges contain
	t.Logf("Bug 11 Debug - FBOM call graph edges:")
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("  %s -> %s", edge.Caller, edge.Callee)
	}

	// Debug: Show function names and IDs we generated
	t.Logf("Bug 11 Debug - Function names and IDs:")
	functionsByName := make(map[string]string) // name -> fullID
	for _, fn := range fbom.Functions {
		functionsByName[fn.Name] = fn.FullName
		t.Logf("  %s: fullName='%s'", fn.Name, fn.FullName)
	}

	// Test 1: Check that both functions exist in our FBOM
	if _, exists := functionsByName["NewServer"]; !exists {
		t.Errorf("Bug 11 - NewServer function not found in FBOM")
	}
	if _, exists := functionsByName["setupRoutes"]; !exists {
		t.Errorf("Bug 11 - setupRoutes function not found in FBOM")
	}

	// Test 2: Check that the call edge exists in raw call graph
	newServerToSetupRoutesInRaw := false
	for fn, node := range callGraph.Nodes {
		if fn != nil && node != nil && strings.Contains(fn.String(), "NewServer") {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil &&
					strings.Contains(edge.Callee.Func.String(), "setupRoutes") {
					newServerToSetupRoutesInRaw = true
					t.Logf("Bug 11 - Found raw edge: %s -> %s", fn.String(), edge.Callee.Func.String())
					break
				}
			}
		}
	}

	if !newServerToSetupRoutesInRaw {
		t.Errorf("Bug 11 - NewServer -> setupRoutes edge missing from raw call graph")
	}

	// Test 3: Check that the call edge exists in our FBOM call graph
	newServerToSetupRoutesInFBOM := false
	for _, edge := range fbom.CallGraph.CallEdges {
		if strings.Contains(edge.Caller, "NewServer") && strings.Contains(edge.Callee, "setupRoutes") {
			newServerToSetupRoutesInFBOM = true
			break
		}
	}

	if !newServerToSetupRoutesInFBOM {
		t.Errorf("Bug 11 - NewServer -> setupRoutes edge missing from FBOM call graph")
		t.Logf("Bug 11 - This means our call graph processing is not working correctly")
	}

	// Test 4: Check function reachability (should be correct if call edges are correct)
	setupRoutesReachable := false
	for _, fn := range fbom.Functions {
		if fn.Name == "setupRoutes" {
			setupRoutesReachable = fn.UsageInfo.IsReachable
			t.Logf("Bug 11 - setupRoutes reachable: %t, distance: %d", fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
			break
		}
	}

	if !setupRoutesReachable {
		t.Errorf("Bug 11 - setupRoutes should be reachable if call edge processing works correctly")
	}
}
