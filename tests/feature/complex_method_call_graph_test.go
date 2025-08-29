package feature

import (
	"os"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestComplexMethodCallGraph tests method detection in a more complex scenario similar to fbom-demo
func TestComplexMethodCallGraph(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	runServer()
}

func runServer() {
	server := NewServer()
	server.Start()
}

func NewServer() *Server {
	s := &Server{name: "test"}
	s.setupRoutes()  // This call should be detected
	return s
}

type Server struct {
	name string
}

func (s *Server) Start() {
	fmt.Println("Server starting")
}

func (s *Server) setupRoutes() {
	fmt.Println("Setting up routes")
	
	// Anonymous function calling another function
	anonymousFunc := func() bool {
		return dummyFunction()
	}
	
	result := anonymousFunc()
	if !result {
		fmt.Println("Anonymous function failed")
	}
}

func dummyFunction() bool {
	fmt.Println("Dummy function called")
	return true
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

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create the generator in the context of the temporary module
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: List all functions and their reachability
	t.Logf("Complex Method Test - All functions:")
	functionReachability := make(map[string]bool)
	for _, fn := range fbom.Functions {
		functionReachability[fn.Name] = fn.UsageInfo.IsReachable
		t.Logf("  %s: reachable=%t, distance=%d", fn.Name, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
	}

	// Debug: List call graph edges
	t.Logf("Complex Method Test - Call edges:")
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("  %s -> %s", edge.Caller, edge.Callee)
	}

	// Key test: setupRoutes should be reachable (called by NewServer)
	if !functionReachability["setupRoutes"] {
		t.Errorf("setupRoutes should be reachable (called by NewServer)")
	}

	// Key test: dummyFunction should be reachable (called by anonymous function in setupRoutes)
	if !functionReachability["dummyFunction"] {
		t.Errorf("dummyFunction should be reachable (called by anonymous function in setupRoutes)")
	}

	// Check for the critical call edge: NewServer -> setupRoutes
	newServerToSetupRoutes := false
	for _, edge := range fbom.CallGraph.CallEdges {
		if extractFunctionName(edge.Caller) == "NewServer" && extractFunctionName(edge.Callee) == "setupRoutes" {
			newServerToSetupRoutes = true
			break
		}
	}
	if !newServerToSetupRoutes {
		t.Errorf("Expected call edge NewServer -> setupRoutes not found")
	}

	// Check for anonymous function call chain: setupRoutes -> anonymous -> dummyFunction
	setupRoutesToAnonymous := false
	anonymousToDummy := false
	for _, edge := range fbom.CallGraph.CallEdges {
		caller := extractFunctionName(edge.Caller)
		callee := extractFunctionName(edge.Callee)

		if caller == "setupRoutes" && strings.Contains(edge.Callee, "$") {
			setupRoutesToAnonymous = true
		}
		if strings.Contains(edge.Caller, "$") && callee == "dummyFunction" {
			anonymousToDummy = true
		}
	}

	if !setupRoutesToAnonymous {
		t.Logf("WARNING: setupRoutes -> anonymous function call not detected")
	}
	if !anonymousToDummy {
		t.Logf("WARNING: anonymous function -> dummyFunction call not detected")
	}
}
