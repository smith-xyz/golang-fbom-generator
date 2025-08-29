package feature

import (
	"os"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestMethodCallGraph tests that method calls are properly represented in the call graph
func TestMethodCallGraph(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	server := NewServer()
	server.Start()
}

func NewServer() *Server {
	return &Server{}
}

type Server struct{}

func (s *Server) Start() {
	fmt.Println("Starting...")
	s.setupRoutes()
}

func (s *Server) setupRoutes() {
	fmt.Println("Setting up routes")
	// Anonymous function that calls another method
	handler := func() {
		s.handleRequest()
	}
	handler()
}

func (s *Server) handleRequest() {
	fmt.Println("Handling request")
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

	// Debug: List call graph edges
	t.Logf("Method Call Graph Test - Call edges:")
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("  %s -> %s", edge.Caller, edge.Callee)
	}

	// Expected call relationships (note: anonymous functions create intermediate steps)
	expectedCallEdges := map[string][]string{
		"main":      {"NewServer", "Start"},
		"NewServer": {},
		"Start":     {"setupRoutes"},
		// setupRoutes -> setupRoutes$1 -> handleRequest (anonymous function creates intermediate step)
	}

	// Check that expected call edges exist
	actualEdges := make(map[string][]string)
	for _, edge := range fbom.CallGraph.CallEdges {
		// Extract just the function name from full identifiers
		callerName := extractFunctionName(edge.Caller)
		calleeName := extractFunctionName(edge.Callee)
		actualEdges[callerName] = append(actualEdges[callerName], calleeName)
	}

	for caller, expectedCallees := range expectedCallEdges {
		actualCallees := actualEdges[caller]
		for _, expectedCallee := range expectedCallees {
			found := false
			for _, actualCallee := range actualCallees {
				if actualCallee == expectedCallee {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected call edge %s -> %s not found", caller, expectedCallee)
				t.Logf("Actual callees for %s: %v", caller, actualCallees)
			}
		}
	}

	// Test that handleRequest is reachable through the call chain
	handleRequestFound := false
	for _, fn := range fbom.Functions {
		if fn.Name == "handleRequest" {
			handleRequestFound = true
			if !fn.UsageInfo.IsReachable {
				t.Errorf("handleRequest should be reachable (called through anonymous function)")
			}
			if fn.UsageInfo.DistanceFromEntry != 4 {
				t.Errorf("handleRequest should have distance 4 (main->Start->setupRoutes->setupRoutes$1->handleRequest), got %d", fn.UsageInfo.DistanceFromEntry)
			}
			break
		}
	}
	if !handleRequestFound {
		t.Errorf("handleRequest method not found in FBOM")
	}
}

// Helper function to extract function name from full identifier
func extractFunctionName(fullName string) string {
	// Handle cases like "testmodule.main", "testmodule.(*Server).Start", etc.
	parts := strings.Split(fullName, ".")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		// Remove receiver type info like "(*Server)"
		if strings.Contains(lastPart, ")") {
			return lastPart[strings.LastIndex(lastPart, ")")+1:]
		}
		return lastPart
	}
	return fullName
}
