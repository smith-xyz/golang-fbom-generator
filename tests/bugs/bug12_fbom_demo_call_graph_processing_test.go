package bugs

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug12_FbomDemoCallGraphProcessing tests call graph processing with a realistic demo-like structure
//
// Bug Description:
// Real-world call graph processing was failing in the fbom-demo project where
// NewServer -> setupRoutes exists in the raw call graph CLI but not in our FBOM.
// This could be due to package filtering, method resolution, or other complex call patterns.
//
// Expected: Complex call patterns (like methods, anonymous functions, package boundaries) should be processed correctly
// Actual (buggy): Some call edges were missing from FBOM even when present in raw call graph
func TestBug12_FbomDemoCallGraphProcessing(t *testing.T) {
	testCode := `
package main

import (
	"fmt"
	"net/http"
)

func main() {
	server := NewServer()
	server.Start()
}

func NewServer() *Server {
	s := &Server{}
	s.setupRoutes()  // This should create edge: NewServer -> setupRoutes  
	return s
}

type Server struct {
	mux *http.ServeMux
}

func (s *Server) Start() {
	fmt.Println("Starting server")
	s.handleRequests() // Method call within same struct
}

func (s *Server) setupRoutes() {
	fmt.Println("Setting up routes")
	s.mux = http.NewServeMux()
	
	// Anonymous function that calls another method
	handler := func() {
		s.logRequest()
	}
	
	// Simulate route registration
	if s.mux != nil {
		handler() // Call the anonymous function
	}
	
	// Call to external package function
	s.validateConfig()
}

func (s *Server) handleRequests() {
	fmt.Println("Handling requests")
	s.processRequest()
}

func (s *Server) processRequest() {
	fmt.Println("Processing request")
}

func (s *Server) logRequest() {
	fmt.Println("Logging request")
	// Call to helper function
	dummyFunction()
}

func (s *Server) validateConfig() {
	fmt.Println("Validating config")
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

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create the generator in the context of the temporary module
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Show what the raw call graph contains
	t.Logf("Bug 12 Debug - Raw call graph edges from golang.org/x/tools:")
	rawEdges := []string{}
	for fn, node := range callGraph.Nodes {
		if fn != nil && node != nil {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					edgeStr := fmt.Sprintf("%s -> %s", fn.String(), edge.Callee.Func.String())
					rawEdges = append(rawEdges, edgeStr)
					t.Logf("  %s", edgeStr)
				}
			}
		}
	}

	// Debug: Show what our FBOM call edges contain
	t.Logf("Bug 12 Debug - FBOM call graph edges:")
	fbomEdges := []string{}
	for _, edge := range fbom.CallGraph.CallEdges {
		edgeStr := fmt.Sprintf("%s -> %s", edge.Caller, edge.Callee)
		fbomEdges = append(fbomEdges, edgeStr)
		t.Logf("  %s", edgeStr)
	}

	// Debug: Show total edge counts
	t.Logf("Bug 12 Debug - Raw edges count: %d, FBOM edges count: %d", len(rawEdges), len(fbomEdges))

	// Test 1: Critical call edges should be preserved
	criticalEdges := map[string]string{
		"NewServer -> setupRoutes":         "testmodule.NewServer|testmodule.setupRoutes",
		"setupRoutes -> setupRoutes$1":     "testmodule.setupRoutes|testmodule.setupRoutes$1", // anonymous function
		"setupRoutes$1 -> logRequest":      "testmodule.setupRoutes$1|testmodule.logRequest",  // anonymous calls logRequest
		"logRequest -> dummyFunction":      "testmodule.logRequest|testmodule.dummyFunction",
		"Start -> handleRequests":          "testmodule.Start|testmodule.handleRequests",
		"handleRequests -> processRequest": "testmodule.handleRequests|testmodule.processRequest",
	}

	for description, edgePattern := range criticalEdges {
		found := false
		for _, fbomEdge := range fbomEdges {
			if containsEdgePattern(fbomEdge, edgePattern) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Bug 12 - Critical edge missing: %s", description)
			t.Logf("Bug 12 - Looking for pattern: %s", edgePattern)
		}
	}

	// Test 2: Check that methods are properly reachable
	methodReachability := map[string]bool{
		"setupRoutes":    true,
		"handleRequests": true,
		"processRequest": true,
		"logRequest":     true,
		"validateConfig": true,
		"dummyFunction":  true,
	}

	for methodName, expectedReachable := range methodReachability {
		found := false
		for _, fn := range fbom.Functions {
			if fn.Name == methodName {
				found = true
				if fn.UsageInfo.IsReachable != expectedReachable {
					t.Errorf("Bug 12 - Method %s reachability: expected %t, got %t",
						methodName, expectedReachable, fn.UsageInfo.IsReachable)
				}
				if expectedReachable && fn.UsageInfo.DistanceFromEntry == -1 {
					t.Errorf("Bug 12 - Method %s should have valid distance, got -1", methodName)
				}
				break
			}
		}
		if !found {
			t.Errorf("Bug 12 - Method %s not found in FBOM", methodName)
		}
	}
}

// Helper function to check if a FBOM edge matches an expected pattern
func containsEdgePattern(fbomEdge, pattern string) bool {
	// Pattern format: "caller|callee", fbomEdge format: "caller -> callee"
	// Split the pattern and fbomEdge to compare components
	parts := strings.Split(pattern, "|")
	if len(parts) != 2 {
		return false
	}

	expectedCaller := strings.TrimSpace(parts[0])
	expectedCallee := strings.TrimSpace(parts[1])

	// Split the FBOM edge on " -> "
	edgeParts := strings.Split(fbomEdge, " -> ")
	if len(edgeParts) != 2 {
		return false
	}

	actualCaller := strings.TrimSpace(edgeParts[0])
	actualCallee := strings.TrimSpace(edgeParts[1])

	return actualCaller == expectedCaller && actualCallee == expectedCallee
}
