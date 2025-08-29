package bugs

import (
	"os"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug8_CallRelationshipPopulation tests that UsageInfo.Calls is properly populated for all functions
//
// Bug Description:
// Functions were showing calls=null instead of listing the functions they call.
// This made it impossible to see the call relationships from the function perspective,
// only from the call graph edge perspective.
//
// Expected: UsageInfo.Calls should be properly populated for all functions
// Actual (buggy): Functions show calls=null instead of listing the functions they call
func TestBug8_CallRelationshipPopulation(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	server := NewServer()
	server.Start()
}

func NewServer() *Server {
	s := &Server{}
	s.setupRoutes()  // This call should appear in NewServer's UsageInfo.Calls
	s.initialize()   // This call should also appear
	return s
}

type Server struct{}

func (s *Server) Start() {
	fmt.Println("Starting")
	s.healthCheck()  // This call should appear in Start's UsageInfo.Calls
}

func (s *Server) setupRoutes() {
	fmt.Println("Setting up routes")
	helperFunction()  // This call should appear in setupRoutes's UsageInfo.Calls
	
	// Anonymous function call
	anonymousFunc := func() {
		anotherHelper()
	}
	anonymousFunc()
}

func (s *Server) initialize() {
	fmt.Println("Initializing")
}

func (s *Server) healthCheck() {
	fmt.Println("Health check")
}

func helperFunction() {
	fmt.Println("Helper function")
}

func anotherHelper() {
	fmt.Println("Another helper")
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

	// Debug: Show all functions and their calls
	t.Logf("Bug 8 Debug - Function calls:")
	functionCalls := make(map[string][]string)
	for _, fn := range fbom.Functions {
		functionCalls[fn.Name] = fn.UsageInfo.Calls
		t.Logf("  %s calls: %v", fn.Name, fn.UsageInfo.Calls)
	}

	// Expected call relationships
	expectedCalls := map[string][]string{
		"main":           {"NewServer", "Start"},
		"NewServer":      {"setupRoutes", "initialize"},
		"Start":          {"healthCheck"},
		"setupRoutes":    {"helperFunction"}, // Note: anonymous function calls might be represented differently
		"initialize":     {},
		"healthCheck":    {},
		"helperFunction": {},
		"anotherHelper":  {},
	}

	// Test that UsageInfo.Calls is populated (not null)
	for _, fn := range fbom.Functions {
		// Debug the actual value
		t.Logf("Bug 8 Debug - Function %s: Calls=%v, len=%d, isNil=%t", fn.Name, fn.UsageInfo.Calls, len(fn.UsageInfo.Calls), fn.UsageInfo.Calls == nil)
		if fn.UsageInfo.Calls == nil {
			t.Errorf("Bug 8 - Function %s has calls=null, should have empty array or populated calls", fn.Name)
		}
	}

	// Test specific expected call relationships
	for funcName, expectedCallees := range expectedCalls {
		actualCalls := functionCalls[funcName]
		if actualCalls == nil {
			t.Errorf("Bug 8 - Function %s has no calls data (null)", funcName)
			continue
		}

		// For functions that should make calls, verify they're recorded
		if len(expectedCallees) > 0 {
			if len(actualCalls) == 0 {
				t.Errorf("Bug 8 - Function %s should call %v but has no calls recorded", funcName, expectedCallees)
			} else {
				// Check that expected calls are present
				for _, expectedCallee := range expectedCallees {
					found := false
					for _, actualCall := range actualCalls {
						if strings.Contains(actualCall, expectedCallee) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Bug 8 - Function %s should call %s but it's not in calls list: %v", funcName, expectedCallee, actualCalls)
					}
				}
			}
		}
	}
}
