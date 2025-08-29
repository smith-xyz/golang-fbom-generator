package feature

import (
	"golang-fbom-generator/tests/shared"
	"os"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestMethodDetection tests that struct methods are properly detected and included in FBOM
func TestMethodDetection(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	server := &Server{name: "test"}
	server.Start()
	server.setupRoutes()
}

type Server struct {
	name string
}

func (s *Server) Start() {
	fmt.Println("Server starting:", s.name)
	s.initialize()
}

func (s *Server) setupRoutes() {
	fmt.Println("Setting up routes")
	s.addHealthCheck()
}

func (s *Server) initialize() {
	fmt.Println("Initializing server")
}

func (s *Server) addHealthCheck() {
	fmt.Println("Adding health check")
}

// Unused method that should still be detected
func (s *Server) unusedMethod() {
	fmt.Println("This method is never called")
}

// Package-level function for comparison
func packageFunction() {
	fmt.Println("Package function")
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

	// Debug: List all functions found
	t.Logf("Method Detection Test - All functions in FBOM:")
	functionNames := make(map[string]bool)
	reachableFunctions := make(map[string]bool)
	for _, fn := range fbom.Functions {
		functionNames[fn.Name] = true
		if fn.UsageInfo.IsReachable {
			reachableFunctions[fn.Name] = true
		}
		t.Logf("  %s: reachable=%t, distance=%d, type=%s", fn.Name, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry, fn.FunctionType)
	}

	// Expected functions that should be detected
	expectedFunctions := []string{
		"main",            // entry point
		"Start",           // method called by main
		"setupRoutes",     // method called by main
		"initialize",      // method called by Start
		"addHealthCheck",  // method called by setupRoutes
		"unusedMethod",    // unused method (should still be detected)
		"packageFunction", // unused package function
	}

	for _, funcName := range expectedFunctions {
		if !functionNames[funcName] {
			t.Errorf("Expected method %s to be detected in FBOM", funcName)
		}
	}

	// Test reachability expectations
	expectedReachable := map[string]bool{
		"main":            true,  // entry point
		"Start":           true,  // called by main
		"setupRoutes":     true,  // called by main
		"initialize":      true,  // called by Start
		"addHealthCheck":  true,  // called by setupRoutes
		"unusedMethod":    false, // never called
		"packageFunction": false, // never called
	}

	for funcName, expectedReachable := range expectedReachable {
		if functionNames[funcName] {
			actualReachable := reachableFunctions[funcName]
			if actualReachable != expectedReachable {
				t.Errorf("Method %s: expected reachable=%t, got reachable=%t", funcName, expectedReachable, actualReachable)
			}
		}
	}

	// Test distance calculations for methods
	expectedDistances := map[string]int{
		"main":            0,  // entry point
		"Start":           1,  // called by main
		"setupRoutes":     1,  // called by main
		"initialize":      2,  // called by Start
		"addHealthCheck":  2,  // called by setupRoutes
		"unusedMethod":    -1, // unreachable
		"packageFunction": -1, // unreachable
	}

	for funcName, expectedDistance := range expectedDistances {
		if functionNames[funcName] {
			var actualDistance int
			for _, fn := range fbom.Functions {
				if fn.Name == funcName {
					actualDistance = fn.UsageInfo.DistanceFromEntry
					break
				}
			}
			if actualDistance != expectedDistance {
				t.Errorf("Method %s: expected distance=%d, got distance=%d", funcName, expectedDistance, actualDistance)
			}
		}
	}
}
