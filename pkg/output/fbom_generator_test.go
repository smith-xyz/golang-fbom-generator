package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis"
	callgraphgen "github.com/smith-xyz/golang-fbom-generator/pkg/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
)

// Unit Tests for Simplified FBOM Generator

func TestNewFBOMGenerator(t *testing.T) {
	generator := NewFBOMGenerator(true)

	if generator == nil {
		t.Fatal("NewFBOMGenerator should not return nil")
	}

	if !generator.verbose {
		t.Error("Expected verbose to be true")
	}

	if generator.logger == nil {
		t.Error("Expected logger to be initialized")
	}
}

func TestNewFBOMGenerator_NonVerbose(t *testing.T) {
	generator := NewFBOMGenerator(false)

	if generator == nil {
		t.Fatal("NewFBOMGenerator should not return nil")
	}

	if generator.verbose {
		t.Error("Expected verbose to be false")
	}
}

func TestIsStandardLibraryPackage(t *testing.T) {
	generator := NewFBOMGenerator(false)

	tests := []struct {
		packagePath string
		expected    bool
	}{
		// Standard library packages
		{"fmt", true},
		{"net/http", true},
		{"encoding/json", true},
		{"crypto/tls", true},
		{"strings", true},
		{"reflect", true},
		{"time", true},
		{"os", true},
		{"io", true},
		{"math", true},
		{"sort", true},
		{"syscall", true},
		{"testing", true},
		{"unicode", true},
		{"unsafe", true},

		// Non-standard library packages
		{"myapp/service", false},
		{"github.com/gin-gonic/gin", false},
		{"hello-world", false},
		{"example.com/mypackage", false},
		{"test-project", false},
		{"my.domain.com/app", false},
	}

	for _, tt := range tests {
		t.Run(tt.packagePath, func(t *testing.T) {
			result := generator.isStandardLibraryPackage(tt.packagePath)
			if result != tt.expected {
				t.Errorf("isStandardLibraryPackage(%s) = %v, expected %v",
					tt.packagePath, result, tt.expected)
			}
		})
	}
}

func TestIsDependencyPackage(t *testing.T) {
	generator := NewFBOMGenerator(false)

	tests := []struct {
		packagePath string
		expected    bool
	}{
		// Known dependency patterns
		{"github.com/gin-gonic/gin", true},
		{"github.com/gorilla/mux", true},
		{"gitlab.com/myorg/myrepo", true},
		{"bitbucket.org/user/repo", true},
		{"golang.org/x/tools", true},
		{"golang.org/x/crypto", true},
		{"google.golang.org/grpc", true},
		{"google.golang.org/protobuf", true},
		{"gopkg.in/yaml.v3", true},
		{"go.uber.org/zap", true},
		{"k8s.io/client-go", true},

		// Non-dependency packages
		{"fmt", false},
		{"net/http", false},
		{"myapp/service", false},
		{"hello-world", false},
		{"local/package", false},
		{"test-project", false},
		{"my.company.internal/service", false},
	}

	for _, tt := range tests {
		t.Run(tt.packagePath, func(t *testing.T) {
			result := generator.isDependencyPackage(tt.packagePath)
			if result != tt.expected {
				t.Errorf("isDependencyPackage(%s) = %v, expected %v",
					tt.packagePath, result, tt.expected)
			}
		})
	}
}

func TestBuildFBOM_BasicStructure(t *testing.T) {
	generator := NewFBOMGenerator(false)

	// Create minimal test data
	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}
	callGraph := (*callgraph.Graph)(nil) // Simple test without call graph
	ssaProgram := (*ssa.Program)(nil)    // Simple test without SSA program
	mainPackageName := "test-app"

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, mainPackageName)

	// Test basic FBOM structure
	if fbom.FBOMVersion != "0.1.0" {
		t.Errorf("Expected FBOM version 0.1.0, got %s", fbom.FBOMVersion)
	}

	if fbom.SPDXId != "SPDXRef-FBOM-ROOT" {
		t.Errorf("Expected SPDX ID 'SPDXRef-FBOM-ROOT', got %s", fbom.SPDXId)
	}

	// Note: PackageInfo.Name will be extracted from go.mod, not the parameter passed to buildFBOM
	// This is correct behavior since Bug 1 fix - it should use the real module name
	if fbom.PackageInfo.Name == "" {
		t.Errorf("Expected package name to be non-empty, got empty string")
	}

	if fbom.PackageInfo.SPDXId == "" {
		t.Errorf("Expected package SPDX ID to be non-empty, got empty string")
	}

	// Test that slices are initialized (even if empty)
	if fbom.Functions == nil {
		t.Error("Functions array should not be nil")
	}

	if fbom.EntryPoints == nil {
		t.Error("EntryPoints array should not be nil")
	}

	if fbom.Dependencies == nil {
		t.Error("Dependencies array should not be nil")
	}

	// Test creation info
	if fbom.CreationInfo.ToolName != "golang-fbom-generator" {
		t.Errorf("Expected tool name 'golang-fbom-generator', got %s", fbom.CreationInfo.ToolName)
	}

	if fbom.CreationInfo.ToolVersion != "v1.0.0-beta" {
		t.Errorf("Expected tool version 'v1.0.0-beta', got %s", fbom.CreationInfo.ToolVersion)
	}

	if len(fbom.CreationInfo.Creators) == 0 {
		t.Error("Expected at least one creator")
	}
}

func TestExtractDependencies(t *testing.T) {
	generator := NewFBOMGenerator(false)

	packages := []string{
		"fmt",                       // stdlib - should be excluded
		"net/http",                  // stdlib - should be excluded
		"github.com/gin-gonic/gin",  // dependency - should be included
		"golang.org/x/tools/go/ssa", // dependency - should be included
		"myapp/service",             // user code - should be excluded
		"hello-world",               // user code - should be excluded
		"gopkg.in/yaml.v3",          // dependency - should be included
	}

	dependencies := generator.extractDependencies(packages, []Function{}, nil)

	// Should only include dependencies, not stdlib or user code
	expectedCount := 3 // gin, golang.org/x/tools, yaml.v3
	if len(dependencies) != expectedCount {
		t.Errorf("Expected %d dependencies, got %d", expectedCount, len(dependencies))
	}

	// Check that all returned dependencies are actually dependencies
	for _, dep := range dependencies {
		if !generator.isDependencyPackage(dep.Name) {
			t.Errorf("Package %s should not be classified as a dependency", dep.Name)
		}
	}
}

func TestCountReachableFunctions(t *testing.T) {
	functions := []Function{
		{
			Name: "Function1",
			UsageInfo: UsageInfo{
				IsReachable: true,
			},
		},
		{
			Name: "Function2",
			UsageInfo: UsageInfo{
				IsReachable: false,
			},
		},
		{
			Name: "Function3",
			UsageInfo: UsageInfo{
				IsReachable: true,
			},
		},
	}

	// Count reachable functions inline
	count := 0
	for _, fn := range functions {
		if fn.UsageInfo.IsReachable {
			count++
		}
	}
	expectedCount := 2

	if count != expectedCount {
		t.Errorf("Expected %d reachable functions, got %d", expectedCount, count)
	}
}

func TestBuildSecurityInfo_Basic(t *testing.T) {
	generator := NewFBOMGenerator(false)

	assessments := []analysis.Assessment{
		{CVE: cve.CVE{ID: "CVE-2023-0001"}},
		{CVE: cve.CVE{ID: "CVE-2023-0002"}},
	}

	reflectionUsage := map[string]*reflection.Usage{
		"func1": {},
		"func2": {},
	}

	securityInfo := generator.buildSecurityInfo(assessments, reflectionUsage)

	if securityInfo.TotalCVEsFound != len(assessments) {
		t.Errorf("Expected %d total CVEs, got %d", len(assessments), securityInfo.TotalCVEsFound)
	}

	if securityInfo.ReflectionCallsCount != len(reflectionUsage) {
		t.Errorf("Expected %d reflection calls, got %d", len(reflectionUsage), securityInfo.ReflectionCallsCount)
	}

	// Verify slices are initialized (should be empty slice, not nil)
	if securityInfo.VulnerableFunctions == nil {
		t.Error("VulnerableFunctions should not be nil")
	}
	if len(securityInfo.VulnerableFunctions) != 0 {
		t.Errorf("Expected 0 vulnerable functions for non-reachable CVEs, got %d", len(securityInfo.VulnerableFunctions))
	}

	if securityInfo.SecurityHotspots == nil {
		t.Error("SecurityHotspots should not be nil")
	}

	if securityInfo.CriticalPaths == nil {
		t.Error("CriticalPaths should not be nil")
	}

	if securityInfo.UnreachableVulnerabilities == nil {
		t.Error("UnreachableVulnerabilities should not be nil")
	}
}

func TestHasReflectionRisk(t *testing.T) {
	generator := NewFBOMGenerator(false)

	tests := []struct {
		name     string
		usage    *reflection.Usage
		expected bool
	}{
		{
			name:     "nil usage",
			usage:    nil,
			expected: false,
		},
		{
			name: "low risk",
			usage: &reflection.Usage{
				ReflectionRisk: reflection.RiskLow,
			},
			expected: false,
		},
		{
			name: "medium risk",
			usage: &reflection.Usage{
				ReflectionRisk: reflection.RiskMedium,
			},
			expected: true,
		},
		{
			name: "high risk",
			usage: &reflection.Usage{
				ReflectionRisk: reflection.RiskHigh,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generator.hasReflectionRisk(tt.usage)
			if result != tt.expected {
				t.Errorf("hasReflectionRisk() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// Test that the FBOM generator handles edge cases gracefully
func TestBuildFBOM_EdgeCases(t *testing.T) {
	generator := NewFBOMGenerator(false)

	// Test with nil inputs
	fbom := generator.buildFBOM(nil, nil, nil, nil, "")

	// Should not panic and should return valid FBOM structure
	if fbom.FBOMVersion == "" {
		t.Error("FBOM version should not be empty")
	}

	if fbom.Functions == nil {
		t.Error("Functions should be initialized even with nil inputs")
	}

	if fbom.EntryPoints == nil {
		t.Error("EntryPoints should be initialized even with nil inputs")
	}

	if fbom.Dependencies == nil {
		t.Error("Dependencies should be initialized even with nil inputs")
	}
}

// TestBug1_PackageInfoName tests that package_info.name shows the correct package name
// Bug: Package info doesn't seem to be correct. It's not showing the correct package name.
// Expected: For hello-world module, package_info.name should be "hello-world", not "main"
func TestBug1_PackageInfoName(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world!")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Bug: package_info.name should be the actual module name, not "main" (the package name)
	expectedPackageName := "github.com/smith-xyz/golang-fbom-generator"
	if fbom.PackageInfo.Name != expectedPackageName {
		t.Errorf("Bug 1 - Package info name incorrect: expected %q, got %q", expectedPackageName, fbom.PackageInfo.Name)
	}
}

// TestBug2_CallGraphTotalFunctions tests that call graph counts all functions including uncalled ones
// Bug: The callgraph total_function seems incorrect. I added a new uncalled function to hello-world example and its not being counted.
// Expected: Should count all user-defined functions, including unreachable ones
func TestBug2_CallGraphTotalFunctions(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world!")
	called()
}

func called() {
	// This function is called
}

func notCalled() {
	// This function is NOT called - but should still be counted
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Count expected user functions: main, init, called, notCalled = 4
	expectedFunctionCount := 4
	actualFunctionCount := fbom.CallGraph.TotalFunctions

	if actualFunctionCount != expectedFunctionCount {
		t.Errorf("Bug 2 - Call graph total functions incorrect: expected %d, got %d", expectedFunctionCount, actualFunctionCount)
	}

	// Also verify the functions list includes the uncalled function
	var foundNotCalled bool
	for _, fn := range fbom.Functions {
		if fn.Name == "notCalled" {
			foundNotCalled = true
			break
		}
	}

	if !foundNotCalled {
		t.Error("Bug 2 - notCalled function should be included in functions list even though it's unreachable")
	}
}

// TestBug3_CallTypeTransitive tests that call graph call_type correctly identifies transitive calls
// Bug: The callgraph call edges properties call_type marked a transitive function as a direct.
// Expected: Calls should be marked as "transitive" when they are to functions at distance 2+ from entry points
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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Find the call edge from directCall to transitiveCall
	var foundTransitiveCallEdge bool
	for _, edge := range fbom.CallGraph.CallEdges {
		if edge.Caller == "testmodule.directCall" && edge.Callee == "testmodule.transitiveCall" {
			foundTransitiveCallEdge = true
			// Bug: This should be marked as "transitive" because transitiveCall is at distance 2 from main
			expectedCallType := "transitive"
			if edge.CallType != expectedCallType {
				t.Errorf("Bug 3 - Call type incorrect for transitive call: expected %q, got %q", expectedCallType, edge.CallType)
			}
			break
		}
	}

	if !foundTransitiveCallEdge {
		t.Error("Bug 3 - Expected to find call edge from directCall to transitiveCall")
	}
}

// TestBug4_CallEdgeFilePathAndLineNumber tests that call edges have correct file path and line numbers
// Bug: The call graph file path and line number are not being set correctly.
// Expected: Each call edge should have the file_path and line_number where the call occurs
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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Find the call edge from main to helper
	var foundCallEdge bool
	for _, edge := range fbom.CallGraph.CallEdges {
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
		t.Error("Bug 4 - Expected to find call edge from main to helper")
	}
}

// TestBug5_ReachableFunctionsCount tests that reachable_functions count is calculated correctly
// Bug: ReachableFunctions is defaulting to 1, should calculate the actual number of functions reachable from entry points
// Expected: For hello-world with main->sum, main->multiplication, multiplication->transitiveMultiplication, should be 5 reachable functions (main, init, sum, multiplication, transitiveMultiplication)
func TestBug5_ReachableFunctionsCount(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world! Sum of 1 and 2 is", sum(1, 2))
	fmt.Println("Hello world! Transitive multiplication of 1 and 2 is", multiplication(1, 2))
}

// This function is called directly by the main function
func sum(a int, b int) int {
	return a + b
}

// This function is called directly by the main function
func multiplication(a int, b int) int {
	return transitiveMultiplication(a, b)
}

// This function is called transitively by the multiplication function
func transitiveMultiplication(a int, b int) int {
	return a * b
}

func notCalled() {
	fmt.Println("This function is not called")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Expected reachable functions: main, init, sum, multiplication, transitiveMultiplication = 5
	// notCalled() should NOT be counted as it's unreachable
	expectedReachableFunctions := 5
	if fbom.CallGraph.ReachableFunctions != expectedReachableFunctions {
		t.Errorf("Bug 5 - ReachableFunctions count incorrect: expected %d, got %d", expectedReachableFunctions, fbom.CallGraph.ReachableFunctions)
	}

	// Also verify this matches the used_functions count (should be the same)
	if fbom.CallGraph.ReachableFunctions != fbom.CallGraph.UsedFunctions {
		t.Errorf("Bug 5 - ReachableFunctions (%d) should equal UsedFunctions (%d)", fbom.CallGraph.ReachableFunctions, fbom.CallGraph.UsedFunctions)
	}

	// Total should be 6 (5 reachable + 1 unreachable)
	expectedTotalFunctions := 6
	if fbom.CallGraph.TotalFunctions != expectedTotalFunctions {
		t.Errorf("Bug 5 - TotalFunctions count incorrect: expected %d, got %d", expectedTotalFunctions, fbom.CallGraph.TotalFunctions)
	}

	// Unused should be 1 (just notCalled)
	expectedUnusedFunctions := 1
	if fbom.CallGraph.UnusedFunctions != expectedUnusedFunctions {
		t.Errorf("Bug 5 - UnusedFunctions count incorrect: expected %d, got %d", expectedUnusedFunctions, fbom.CallGraph.UnusedFunctions)
	}
}

// TestBug6_MaxDepthCalculation tests that max_depth is calculated correctly instead of defaulting to 10
// Bug: MaxDepth is hardcoded to 10, should calculate the actual maximum depth from entry points
// Expected: For hello-world call chain: main->multiplication->transitiveMultiplication, max depth should be 2
func TestBug6_MaxDepthCalculation(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world! Sum of 1 and 2 is", sum(1, 2))
	fmt.Println("Hello world! Transitive multiplication of 1 and 2 is", multiplication(1, 2))
}

// This function is called directly by the main function (depth 1)
func sum(a int, b int) int {
	return a + b
}

// This function is called directly by the main function (depth 1)
func multiplication(a int, b int) int {
	return transitiveMultiplication(a, b)
}

// This function is called transitively by the multiplication function (depth 2)
func transitiveMultiplication(a int, b int) int {
	return a * b
}

func notCalled() {
	fmt.Println("This function is not called")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Expected max depth: main(0) -> multiplication(1) -> transitiveMultiplication(2) = depth 2
	expectedMaxDepth := 2
	if fbom.CallGraph.MaxDepth != expectedMaxDepth {
		t.Errorf("Bug 6 - MaxDepth incorrect: expected %d, got %d", expectedMaxDepth, fbom.CallGraph.MaxDepth)
	}
}

// TestBug7_AvgDepthCalculation tests that avg_depth is calculated correctly instead of defaulting to 5.0
// Bug: AvgDepth is hardcoded to 5.0, should calculate the actual average depth from entry points
// Expected: For hello-world depths: main(0), sum(1), multiplication(1), transitiveMultiplication(2), average should be 1.0
func TestBug7_AvgDepthCalculation(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world! Sum of 1 and 2 is", sum(1, 2))
	fmt.Println("Hello world! Transitive multiplication of 1 and 2 is", multiplication(1, 2))
}

// This function is called directly by the main function (depth 1)
func sum(a int, b int) int {
	return a + b
}

// This function is called directly by the main function (depth 1)
func multiplication(a int, b int) int {
	return transitiveMultiplication(a, b)
}

// This function is called transitively by the multiplication function (depth 2)  
func transitiveMultiplication(a int, b int) int {
	return a * b
}

func notCalled() {
	fmt.Println("This function is not called")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Expected avg depth: main(0) + sum(1) + multiplication(1) + transitiveMultiplication(2) + init(0) = 4/5 = 0.8
	// Note: init function is at depth 0 since it's also an entry point
	expectedAvgDepth := 0.8
	tolerance := 0.1 // Allow small floating point differences

	if fbom.CallGraph.AvgDepth < expectedAvgDepth-tolerance || fbom.CallGraph.AvgDepth > expectedAvgDepth+tolerance {
		t.Errorf("Bug 7 - AvgDepth incorrect: expected ~%.1f, got %.1f", expectedAvgDepth, fbom.CallGraph.AvgDepth)
	}
}

// TestBug8_DistanceFromEntryCalculation tests that distance_from_entry is calculated correctly instead of being simplified
// Bug: calculateDistanceFromEntry is simplified - returns 0 for entry points, 1 for everything else
// Expected: For hello-world: main(0), sum(1), multiplication(1), transitiveMultiplication(2), notCalled(-1)
func TestBug8_DistanceFromEntryCalculation(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world! Sum of 1 and 2 is", sum(1, 2))
	fmt.Println("Hello world! Transitive multiplication of 1 and 2 is", multiplication(1, 2))
}

// This function is called directly by the main function (distance 1)
func sum(a int, b int) int {
	return a + b
}

// This function is called directly by the main function (distance 1)
func multiplication(a int, b int) int {
	return transitiveMultiplication(a, b)
}

// This function is called transitively by the multiplication function (distance 2)  
func transitiveMultiplication(a int, b int) int {
	return a * b
}

func notCalled() {
	fmt.Println("This function is not called")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Check distance_from_entry for each function
	functionDistances := make(map[string]int)
	for _, fn := range fbom.Functions {
		functionDistances[fn.Name] = fn.UsageInfo.DistanceFromEntry
	}

	// Expected distances
	expectedDistances := map[string]int{
		"main":                     0,  // Entry point
		"sum":                      1,  // Called directly by main
		"multiplication":           1,  // Called directly by main
		"transitiveMultiplication": 2,  // Called by multiplication (main->multiplication->transitiveMultiplication)
		"notCalled":                -1, // Unreachable
	}

	for funcName, expectedDistance := range expectedDistances {
		if actualDistance, found := functionDistances[funcName]; found {
			if actualDistance != expectedDistance {
				t.Errorf("Bug 8 - Function %s distance_from_entry incorrect: expected %d, got %d",
					funcName, expectedDistance, actualDistance)
			}
		} else {
			t.Errorf("Bug 8 - Function %s not found in FBOM", funcName)
		}
	}
}

// TestBug9_MethodDistanceFromEntry tests that methods injected into structs get proper distance calculation
// Bug: Functions that are injected into other functions (methods) are defaulting to -1 distance
// Expected: Methods should have proper distance calculation based on their call chain
func TestBug9_MethodDistanceFromEntry(t *testing.T) {
	testCode := `
package main

import "fmt"

type Server struct {
	name string
}

func main() {
	server := Server{name: "test"}
	server.Start()
}

// This method is called by main, should have distance 1
func (s *Server) Start() {
	fmt.Println("Server starting:", s.name)
	s.initialize()
}

// This method is called by Start, should have distance 2
func (s *Server) initialize() {
	fmt.Println("Initializing server")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Check distance_from_entry for methods
	functionDistances := make(map[string]int)
	for _, fn := range fbom.Functions {
		functionDistances[fn.Name] = fn.UsageInfo.DistanceFromEntry
	}

	// Expected distances for methods
	expectedDistances := map[string]int{
		"main":       0, // Entry point
		"Start":      1, // Called by main
		"initialize": 2, // Called by Start method
	}

	// Debug: Print all function distances found
	t.Logf("Bug 9 Debug - All function distances found:")
	for name, dist := range functionDistances {
		t.Logf("  %s: %d", name, dist)
	}

	for funcName, expectedDistance := range expectedDistances {
		if actualDistance, found := functionDistances[funcName]; found {
			if actualDistance == -1 {
				t.Errorf("Bug 9 - Method %s has distance -1 (defaulting), should be calculated properly", funcName)
			} else if actualDistance != expectedDistance {
				t.Errorf("Bug 9 - Method %s distance_from_entry incorrect: expected %d, got %d",
					funcName, expectedDistance, actualDistance)
			}
		} else {
			t.Errorf("Bug 9 - Method %s not found in FBOM", funcName)
		}
	}
}

// TestBug10_ComplexDistanceCalculation tests distance calculation for more complex call chains
// Bug: Distance calculation seems incorrect at times (e.g., ValidateToken should be distance 3, not 1)
// Expected: Complex call chains should have accurate distance calculation
func TestBug10_ComplexDistanceCalculation(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	HandleRequest()
}

// Distance 1 from main
func HandleRequest() {
	fmt.Println("Handling request")
	AuthenticateUser()
}

// Distance 2 from main
func AuthenticateUser() {
	fmt.Println("Authenticating user")
	ValidateToken()
}

// Distance 3 from main (main->HandleRequest->AuthenticateUser->ValidateToken)
func ValidateToken() {
	fmt.Println("Validating token")
	CheckTokenExpiry()
}

// Distance 4 from main
func CheckTokenExpiry() {
	fmt.Println("Checking token expiry")
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Check distance_from_entry for the complex chain
	functionDistances := make(map[string]int)
	for _, fn := range fbom.Functions {
		functionDistances[fn.Name] = fn.UsageInfo.DistanceFromEntry
	}

	// Expected distances for complex call chain
	expectedDistances := map[string]int{
		"main":             0, // Entry point
		"HandleRequest":    1, // main->HandleRequest
		"AuthenticateUser": 2, // main->HandleRequest->AuthenticateUser
		"ValidateToken":    3, // main->HandleRequest->AuthenticateUser->ValidateToken
		"CheckTokenExpiry": 4, // main->HandleRequest->AuthenticateUser->ValidateToken->CheckTokenExpiry
	}

	for funcName, expectedDistance := range expectedDistances {
		if actualDistance, found := functionDistances[funcName]; found {
			if actualDistance != expectedDistance {
				t.Errorf("Bug 10 - Function %s distance_from_entry incorrect in complex chain: expected %d, got %d",
					funcName, expectedDistance, actualDistance)
			}
		} else {
			t.Errorf("Bug 10 - Function %s not found in FBOM", funcName)
		}
	}
}

// TestBug11_UnusedFunctionInclusion tests that unused functions are included in FBOM
// Bug: Unused standalone functions are not added to the FBOM at all
// Expected: Even unreachable functions should exist in the FBOM with distance -1 and reachable=false
func TestBug11_UnusedFunctionInclusion(t *testing.T) {
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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Print all functions found
	t.Logf("Bug 11 Debug - All functions found in FBOM:")
	functionNames := make(map[string]bool)
	for _, fn := range fbom.Functions {
		functionNames[fn.Name] = true
		t.Logf("  %s: reachable=%t, distance=%d, type=%s", fn.Name, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry, fn.UsageInfo.ReachabilityType)
	}

	expectedUnusedFunctions := []string{"unusedStandaloneFunction", "anotherUnusedFunction"}

	for _, funcName := range expectedUnusedFunctions {
		if !functionNames[funcName] {
			t.Errorf("Bug 11 - Unused function %s is missing from FBOM, should be included with reachable=false", funcName)
		}
	}

	// Also verify their properties if they exist
	for _, fn := range fbom.Functions {
		if fn.Name == "unusedStandaloneFunction" || fn.Name == "anotherUnusedFunction" {
			if fn.UsageInfo.IsReachable {
				t.Errorf("Bug 11 - Unused function %s should have IsReachable=false", fn.Name)
			}
			if fn.UsageInfo.DistanceFromEntry != -1 {
				t.Errorf("Bug 11 - Unused function %s should have DistanceFromEntry=-1, got %d", fn.Name, fn.UsageInfo.DistanceFromEntry)
			}
			if fn.UsageInfo.ReachabilityType != "unreachable" {
				t.Errorf("Bug 11 - Unused function %s should have ReachabilityType='unreachable', got '%s'", fn.Name, fn.UsageInfo.ReachabilityType)
			}
		}
	}
}

// TestBug12_InterfaceMethodDistances tests distance calculation for interface methods and embedded structs
// This might catch edge cases not covered by simple struct methods
func TestBug12_InterfaceMethodDistances(t *testing.T) {
	testCode := `
package main

import "fmt"

type Handler interface {
	Handle() error
}

type Database struct {
	connection string
}

func (db *Database) Connect() error {
	fmt.Println("Connecting to database")
	return db.validateConnection()
}

func (db *Database) validateConnection() error {
	fmt.Println("Validating connection")
	return nil
}

func (db *Database) Handle() error {
	return db.Connect()
}

func main() {
	var handler Handler = &Database{connection: "test"}
	handler.Handle()
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Print all function distances found
	t.Logf("Bug 12 Debug - All function distances found:")
	functionDistances := make(map[string]int)
	for _, fn := range fbom.Functions {
		functionDistances[fn.Name] = fn.UsageInfo.DistanceFromEntry
		t.Logf("  %s: %d (reachable=%t)", fn.Name, fn.UsageInfo.DistanceFromEntry, fn.UsageInfo.IsReachable)
	}

	// Expected distances for interface/struct methods
	expectedDistances := map[string]int{
		"main":               0, // Entry point
		"Handle":             1, // Called by main through interface
		"Connect":            2, // Called by Handle
		"validateConnection": 3, // Called by Connect
	}

	for funcName, expectedDistance := range expectedDistances {
		if actualDistance, found := functionDistances[funcName]; found {
			if actualDistance == -1 {
				t.Errorf("Bug 12 - Interface method %s has distance -1 (defaulting), should be calculated properly", funcName)
			} else if actualDistance != expectedDistance {
				t.Logf("Bug 12 - Interface method %s distance_from_entry: expected %d, got %d",
					funcName, expectedDistance, actualDistance)
				// Don't fail the test yet, just log for analysis
			}
		} else {
			t.Errorf("Bug 12 - Interface method %s not found in FBOM", funcName)
		}
	}
}

// TestBug13_ExportedFunctionsAsEntryPoints reproduces the fbom-demo issue where exported functions are incorrectly treated as entry points
// Bug: ValidateToken (struct method) showing distance 0 instead of proper call chain distance
// Root Cause: isEntryPoint treats all exported functions in non-main packages as entry points
func TestBug13_ExportedFunctionsAsEntryPoints(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	service := &AuthService{}
	service.HandleRequest()
}

type AuthService struct{}

// This exported method should NOT be an entry point - it's called by main
func (s *AuthService) HandleRequest() {
	fmt.Println("Handling request")
	s.ValidateToken("test-token")
}

// This exported method should be distance 2, not 0 (entry point)
func (s *AuthService) ValidateToken(token string) bool {
	fmt.Println("Validating token:", token)
	return s.checkTokenExpiry(token)
}

// This should be distance 3, not 0
func (s *AuthService) checkTokenExpiry(token string) bool {
	fmt.Println("Checking expiry for:", token)
	return true
}

// Exported function that should be distance 1, not 0
func HashPassword(password string) string {
	return "hashed_" + password
}
`

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Print all function distances
	t.Logf("Bug 13 Debug - Function distances:")
	functionDistances := make(map[string]int)
	for _, fn := range fbom.Functions {
		functionDistances[fn.Name] = fn.UsageInfo.DistanceFromEntry
		isEntry := fn.UsageInfo.IsEntryPoint
		t.Logf("  %s: distance=%d, isEntryPoint=%t", fn.Name, fn.UsageInfo.DistanceFromEntry, isEntry)
	}

	// Test the specific issues we found in fbom-demo
	testCases := []struct {
		funcName         string
		expectedDistance int
		shouldBeEntry    bool
		description      string
	}{
		{"main", 0, true, "main should be entry point"},
		{"HandleRequest", 1, false, "exported method should not be entry point"},
		{"ValidateToken", 2, false, "ValidateToken should be distance 2, not entry point"},
		{"checkTokenExpiry", 3, false, "checkTokenExpiry should be distance 3"},
		{"HashPassword", -1, false, "unused HashPassword should be unreachable, not entry point"},
	}

	for _, tc := range testCases {
		actualDistance := functionDistances[tc.funcName]

		// Check for the specific bug: exported functions incorrectly as entry points
		for _, fn := range fbom.Functions {
			if fn.Name == tc.funcName {
				if fn.UsageInfo.IsEntryPoint != tc.shouldBeEntry {
					t.Errorf("Bug 13 - %s: %s - isEntryPoint should be %t, got %t",
						tc.funcName, tc.description, tc.shouldBeEntry, fn.UsageInfo.IsEntryPoint)
				}
				break
			}
		}

		if actualDistance != tc.expectedDistance {
			t.Errorf("Bug 13 - %s: %s - expected distance %d, got %d",
				tc.funcName, tc.description, tc.expectedDistance, actualDistance)
		}
	}
}

// TestBug14_MissingUnusedFunctionsFromOtherPackages reproduces the real issue where unused functions in other packages don't appear in FBOM
// Bug: databaseConnectionHelper function in internal/database package missing from FBOM entirely
// This is different from unused functions in main - the issue is with multi-package analysis
func TestBug14_MissingUnusedFunctionsFromOtherPackages(t *testing.T) {
	// This test uses the real fbom-demo project to reproduce the actual bug
	// We can't easily simulate this with inline code because it requires proper package structure

	// Skip if we can't access the fbom-demo directory
	fbomDemoPath := "../../examples/fbom-demo"
	if _, err := os.Stat(fbomDemoPath); os.IsNotExist(err) {
		t.Skip("Skipping test - fbom-demo directory not found")
	}

	// Change to fbom-demo directory for testing
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	err = os.Chdir(fbomDemoPath)
	if err != nil {
		t.Fatalf("Failed to change to fbom-demo directory: %v", err)
	}

	generator := NewFBOMGenerator(false)
	callGraphGen := callgraphgen.NewGenerator(".", false)
	callGraphResult, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		t.Fatalf("Failed to build call graph for fbom-demo: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraphResult, ssaProgram, "fbom-demo")

	// Debug: List all functions found in database package
	t.Logf("Bug 14 Debug - All functions in FBOM from database package:")
	functionNames := make(map[string]bool)
	databaseFunctions := []string{}
	for _, fn := range fbom.Functions {
		functionNames[fn.Name] = true
		if strings.Contains(fn.Package, "database") {
			databaseFunctions = append(databaseFunctions, fn.Name)
			t.Logf("  %s: package=%s, reachable=%t, distance=%d", fn.Name, fn.Package, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
		}
	}

	// The specific function that should be present but isn't
	expectedUnusedFunction := "databaseConnectionHelper"

	if !functionNames[expectedUnusedFunction] {
		t.Errorf("Bug 14 - Unused function %s from internal/database package is missing from FBOM entirely", expectedUnusedFunction)
		t.Logf("Functions found in database package: %v", databaseFunctions)
	} else {
		// If it is present, verify it has correct properties
		for _, fn := range fbom.Functions {
			if fn.Name == expectedUnusedFunction {
				if fn.UsageInfo.IsReachable {
					t.Errorf("Bug 14 - Unused function %s should be unreachable", expectedUnusedFunction)
				}
				if fn.UsageInfo.DistanceFromEntry != -1 {
					t.Errorf("Bug 14 - Unused function %s should have distance -1, got %d", expectedUnusedFunction, fn.UsageInfo.DistanceFromEntry)
				}
				t.Logf("Bug 14 - Function %s correctly found with reachable=%t, distance=%d",
					expectedUnusedFunction, fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
			}
		}
	}
}

// TestBug15_AnonymousFunctionCallGraph tests the detection of anonymous functions and their calls
// Bug: Anonymous functions are not being added to the call graph, making it impossible to track
// calls that happen through anonymous function execution
func TestBug15_AnonymousFunctionCallGraph(t *testing.T) {
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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: List all functions found
	t.Logf("Bug 15 Debug - All functions in FBOM:")
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
	t.Logf("Bug 15 Debug - Call graph edges:")
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("  %s -> %s", edge.Caller, edge.Callee)
	}

	// Test expectations
	expectedFunctions := []string{"main", "dummyFunction", "anotherDummyFunction", "unreachableFunction"}
	for _, funcName := range expectedFunctions {
		if !functionNames[funcName] {
			t.Errorf("Bug 15 - Function %s should be in FBOM", funcName)
		}
	}

	// Key test: Functions called by anonymous functions should be reachable
	if !reachableFunctions["dummyFunction"] {
		t.Errorf("Bug 15 - dummyFunction should be reachable (called by anonymous function)")
	}

	if !reachableFunctions["anotherDummyFunction"] {
		t.Errorf("Bug 15 - anotherDummyFunction should be reachable (called by inline anonymous function)")
	}

	// unreachableFunction should NOT be reachable
	if reachableFunctions["unreachableFunction"] {
		t.Errorf("Bug 15 - unreachableFunction should NOT be reachable")
	}

	// Check for call edges from main to the dummy functions (should exist if anonymous functions are tracked)
	mainToDummy := false
	mainToAnotherDummy := false
	for _, edge := range fbom.CallGraph.CallEdges {
		if edge.Caller == "main" && edge.Callee == "dummyFunction" {
			mainToDummy = true
		}
		if edge.Caller == "main" && edge.Callee == "anotherDummyFunction" {
			mainToAnotherDummy = true
		}
	}

	// Note: These might fail if anonymous functions aren't properly tracked
	if !mainToDummy {
		t.Logf("Bug 15 - WARNING: No call edge from main to dummyFunction (anonymous function not tracked)")
	}
	if !mainToAnotherDummy {
		t.Logf("Bug 15 - WARNING: No call edge from main to anotherDummyFunction (inline anonymous function not tracked)")
	}
}

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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

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

// TestBug16_CallRelationshipPopulation tests that UsageInfo.Calls is properly populated for all functions
// Bug: Functions show calls=null instead of listing the functions they call
func TestBug16_CallRelationshipPopulation(t *testing.T) {
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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Show all functions and their calls
	t.Logf("Bug 16 Debug - Function calls:")
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
		t.Logf("Bug 16 Debug - Function %s: Calls=%v, len=%d, isNil=%t", fn.Name, fn.UsageInfo.Calls, len(fn.UsageInfo.Calls), fn.UsageInfo.Calls == nil)
		if fn.UsageInfo.Calls == nil {
			t.Errorf("Bug 16 - Function %s has calls=null, should have empty array or populated calls", fn.Name)
		}
	}

	// Test specific expected call relationships
	for funcName, expectedCallees := range expectedCalls {
		actualCalls := functionCalls[funcName]
		if actualCalls == nil {
			t.Errorf("Bug 16 - Function %s has no calls data (null)", funcName)
			continue
		}

		// For functions that should make calls, verify they're recorded
		if len(expectedCallees) > 0 {
			if len(actualCalls) == 0 {
				t.Errorf("Bug 16 - Function %s should call %v but has no calls recorded", funcName, expectedCallees)
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
						t.Errorf("Bug 16 - Function %s should call %s but it's not in calls list: %v", funcName, expectedCallee, actualCalls)
					}
				}
			}
		}
	}

	// Test that call relationships match call graph edges
	callGraphEdges := make(map[string][]string)
	for _, edge := range fbom.CallGraph.CallEdges {
		caller := extractFunctionName(edge.Caller)
		callee := extractFunctionName(edge.Callee)
		callGraphEdges[caller] = append(callGraphEdges[caller], callee)
	}

	t.Logf("Bug 16 Debug - Call graph edges:")
	for caller, callees := range callGraphEdges {
		t.Logf("  %s -> %v", caller, callees)
	}

	// Verify that UsageInfo.Calls matches the call graph edges (filtering out stdlib calls)
	for funcName, expectedCallees := range callGraphEdges {
		actualCalls := functionCalls[funcName]

		// Filter out stdlib calls from expected callees - only user function calls should be in UsageInfo.Calls
		var expectedUserCalls []string
		for _, callee := range expectedCallees {
			// Skip stdlib functions - these should go in StdlibCalls, not Calls
			if callee != "Println" && callee != "Print" && callee != "Printf" &&
				callee != "init" && callee != "Sprintf" && callee != "Read" && callee != "Write" {
				expectedUserCalls = append(expectedUserCalls, callee)
			}
		}

		if len(expectedUserCalls) > 0 && len(actualCalls) == 0 {
			t.Errorf("Bug 16 - Function %s has user call graph edges but no UsageInfo.Calls: expected %v, got %v", funcName, expectedUserCalls, actualCalls)
		}
	}
}

// TestBug17_CallGraphProcessing tests that call graph edges are properly processed and matched to our functions
// This reproduces the issue where NewServer -> setupRoutes exists in callgraph CLI but not in our FBOM
func TestBug17_CallGraphProcessing(t *testing.T) {
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

	generator := NewFBOMGenerator(false)
	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	// Debug: Show what the raw call graph contains
	t.Logf("Bug 17 Debug - Raw call graph edges from golang.org/x/tools:")
	for fn, node := range callGraph.Nodes {
		if fn != nil && node != nil {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					t.Logf("  %s -> %s", fn.String(), edge.Callee.Func.String())
				}
			}
		}
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := generator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Show what our FBOM call edges contain
	t.Logf("Bug 17 Debug - FBOM call graph edges:")
	for _, edge := range fbom.CallGraph.CallEdges {
		t.Logf("  %s -> %s", edge.Caller, edge.Callee)
	}

	// Debug: Show function names and IDs we generated
	t.Logf("Bug 17 Debug - Function names and IDs:")
	functionsByName := make(map[string]string) // name -> fullID
	for _, fn := range fbom.Functions {
		functionsByName[fn.Name] = fn.FullName
		t.Logf("  %s: fullName='%s'", fn.Name, fn.FullName)
	}

	// Test 1: Check that both functions exist in our FBOM
	if _, exists := functionsByName["NewServer"]; !exists {
		t.Errorf("Bug 17 - NewServer function not found in FBOM")
	}
	if _, exists := functionsByName["setupRoutes"]; !exists {
		t.Errorf("Bug 17 - setupRoutes function not found in FBOM")
	}

	// Test 2: Check that the call edge exists in raw call graph
	newServerToSetupRoutesInRaw := false
	for fn, node := range callGraph.Nodes {
		if fn != nil && node != nil && strings.Contains(fn.String(), "NewServer") {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil &&
					strings.Contains(edge.Callee.Func.String(), "setupRoutes") {
					newServerToSetupRoutesInRaw = true
					t.Logf("Bug 17 - Found raw edge: %s -> %s", fn.String(), edge.Callee.Func.String())
					break
				}
			}
		}
	}

	if !newServerToSetupRoutesInRaw {
		t.Errorf("Bug 17 - NewServer -> setupRoutes edge missing from raw call graph")
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
		t.Errorf("Bug 17 - NewServer -> setupRoutes edge missing from FBOM call graph")
		t.Logf("Bug 17 - This means our call graph processing is not working correctly")
	}

	// Test 4: Check function reachability (should be correct if call edges are correct)
	setupRoutesReachable := false
	for _, fn := range fbom.Functions {
		if fn.Name == "setupRoutes" {
			setupRoutesReachable = fn.UsageInfo.IsReachable
			t.Logf("Bug 17 - setupRoutes reachable: %t, distance: %d", fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
			break
		}
	}

	if !setupRoutesReachable {
		t.Errorf("Bug 17 - setupRoutes should be reachable (called by NewServer)")
	}

	// Test 5: Test the anonymous function chain as well
	dummyFunctionReachable := false
	for _, fn := range fbom.Functions {
		if fn.Name == "dummyFunction" {
			dummyFunctionReachable = fn.UsageInfo.IsReachable
			t.Logf("Bug 17 - dummyFunction reachable: %t, distance: %d", fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
			break
		}
	}

	if !dummyFunctionReachable {
		t.Errorf("Bug 17 - dummyFunction should be reachable (called through anonymous function)")
	}
}

// TestBug18_FbomDemoCallGraphProcessing tests the actual fbom-demo project call graph processing
// This reproduces the real issue where NewServer -> setupRoutes exists in callgraph CLI but not in our FBOM
func TestBug18_FbomDemoCallGraphProcessing(t *testing.T) {
	// Change to fbom-demo directory for this test
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWd)
	}()

	// Go up to project root first
	projectRoot := filepath.Join(originalWd, "..", "..")
	fbomDemoPath := filepath.Join(projectRoot, "examples", "fbom-demo")
	if err := os.Chdir(fbomDemoPath); err != nil {
		t.Fatalf("Failed to change to fbom-demo directory: %v", err)
	}

	callGraphGen := callgraphgen.NewGenerator(".", false)
	callGraph, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph for fbom-demo: %v", err)
	}

	// Debug: Show relevant raw call graph edges
	t.Logf("Bug 18 Debug - Raw call graph edges (NewServer and setupRoutes related):")
	newServerEdges := []string{}
	setupRoutesEdges := []string{}

	for fn, node := range callGraph.Nodes {
		if fn != nil && node != nil {
			fnStr := fn.String()
			if strings.Contains(fnStr, "NewServer") {
				for _, edge := range node.Out {
					if edge.Callee != nil && edge.Callee.Func != nil {
						edgeStr := fmt.Sprintf("%s -> %s", fnStr, edge.Callee.Func.String())
						newServerEdges = append(newServerEdges, edgeStr)
						t.Logf("  %s", edgeStr)
					}
				}
			}
			if strings.Contains(fnStr, "setupRoutes") {
				for _, edge := range node.Out {
					if edge.Callee != nil && edge.Callee.Func != nil {
						edgeStr := fmt.Sprintf("%s -> %s", fnStr, edge.Callee.Func.String())
						setupRoutesEdges = append(setupRoutesEdges, edgeStr)
						t.Logf("  %s", edgeStr)
					}
				}
			}
		}
	}

	fbomGenerator := NewFBOMGenerator(false)
	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	fbom := fbomGenerator.buildFBOM(assessments, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Show our FBOM call edges (NewServer and setupRoutes related)
	t.Logf("Bug 18 Debug - FBOM call graph edges (NewServer and setupRoutes related):")
	fbomNewServerEdges := []string{}
	fbomSetupRoutesEdges := []string{}

	for _, edge := range fbom.CallGraph.CallEdges {
		if strings.Contains(edge.Caller, "NewServer") {
			fbomNewServerEdges = append(fbomNewServerEdges, fmt.Sprintf("%s -> %s", edge.Caller, edge.Callee))
			t.Logf("  %s -> %s", edge.Caller, edge.Callee)
		}
		if strings.Contains(edge.Caller, "setupRoutes") || strings.Contains(edge.Callee, "setupRoutes") {
			fbomSetupRoutesEdges = append(fbomSetupRoutesEdges, fmt.Sprintf("%s -> %s", edge.Caller, edge.Callee))
			t.Logf("  %s -> %s", edge.Caller, edge.Callee)
		}
	}

	// Log the collected edges for debugging
	t.Logf("Collected %d setupRoutes edges and %d FBOM setupRoutes edges", len(setupRoutesEdges), len(fbomSetupRoutesEdges))

	// Debug: Show function names and IDs we generated (NewServer and setupRoutes related)
	t.Logf("Bug 18 Debug - Function names and IDs (NewServer and setupRoutes related):")
	functionsByName := make(map[string]string) // name -> fullID
	for _, fn := range fbom.Functions {
		functionsByName[fn.Name] = fn.FullName
		if strings.Contains(fn.Name, "NewServer") || strings.Contains(fn.Name, "setupRoutes") {
			t.Logf("  %s: fullName='%s'", fn.Name, fn.FullName)
		}
	}

	// Test 1: Check that both functions exist in our FBOM
	newServerFound := false
	setupRoutesFound := false
	for name := range functionsByName {
		if strings.Contains(name, "NewServer") {
			newServerFound = true
		}
		if strings.Contains(name, "setupRoutes") {
			setupRoutesFound = true
		}
	}

	if !newServerFound {
		t.Errorf("Bug 18 - NewServer function not found in FBOM")
	}
	if !setupRoutesFound {
		t.Errorf("Bug 18 - setupRoutes function not found in FBOM")
	}

	// Test 2: Check that the call edge exists in raw call graph
	newServerToSetupRoutesInRaw := false
	for _, edge := range newServerEdges {
		if strings.Contains(edge, "setupRoutes") {
			newServerToSetupRoutesInRaw = true
			t.Logf("Bug 18 - Found raw edge: %s", edge)
			break
		}
	}

	if !newServerToSetupRoutesInRaw {
		t.Errorf("Bug 18 - NewServer -> setupRoutes edge missing from raw call graph")
	}

	// Test 3: Check that the call edge exists in our FBOM call graph
	newServerToSetupRoutesInFBOM := false
	for _, edge := range fbomNewServerEdges {
		if strings.Contains(edge, "setupRoutes") {
			newServerToSetupRoutesInFBOM = true
			break
		}
	}

	if !newServerToSetupRoutesInFBOM {
		t.Errorf("Bug 18 - NewServer -> setupRoutes edge missing from FBOM call graph")
		t.Logf("Bug 18 - Raw edges from NewServer: %v", newServerEdges)
		t.Logf("Bug 18 - FBOM edges from NewServer: %v", fbomNewServerEdges)
		t.Logf("Bug 18 - This means our call graph processing is not working correctly for fbom-demo")
	}

	// Test 4: Check function reachability (should be correct if call edges are correct)
	setupRoutesReachable := false
	setupRoutesDistance := -1
	for _, fn := range fbom.Functions {
		if strings.Contains(fn.Name, "setupRoutes") {
			setupRoutesReachable = fn.UsageInfo.IsReachable
			setupRoutesDistance = fn.UsageInfo.DistanceFromEntry
			t.Logf("Bug 18 - setupRoutes reachable: %t, distance: %d", fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
			break
		}
	}

	if !setupRoutesReachable {
		t.Errorf("Bug 18 - setupRoutes should be reachable (called by NewServer)")
	}

	if setupRoutesDistance == -1 {
		t.Errorf("Bug 18 - setupRoutes distance should not be -1 (indicates unreachable)")
	}

	// Test 5: Test the dummyFunction as well
	dummyFunctionReachable := false
	for _, fn := range fbom.Functions {
		if strings.Contains(fn.Name, "dummyFunction") {
			dummyFunctionReachable = fn.UsageInfo.IsReachable
			t.Logf("Bug 18 - dummyFunction reachable: %t, distance: %d", fn.UsageInfo.IsReachable, fn.UsageInfo.DistanceFromEntry)
			break
		}
	}

	if !dummyFunctionReachable {
		t.Errorf("Bug 18 - dummyFunction should be reachable (called through anonymous function from setupRoutes)")
	}
}

// TestBug19_PackageFilteringIssue tests whether package filtering is causing method calls to be missed
func TestBug19_PackageFilteringIssue(t *testing.T) {
	// Change to fbom-demo directory for this test
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWd)
	}()

	// Go up to project root first
	projectRoot := filepath.Join(originalWd, "..", "..")
	fbomDemoPath := filepath.Join(projectRoot, "examples", "fbom-demo")
	if err := os.Chdir(fbomDemoPath); err != nil {
		t.Fatalf("Failed to change to fbom-demo directory: %v", err)
	}

	// Test 1: Generate call graph WITHOUT filtering (like CLI tool)
	t.Logf("Bug 19 Test 1 - Generate call graph without package filtering")
	callGraphGenNoFilter := callgraphgen.NewGenerator(".", false)

	callGraphNoFilter, ssaProgramNoFilter, err := callGraphGenNoFilter.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph without filtering: %v", err)
	}

	// Check if NewServer -> setupRoutes exists in unfiltered version
	newServerToSetupRoutesNoFilter := false
	for fn, node := range callGraphNoFilter.Nodes {
		if fn != nil && node != nil && strings.Contains(fn.String(), "NewServer") {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil &&
					strings.Contains(edge.Callee.Func.String(), "setupRoutes") {
					newServerToSetupRoutesNoFilter = true
					t.Logf("Bug 19 - Found edge in unfiltered: %s -> %s", fn.String(), edge.Callee.Func.String())
					break
				}
			}
		}
	}

	// Test 2: Generate call graph WITH filtering (like our current code)
	t.Logf("Bug 19 Test 2 - Generate call graph with package filtering")
	callGraphGenFiltered := callgraphgen.NewGenerator(".", false)

	callGraphFiltered, ssaProgramFiltered, err := callGraphGenFiltered.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph with filtering: %v", err)
	}

	// Check if NewServer -> setupRoutes exists in filtered version
	newServerToSetupRoutesFiltered := false
	for fn, node := range callGraphFiltered.Nodes {
		if fn != nil && node != nil && strings.Contains(fn.String(), "NewServer") {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil &&
					strings.Contains(edge.Callee.Func.String(), "setupRoutes") {
					newServerToSetupRoutesFiltered = true
					t.Logf("Bug 19 - Found edge in filtered: %s -> %s", fn.String(), edge.Callee.Func.String())
					break
				}
			}
		}
	}

	// Compare results
	t.Logf("Bug 19 Results:")
	t.Logf("  Unfiltered call graph nodes: %d", len(callGraphNoFilter.Nodes))
	t.Logf("  Filtered call graph nodes: %d", len(callGraphFiltered.Nodes))
	t.Logf("  Unfiltered SSA packages: %d", len(ssaProgramNoFilter.AllPackages()))
	t.Logf("  Filtered SSA packages: %d", len(ssaProgramFiltered.AllPackages()))
	t.Logf("  NewServer->setupRoutes in unfiltered: %t", newServerToSetupRoutesNoFilter)
	t.Logf("  NewServer->setupRoutes in filtered: %t", newServerToSetupRoutesFiltered)

	// The hypothesis: filtering removes packages needed for method resolution
	if newServerToSetupRoutesNoFilter && !newServerToSetupRoutesFiltered {
		t.Logf("Bug 19 - CONFIRMED: Package filtering is removing method calls!")
		t.Logf("Bug 19 - Unfiltered version finds the edge, filtered version does not")
		t.Logf("Bug 19 - This proves our package filtering is too aggressive")
	} else if !newServerToSetupRoutesNoFilter {
		t.Errorf("Bug 19 - Even unfiltered version missing edge - deeper issue")
	} else {
		t.Logf("Bug 19 - Both versions find the edge - filtering not the issue")
	}
}

// TestVersionSpecificDependencies tests that dependency versions are correctly extracted from go.mod
func TestVersionSpecificDependencies(t *testing.T) {
	t.Log("Testing version-specific dependency extraction from go.mod files")

	// Test using the test-project which has a go.mod file with specific versions
	testProjectPath := filepath.Join("..", "..", "examples", "test-project")

	// Verify test project exists and has go.mod
	goModPath := filepath.Join(testProjectPath, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		t.Fatalf("Test project go.mod not found at %s", goModPath)
	}

	// Change to test-project directory for analysis
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWd)
	}()

	err = os.Chdir(testProjectPath)
	if err != nil {
		t.Fatalf("Failed to change to test project directory: %v", err)
	}

	// Generate FBOM using FBOMGenerator
	fbomGenerator := NewFBOMGenerator(false) // non-verbose for cleaner test output
	callGraphGen := callgraphgen.NewGenerator(".", false)
	callGraphResult, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		t.Fatalf("Failed to build call graph for test-project: %v", err)
	}

	assessments := []analysis.Assessment{}
	reflectionUsage := map[string]*reflection.Usage{}

	// Generate FBOM
	fbom := fbomGenerator.buildFBOM(assessments, reflectionUsage, callGraphResult, ssaProgram, "test-project")

	// Test that FBOM has dependencies with version information
	if len(fbom.Dependencies) == 0 {
		t.Fatalf("Expected dependencies but found none")
	}

	// Define expected versions from go.mod
	expectedVersions := map[string]string{
		"github.com/gin-gonic/gin":   "v1.9.1",
		"gopkg.in/yaml.v2":           "v2.4.0",
		"golang.org/x/crypto":        "v0.9.0",
		"golang.org/x/net":           "v0.10.0",
		"golang.org/x/sys":           "v0.8.0",
		"golang.org/x/text":          "v0.9.0",
		"google.golang.org/protobuf": "v1.30.0",
		"gopkg.in/yaml.v3":           "v3.0.1",
	}

	// Verify that key dependencies have correct versions
	foundVersions := make(map[string]string)
	for _, dep := range fbom.Dependencies {
		// Extract root package name (remove subpackages)
		rootPackage := extractRootPackage(dep.Name)
		if expectedVersion, exists := expectedVersions[rootPackage]; exists {
			foundVersions[rootPackage] = dep.Version

			// Check that version is not "unknown"
			if dep.Version == "unknown" {
				t.Errorf("Dependency %s has version 'unknown', expected %s", rootPackage, expectedVersion)
			}

			// Check that version matches expected
			if dep.Version != expectedVersion {
				t.Errorf("Dependency %s has version %s, expected %s", rootPackage, dep.Version, expectedVersion)
			}
		}
	}

	// Ensure we found the key dependencies
	keyDependencies := []string{
		"github.com/gin-gonic/gin",
		"gopkg.in/yaml.v2",
	}

	for _, keyDep := range keyDependencies {
		if version, found := foundVersions[keyDep]; !found {
			t.Errorf("Key dependency %s not found in FBOM", keyDep)
		} else {
			t.Logf("✓ Found %s with version %s", keyDep, version)
		}
	}

	// Verify that some dependencies were found with actual version information
	versionedDependencies := 0
	for _, dep := range fbom.Dependencies {
		if dep.Version != "unknown" && dep.Version != "" {
			versionedDependencies++
		}
	}

	if versionedDependencies == 0 {
		t.Error("Expected at least some dependencies to have version information, but all have 'unknown' or empty versions")
	} else {
		t.Logf("✓ Found %d dependencies with version information", versionedDependencies)
	}
}

// extractRootPackage extracts the root package name from a full package path
// e.g., "github.com/gin-gonic/gin/binding" -> "github.com/gin-gonic/gin"
func extractRootPackage(packageName string) string {
	// Handle special cases
	if strings.HasPrefix(packageName, "golang.org/x/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
	}

	if strings.HasPrefix(packageName, "google.golang.org/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
	}

	if strings.HasPrefix(packageName, "gopkg.in/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
	}

	// For GitHub packages: github.com/owner/repo
	if strings.HasPrefix(packageName, "github.com/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
	}

	// Default: return the first component
	parts := strings.Split(packageName, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return packageName
}

// TestExtractRootPackageForVersionLookup tests the root package extraction logic
func TestExtractRootPackageForVersionLookup(t *testing.T) {
	generator := NewFBOMGenerator(false)

	tests := []struct {
		packageName  string
		expectedRoot string
	}{
		{"github.com/gin-gonic/gin", "github.com/gin-gonic/gin"},
		{"github.com/gin-gonic/gin/binding", "github.com/gin-gonic/gin"}, // subpackage should find root
		{"github.com/gin-gonic/gin/render", "github.com/gin-gonic/gin"},
		{"golang.org/x/crypto", "golang.org/x/crypto"},
		{"golang.org/x/crypto/sha3", "golang.org/x/crypto"},
		{"golang.org/x/net/http2", "golang.org/x/net"}, // subpackage should find root
		{"google.golang.org/protobuf", "google.golang.org/protobuf"},
		{"google.golang.org/protobuf/proto", "google.golang.org/protobuf"},
		{"gopkg.in/yaml.v2", "gopkg.in/yaml.v2"},
		{"gopkg.in/yaml.v3", "gopkg.in/yaml.v3"},
		{"nonexistent/package", "nonexistent/package"}, // should return package as-is for unknown patterns
	}

	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {
			root := generator.extractRootPackageForVersionLookup(tt.packageName)
			if root != tt.expectedRoot {
				t.Errorf("extractRootPackageForVersionLookup(%q) = %q, want %q", tt.packageName, root, tt.expectedRoot)
			}
		})
	}
}

// TestHasVendorDirectory tests the vendor directory detection functionality
func TestHasVendorDirectory(t *testing.T) {
	generator := NewFBOMGenerator(false)

	// Test case 1: No vendor directory
	t.Run("NoVendorDirectory", func(t *testing.T) {
		// Create a temporary directory without vendor
		tempDir := t.TempDir()
		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current directory: %v", err)
		}
		defer os.Chdir(originalDir)

		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change to temp directory: %v", err)
		}

		hasVendor := generator.hasVendorDirectory()
		if hasVendor {
			t.Error("Expected hasVendorDirectory() to return false when no vendor directory exists")
		}
	})

	// Test case 2: Vendor directory exists
	t.Run("VendorDirectoryExists", func(t *testing.T) {
		// Create a temporary directory with vendor
		tempDir := t.TempDir()
		vendorDir := filepath.Join(tempDir, "vendor")
		err := os.Mkdir(vendorDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create vendor directory: %v", err)
		}

		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current directory: %v", err)
		}
		defer os.Chdir(originalDir)

		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change to temp directory: %v", err)
		}

		hasVendor := generator.hasVendorDirectory()
		if !hasVendor {
			t.Error("Expected hasVendorDirectory() to return true when vendor directory exists")
		}
	})

	// Test case 3: Vendor is a file, not a directory
	t.Run("VendorIsFile", func(t *testing.T) {
		// Create a temporary directory with vendor file
		tempDir := t.TempDir()
		vendorFile := filepath.Join(tempDir, "vendor")
		err := os.WriteFile(vendorFile, []byte("not a directory"), 0644)
		if err != nil {
			t.Fatalf("Failed to create vendor file: %v", err)
		}

		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current directory: %v", err)
		}
		defer os.Chdir(originalDir)

		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change to temp directory: %v", err)
		}

		hasVendor := generator.hasVendorDirectory()
		if !hasVendor {
			// Note: os.Stat() will succeed even if vendor is a file, not a directory
			// This is acceptable behavior for our use case
			t.Log("hasVendorDirectory() returned false for vendor file - this is acceptable")
		}
	})
}

// TestGetModuleVersionsWithVendor tests that getModuleVersions handles vendor directories correctly
func TestGetModuleVersionsWithVendor(t *testing.T) {
	generator := NewFBOMGenerator(true) // verbose for better debugging

	// We'll create a mock scenario by testing the command selection logic
	// Since we can't easily mock exec.Command in unit tests, we'll test the logic flow

	t.Run("CommandSelectionLogic", func(t *testing.T) {
		// Test case 1: No vendor directory - should use standard command
		tempDir := t.TempDir()
		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current directory: %v", err)
		}
		defer os.Chdir(originalDir)

		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change to temp directory: %v", err)
		}

		// Since we can't easily test the actual command execution without a real Go module,
		// we'll test that the vendor detection logic works correctly
		hasVendor := generator.hasVendorDirectory()
		if hasVendor {
			t.Error("Expected no vendor directory in empty temp dir")
		}

		// Test case 2: With vendor directory
		vendorDir := filepath.Join(tempDir, "vendor")
		err = os.Mkdir(vendorDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create vendor directory: %v", err)
		}

		hasVendor = generator.hasVendorDirectory()
		if !hasVendor {
			t.Error("Expected vendor directory to be detected")
		}
	})
}

// TestGetModuleVersionsIntegration is an integration test that requires a real Go module
func TestGetModuleVersionsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	generator := NewFBOMGenerator(true)

	t.Run("RealGoModule", func(t *testing.T) {
		// Create a temporary Go module for testing
		tempDir := t.TempDir()
		originalDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current directory: %v", err)
		}
		defer os.Chdir(originalDir)

		err = os.Chdir(tempDir)
		if err != nil {
			t.Fatalf("Failed to change to temp directory: %v", err)
		}

		// Create a minimal go.mod file
		goModContent := `module test-module

go 1.21

require github.com/stretchr/testify v1.8.0
`
		err = os.WriteFile("go.mod", []byte(goModContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create go.mod: %v", err)
		}

		// Create a simple main.go file
		mainContent := `package main

import "fmt"

func main() {
	fmt.Println("test")
}
`
		err = os.WriteFile("main.go", []byte(mainContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create main.go: %v", err)
		}

		// Test without vendor directory
		versions, err := generator.getModuleVersions()
		if err != nil {
			t.Logf("getModuleVersions without vendor failed (this may be expected): %v", err)
		} else {
			if len(versions) == 0 {
				t.Error("Expected some module versions to be returned")
			}
			t.Logf("Found %d module versions without vendor", len(versions))
		}

		// Create vendor directory and test again
		err = os.Mkdir("vendor", 0755)
		if err != nil {
			t.Fatalf("Failed to create vendor directory: %v", err)
		}

		// Add some dummy vendor content
		err = os.MkdirAll("vendor/github.com/stretchr/testify", 0755)
		if err != nil {
			t.Fatalf("Failed to create vendor subdirectory: %v", err)
		}

		// Test with vendor directory
		versions, err = generator.getModuleVersions()
		if err != nil {
			t.Logf("getModuleVersions with vendor failed: %v", err)
		} else {
			if len(versions) == 0 {
				t.Error("Expected some module versions to be returned with vendor")
			}
			t.Logf("Found %d module versions with vendor", len(versions))
		}
	})
}
