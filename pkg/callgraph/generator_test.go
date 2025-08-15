package callgraph

// NOTE: This test file was generated using AI assistance.
// While the tests have been validated and are functional,
// they should be reviewed and potentially enhanced by human developers.

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
)

// Test helper functions

func createTestModule() (string, error) {
	tmpDir, err := os.MkdirTemp("", "test_module_*")
	if err != nil {
		return "", err
	}

	// Create go.mod
	goModContent := `module test.example/callgraph

go 1.19
`
	err = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	// Create main.go with some functions
	mainContent := `package main

import "fmt"

func main() {
	hello()
	world()
}

func hello() {
	fmt.Println("Hello")
	internal()
}

func world() {
	fmt.Println("World")
}

func internal() {
	fmt.Println("Internal")
}

func init() {
	fmt.Println("Initializing")
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainContent), 0644)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	return tmpDir, nil
}

func TestNewGenerator(t *testing.T) {
	tests := []struct {
		name        string
		packagePath string
		verbose     bool
	}{
		{
			name:        "basic generator",
			packagePath: "./testpackage",
			verbose:     false,
		},
		{
			name:        "verbose generator",
			packagePath: "github.com/example/project",
			verbose:     true,
		},
		{
			name:        "current directory",
			packagePath: ".",
			verbose:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewGenerator(tt.packagePath, tt.verbose)
			if generator == nil {
				t.Fatal("NewGenerator() returned nil")
			}
			if generator.packagePath != tt.packagePath {
				t.Errorf("Expected packagePath %s, got %s", tt.packagePath, generator.packagePath)
			}
			if generator.verbose != tt.verbose {
				t.Errorf("Expected verbose %v, got %v", tt.verbose, generator.verbose)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	// Create a test module
	tmpDir, err := createTestModule()
	if err != nil {
		t.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Change to test directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	tests := []struct {
		name        string
		packagePath string
		verbose     bool
		wantErr     bool
	}{
		{
			name:        "generate for current directory",
			packagePath: ".",
			verbose:     true,
			wantErr:     false,
		},
		{
			name:        "generate for module",
			packagePath: "test.example/callgraph",
			verbose:     false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewGenerator(tt.packagePath, tt.verbose)

			graph, program, err := generator.Generate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if graph == nil {
					t.Error("Expected call graph to be generated")
					return // Early return to avoid nil dereference
				}
				if program == nil {
					t.Error("Expected SSA program to be generated")
				}

				// Verify that we have some nodes in the graph
				if len(graph.Nodes) == 0 {
					t.Error("Expected call graph to have nodes")
				}

				// Verify that main function exists
				mainFound := false
				for _, node := range graph.Nodes {
					if node.Func != nil && strings.Contains(node.Func.String(), "main") {
						mainFound = true
						break
					}
				}
				if !mainFound {
					t.Error("Expected to find main function in call graph")
				}
			}
		})
	}
}

func TestGenerateErrors(t *testing.T) {
	tests := []struct {
		name        string
		packagePath string
		expectErr   bool
	}{
		{
			name:        "invalid package path",
			packagePath: "/nonexistent/invalid/path",
			expectErr:   true,
		},
		{
			name:        "empty package path",
			packagePath: "",
			expectErr:   false, // Empty package path defaults to current directory, which can work
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewGenerator(tt.packagePath, false)
			_, _, err := generator.Generate()

			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGetFunctionInfo(t *testing.T) {
	// Create a mock function and node
	fset := token.NewFileSet()

	tests := []struct {
		name     string
		node     *callgraph.Node
		expected *CallGraphInfo
	}{
		{
			name: "nil function",
			node: &callgraph.Node{
				Func: nil,
			},
			expected: nil,
		},
		{
			name:     "nil node",
			node:     nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetFunctionInfo(tt.node, fset)
			if (result == nil) != (tt.expected == nil) {
				t.Errorf("Expected nil result: %v, got nil result: %v", tt.expected == nil, result == nil)
			}
		})
	}
}

func TestFindFunctionByName(t *testing.T) {
	// Create a test module and generate call graph
	tmpDir, err := createTestModule()
	if err != nil {
		t.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Change to test directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	generator := NewGenerator(".", false)
	graph, _, err := generator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph: %v", err)
	}

	tests := []struct {
		name         string
		packagePath  string
		functionName string
		expectFound  bool
	}{
		{
			name:         "find main function",
			packagePath:  "test.example/callgraph",
			functionName: "main",
			expectFound:  true,
		},
		{
			name:         "find hello function",
			packagePath:  "test.example/callgraph",
			functionName: "hello",
			expectFound:  true,
		},
		{
			name:         "find nonexistent function",
			packagePath:  "test.example/callgraph",
			functionName: "nonexistent",
			expectFound:  false,
		},
		{
			name:         "wrong package path",
			packagePath:  "wrong.package",
			functionName: "main",
			expectFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := FindFunctionByName(graph, tt.packagePath, tt.functionName)

			if tt.expectFound && len(results) == 0 {
				t.Errorf("Expected to find function %s in package %s", tt.functionName, tt.packagePath)
			}
			if !tt.expectFound && len(results) > 0 {
				t.Errorf("Did not expect to find function %s in package %s", tt.functionName, tt.packagePath)
			}

			// Verify that all results match the criteria
			for _, result := range results {
				if result.Func == nil {
					t.Error("Found node with nil function")
					continue
				}
				if result.Func.Pkg == nil {
					t.Error("Found function with nil package")
					continue
				}
				if result.Func.Pkg.Pkg.Path() != tt.packagePath {
					t.Errorf("Expected package %s, got %s", tt.packagePath, result.Func.Pkg.Pkg.Path())
				}
			}
		})
	}
}

func TestGetCallersOf(t *testing.T) {
	// Create a test module and generate call graph
	tmpDir, err := createTestModule()
	if err != nil {
		t.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Change to test directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	generator := NewGenerator(".", false)
	graph, _, err := generator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph: %v", err)
	}

	// Find the hello function
	helloNodes := FindFunctionByName(graph, "test.example/callgraph", "hello")
	if len(helloNodes) == 0 {
		t.Fatal("Could not find hello function for testing")
	}

	helloNode := helloNodes[0]
	callers := GetCallersOf(helloNode)

	// hello should be called by main
	found := false
	for _, caller := range callers {
		if caller.Func != nil && strings.Contains(caller.Func.String(), "main") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected hello function to be called by main")
	}
}

func TestGetCalleesOf(t *testing.T) {
	// Create a test module and generate call graph
	tmpDir, err := createTestModule()
	if err != nil {
		t.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Change to test directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	generator := NewGenerator(".", false)
	graph, _, err := generator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph: %v", err)
	}

	// Find the main function
	mainNodes := FindFunctionByName(graph, "test.example/callgraph", "main")
	if len(mainNodes) == 0 {
		t.Fatal("Could not find main function for testing")
	}

	mainNode := mainNodes[0]
	callees := GetCalleesOf(mainNode)

	// main should call hello and world
	foundHello := false
	foundWorld := false

	for _, callee := range callees {
		if callee.Func != nil {
			funcName := callee.Func.String()
			if strings.Contains(funcName, "hello") {
				foundHello = true
			}
			if strings.Contains(funcName, "world") {
				foundWorld = true
			}
		}
	}

	if !foundHello {
		t.Error("Expected main function to call hello")
	}
	if !foundWorld {
		t.Error("Expected main function to call world")
	}
}

func TestGetCallersOfEmptyNode(t *testing.T) {
	// Test with a node that has no incoming edges
	node := &callgraph.Node{
		In: []*callgraph.Edge{},
	}

	callers := GetCallersOf(node)
	if len(callers) != 0 {
		t.Errorf("Expected 0 callers for empty node, got %d", len(callers))
	}
}

func TestGetCalleesOfEmptyNode(t *testing.T) {
	// Test with a node that has no outgoing edges
	node := &callgraph.Node{
		Out: []*callgraph.Edge{},
	}

	callees := GetCalleesOf(node)
	if len(callees) != 0 {
		t.Errorf("Expected 0 callees for empty node, got %d", len(callees))
	}
}

func TestEdgeTraversal(t *testing.T) {
	// Create nodes
	node1 := &callgraph.Node{}
	node2 := &callgraph.Node{}
	node3 := &callgraph.Node{}

	// Create edges: node1 -> node2, node2 -> node3
	edge1 := &callgraph.Edge{
		Caller: node1,
		Callee: node2,
	}
	edge2 := &callgraph.Edge{
		Caller: node2,
		Callee: node3,
	}

	// Set up the graph connections
	node1.Out = []*callgraph.Edge{edge1}
	node2.In = []*callgraph.Edge{edge1}
	node2.Out = []*callgraph.Edge{edge2}
	node3.In = []*callgraph.Edge{edge2}

	// Test GetCallersOf
	callersOfNode2 := GetCallersOf(node2)
	if len(callersOfNode2) != 1 {
		t.Errorf("Expected 1 caller of node2, got %d", len(callersOfNode2))
	}
	if len(callersOfNode2) > 0 && callersOfNode2[0] != node1 {
		t.Error("Expected node1 to be caller of node2")
	}

	// Test GetCalleesOf
	calleesOfNode2 := GetCalleesOf(node2)
	if len(calleesOfNode2) != 1 {
		t.Errorf("Expected 1 callee of node2, got %d", len(calleesOfNode2))
	}
	if len(calleesOfNode2) > 0 && calleesOfNode2[0] != node3 {
		t.Error("Expected node3 to be callee of node2")
	}
}

func TestNilEdgeHandling(t *testing.T) {
	// Test with edges that have nil callers/callees
	node := &callgraph.Node{
		In: []*callgraph.Edge{
			{Caller: nil, Callee: &callgraph.Node{}},
			{Caller: &callgraph.Node{}, Callee: &callgraph.Node{}},
		},
		Out: []*callgraph.Edge{
			{Caller: &callgraph.Node{}, Callee: nil},
			{Caller: &callgraph.Node{}, Callee: &callgraph.Node{}},
		},
	}

	callers := GetCallersOf(node)
	// Should only get the non-nil caller
	if len(callers) != 1 {
		t.Errorf("Expected 1 non-nil caller, got %d", len(callers))
	}

	callees := GetCalleesOf(node)
	// Should only get the non-nil callee
	if len(callees) != 1 {
		t.Errorf("Expected 1 non-nil callee, got %d", len(callees))
	}
}

// Integration test
func TestCallGraphWorkflow(t *testing.T) {
	// Create a more complex test module
	tmpDir, err := os.MkdirTemp("", "test_complex_*")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create go.mod
	goModContent := `module test.example/complex

go 1.19
`
	err = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Create complex main.go
	mainContent := `package main

import "fmt"

func main() {
	processData()
	cleanup()
}

func processData() {
	data := getData()
	transformData(data)
	saveData(data)
}

func getData() string {
	return "test data"
}

func transformData(data string) {
	fmt.Println("Transforming:", data)
	validateData(data)
}

func validateData(data string) {
	if len(data) == 0 {
		panic("empty data")
	}
}

func saveData(data string) {
	fmt.Println("Saving:", data)
}

func cleanup() {
	fmt.Println("Cleaning up")
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Change to test directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Generate call graph
	generator := NewGenerator(".", true) // Enable verbose
	graph, program, err := generator.Generate()
	if err != nil {
		t.Fatalf("Failed to generate call graph: %v", err)
	}

	// Verify the complete workflow
	if graph == nil {
		t.Fatal("Call graph should not be nil")
	}
	if program == nil {
		t.Fatal("SSA program should not be nil")
	}

	// Verify we can find all functions
	expectedFunctions := []string{"main", "processData", "getData", "transformData", "validateData", "saveData", "cleanup"}
	packagePath := "test.example/complex"

	for _, funcName := range expectedFunctions {
		nodes := FindFunctionByName(graph, packagePath, funcName)
		if len(nodes) == 0 {
			t.Errorf("Failed to find function %s", funcName)
		}
	}

	// Verify call relationships
	mainNodes := FindFunctionByName(graph, packagePath, "main")
	if len(mainNodes) > 0 {
		callees := GetCalleesOf(mainNodes[0])
		// main should call processData and cleanup
		foundProcessData := false
		foundCleanup := false

		for _, callee := range callees {
			if callee.Func != nil {
				funcName := callee.Func.String()
				if strings.Contains(funcName, "processData") {
					foundProcessData = true
				}
				if strings.Contains(funcName, "cleanup") {
					foundCleanup = true
				}
			}
		}

		if !foundProcessData {
			t.Error("main should call processData")
		}
		if !foundCleanup {
			t.Error("main should call cleanup")
		}
	}

	// Test function info extraction
	if len(mainNodes) > 0 {
		fset := token.NewFileSet()
		info := GetFunctionInfo(mainNodes[0], fset)
		if info == nil {
			t.Error("Failed to get function info for main")
		} else {
			if info.PackagePath != packagePath {
				t.Errorf("Expected package path %s, got %s", packagePath, info.PackagePath)
			}
			if info.FunctionName != "main" {
				t.Errorf("Expected function name main, got %s", info.FunctionName)
			}
		}
	}
}

// Benchmark tests
func BenchmarkGenerate(b *testing.B) {
	tmpDir, err := createTestModule()
	if err != nil {
		b.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	originalDir, err := os.Getwd()
	if err != nil {
		b.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	err = os.Chdir(tmpDir)
	if err != nil {
		b.Fatalf("Failed to change directory: %v", err)
	}

	generator := NewGenerator(".", false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := generator.Generate()
		if err != nil {
			b.Fatalf("Generate failed: %v", err)
		}
	}
}

func BenchmarkFindFunctionByName(b *testing.B) {
	tmpDir, err := createTestModule()
	if err != nil {
		b.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	originalDir, err := os.Getwd()
	if err != nil {
		b.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	err = os.Chdir(tmpDir)
	if err != nil {
		b.Fatalf("Failed to change directory: %v", err)
	}

	generator := NewGenerator(".", false)
	graph, _, err := generator.Generate()
	if err != nil {
		b.Fatalf("Failed to generate call graph: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FindFunctionByName(graph, "test.example/callgraph", "main")
	}
}

func BenchmarkGetCallersOf(b *testing.B) {
	tmpDir, err := createTestModule()
	if err != nil {
		b.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	originalDir, err := os.Getwd()
	if err != nil {
		b.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	err = os.Chdir(tmpDir)
	if err != nil {
		b.Fatalf("Failed to change directory: %v", err)
	}

	generator := NewGenerator(".", false)
	graph, _, err := generator.Generate()
	if err != nil {
		b.Fatalf("Failed to generate call graph: %v", err)
	}

	nodes := FindFunctionByName(graph, "test.example/callgraph", "hello")
	if len(nodes) == 0 {
		b.Fatal("Could not find hello function")
	}

	node := nodes[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetCallersOf(node)
	}
}

// TestAlgorithmSelection tests that the Generator can use different call graph algorithms
func TestAlgorithmSelection(t *testing.T) {
	// Create a test module
	tmpDir, err := createTestModule()
	if err != nil {
		t.Fatalf("Failed to create test module: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Change to test directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{
			name:      "RTA algorithm",
			algorithm: "rta",
			wantErr:   false,
		},
		{
			name:      "CHA algorithm",
			algorithm: "cha",
			wantErr:   false,
		},
		{
			name:      "Static algorithm",
			algorithm: "static",
			wantErr:   false,
		},
		{
			name:      "VTA algorithm",
			algorithm: "vta",
			wantErr:   false,
		},
		{
			name:      "Invalid algorithm",
			algorithm: "invalid",
			wantErr:   true,
		},
		{
			name:      "Empty algorithm defaults to RTA",
			algorithm: "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewGenerator(".", false)

			// Set the algorithm
			err := generator.SetAlgorithm(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return // Skip graph generation for invalid algorithms
			}

			// Test that we can generate a call graph with the selected algorithm
			graph, program, err := generator.Generate()
			if err != nil {
				t.Errorf("Generate() failed with algorithm %s: %v", tt.algorithm, err)
				return
			}

			if graph == nil {
				t.Errorf("Expected call graph to be generated with algorithm %s", tt.algorithm)
				return
			}
			if program == nil {
				t.Errorf("Expected SSA program to be generated with algorithm %s", tt.algorithm)
				return
			}

			// Verify that we have some nodes in the graph
			if len(graph.Nodes) == 0 {
				t.Errorf("Expected call graph to have nodes with algorithm %s", tt.algorithm)
			}

			// Verify that main function exists (basic sanity check)
			mainFound := false
			for _, node := range graph.Nodes {
				if node.Func != nil && strings.Contains(node.Func.String(), "main") {
					mainFound = true
					break
				}
			}
			if !mainFound {
				t.Errorf("Expected to find main function in call graph with algorithm %s", tt.algorithm)
			}
		})
	}
}

// TestGetAlgorithm tests that we can retrieve the currently set algorithm
func TestGetAlgorithm(t *testing.T) {
	generator := NewGenerator(".", false)

	// Test default algorithm
	if generator.GetAlgorithm() != "rta" {
		t.Errorf("Expected default algorithm to be 'rta', got '%s'", generator.GetAlgorithm())
	}

	// Test setting and getting different algorithms
	algorithms := []string{"rta", "cha", "static", "vta"}
	for _, algo := range algorithms {
		err := generator.SetAlgorithm(algo)
		if err != nil {
			t.Fatalf("SetAlgorithm(%s) failed: %v", algo, err)
		}
		if generator.GetAlgorithm() != algo {
			t.Errorf("Expected algorithm to be '%s', got '%s'", algo, generator.GetAlgorithm())
		}
	}
}
