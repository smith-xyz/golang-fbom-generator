// Package shared contains common test utilities used across different test packages
package shared

import (
	"os"
	"path/filepath"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Call Graph Building Helpers
// These functions help create call graphs from inline test code for testing FBOM generation.

// BuildCallGraphFromCode creates a call graph from Go source code.
// This is the main helper function to use in tests.
//
// It creates a temporary module with the provided code and returns
// the call graph and SSA program. The temporary directory is automatically
// cleaned up when this function returns.
//
// Example usage:
//
//	callGraph, ssaProgram, err := shared.BuildCallGraphFromCode(`
//	  package main
//	  func main() { fmt.Println("hello") }
//	`)
func BuildCallGraphFromCode(code string) (*callgraph.Graph, *ssa.Program, error) {
	callGraph, ssaProgram, tmpDir, err := BuildCallGraphFromCodeWithDir(code)
	if tmpDir != "" {
		defer os.RemoveAll(tmpDir)
	}
	return callGraph, ssaProgram, err
}

// BuildCallGraphFromCodeWithDir creates a call graph from Go source code
// and returns the temporary directory path for manual cleanup.
//
// Use this function when you need to control the cleanup of the temporary
// directory yourself, such as when you need to change the working directory
// to the temporary module for context-aware testing.
//
// Example usage for context-aware testing:
//
//	callGraph, ssaProgram, tmpDir, err := shared.BuildCallGraphFromCodeWithDir(testCode)
//	defer os.RemoveAll(tmpDir)
//
//	// Change to temp dir for proper context detection
//	originalDir, _ := os.Getwd()
//	defer os.Chdir(originalDir)
//	os.Chdir(tmpDir)
//
//	// Now create FBOM generator - it will detect the temporary module
//	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())
func BuildCallGraphFromCodeWithDir(code string) (*callgraph.Graph, *ssa.Program, string, error) {
	// Create a temporary directory for the test module
	tmpDir, err := os.MkdirTemp("", "fbom_test")
	if err != nil {
		return nil, nil, "", err
	}

	// Write the Go code to a main.go file
	mainGoPath := filepath.Join(tmpDir, "main.go")
	err = os.WriteFile(mainGoPath, []byte(code), 0600)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a go.mod file defining a test module
	goModPath := filepath.Join(tmpDir, "go.mod")
	goModContent := `module testmodule
go 1.21
`
	err = os.WriteFile(goModPath, []byte(goModContent), 0600)
	if err != nil {
		return nil, nil, "", err
	}

	// Load the package using go/packages
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  tmpDir,
	}

	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		return nil, nil, "", err
	}
	if len(pkgs) == 0 {
		return nil, nil, "", err
	}

	// Build SSA representation
	prog, _ := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	// Find the main package
	var mainPkg *ssa.Package
	for _, pkg := range prog.AllPackages() {
		if pkg.Pkg.Name() == "main" {
			mainPkg = pkg
			break
		}
	}

	if mainPkg == nil {
		return nil, nil, "", err
	}

	// Build call graph using Rapid Type Analysis (RTA)
	var roots []*ssa.Function
	if mainPkg.Func("main") != nil {
		roots = append(roots, mainPkg.Func("main"))
	}

	// Include init functions as entry points
	if mainPkg.Func("init") != nil {
		roots = append(roots, mainPkg.Func("init"))
	}

	graph := rta.Analyze(roots, true)

	return graph.CallGraph, prog, tmpDir, nil
}

// CreateTestModule creates a temporary directory with a Go module
// containing the provided source code.
//
// This is a lower-level helper for when you need more control over
// the module setup but don't need call graph generation.
//
// Returns the temporary directory path which must be cleaned up by the caller.
func CreateTestModule(code string, moduleName string) (string, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "fbom_test_module")
	if err != nil {
		return "", err
	}

	// Write source code
	mainGoPath := filepath.Join(tmpDir, "main.go")
	err = os.WriteFile(mainGoPath, []byte(code), 0600)
	if err != nil {
		return "", err
	}

	// Create go.mod
	goModPath := filepath.Join(tmpDir, "go.mod")
	goModContent := "module " + moduleName + "\ngo 1.21\n"
	err = os.WriteFile(goModPath, []byte(goModContent), 0600)
	if err != nil {
		return "", err
	}

	return tmpDir, nil
}
