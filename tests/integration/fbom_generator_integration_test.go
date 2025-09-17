package integration

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// Integration tests that actually build real call graphs and test the full FBOM generation pipeline

func TestFBOMGenerator_RealGoCode(t *testing.T) {
	// Create a simple Go program for testing
	testCode := `
package main

import "fmt"

func main() {
	processData("hello")
	fmt.Println("world")
}

func processData(input string) string {
	return "processed: " + input
}

func unusedFunction() {
	// This should not appear in the call graph
}
`

	// Build real SSA and call graph from the test code first
	callGraph, ssaProgram, tmpDir, err := buildCallGraphFromCodeWithDir(testCode)
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
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig()) // Use non-verbose for cleaner test output

	// Generate FBOM with real data
	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Test that it found user-defined functions
	if len(fbom.Functions) == 0 {
		t.Error("Expected to find user-defined functions")
	}

	// Check that we have the main function
	var foundMain bool
	var foundProcessData bool
	var foundFmtPrintln bool

	for _, fn := range fbom.Functions {
		switch fn.Name {
		case "main":
			foundMain = true
			if fn.FunctionType != "main" {
				t.Errorf("Expected main function type 'main', got %s", fn.FunctionType)
			}
		case "processData":
			foundProcessData = true
			if fn.FunctionType != "regular" {
				t.Errorf("Expected processData function type 'regular', got %s", fn.FunctionType)
			}
		case "unusedFunction":
			// unusedFunction might not be found if it's not reachable from main
		case "Println":
			if fn.Package == "fmt" {
				foundFmtPrintln = true
				t.Errorf("Found fmt.Println in user functions - should be filtered out")
			}
		}
	}

	if !foundMain {
		t.Error("Expected to find main function")
	}

	if !foundProcessData {
		t.Error("Expected to find processData function")
	}

	// Note: unusedFunction might not be found if it's not reachable from main
	// This is actually correct behavior for a call graph analysis

	if foundFmtPrintln {
		t.Error("Should not include standard library functions like fmt.Println")
	}

	// Test call relationships
	var mainFunc models.Function
	for _, fn := range fbom.Functions {
		if fn.Name == "main" {
			mainFunc = fn
			break
		}
	}

	if len(mainFunc.UsageInfo.Calls) == 0 {
		t.Error("Expected main function to have outgoing calls")
	}

	// Test entry points
	if len(fbom.EntryPoints) == 0 {
		t.Error("Expected to find entry points")
	}

	var foundMainEntry bool
	for _, ep := range fbom.EntryPoints {
		if ep.Name == "main" && ep.Type == "main" {
			foundMainEntry = true
		}
	}

	if !foundMainEntry {
		t.Error("Expected to find main as an entry point")
	}
}

func TestFBOMGenerator_WithReflection(t *testing.T) {
	// Test code that uses reflection
	testCode := `
package main

import (
	"fmt"
	"reflect"
)

func main() {
	useReflection("test")
}

func useReflection(input interface{}) {
	v := reflect.ValueOf(input)
	fmt.Println(v.Type())
}
`

	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig()) // Use non-verbose for cleaner test output

	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	// Mock reflection usage detection
	reflectionUsage := map[string]*models.Usage{
		"testmodule.useReflection": {
			FunctionName:   "useReflection",
			UsesReflection: true,
			ReflectionRisk: models.RiskMedium,
		},
	}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Check that reflection information is captured
	if fbom.SecurityInfo.ReflectionCallsCount != 1 {
		t.Errorf("Expected 1 reflection call, got %d", fbom.SecurityInfo.ReflectionCallsCount)
	}

	// Find the useReflection function and check it has reflection access
	var foundReflectionFunc bool
	for _, fn := range fbom.Functions {
		if fn.Name == "useReflection" {
			foundReflectionFunc = true
			if !fn.UsageInfo.HasReflectionAccess {
				t.Error("Expected useReflection function to have reflection access")
			}
		}
	}

	if !foundReflectionFunc {
		t.Error("Expected to find useReflection function")
	}
}

func TestFBOMGenerator_WithCVE(t *testing.T) {
	testCode := `
package main

func main() {
	vulnerableFunction()
}

func vulnerableFunction() {
	// This function will be marked as vulnerable in our test
}
`

	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig()) // Use non-verbose for cleaner test output

	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}

	// Create a mock CVE assessment
	// Create CVE database for testing
	cveDB := &cveloader.CVEDatabase{
		CVEs: []models.CVE{
			{
				ID:                  "CVE-2023-TEST",
				VulnerablePackage:   "main",
				VulnerableFunctions: []string{"vulnerableFunction"},
			},
		},
	}

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(cveDB, reflectionUsage, callGraph, ssaProgram, "main")

	// Check that CVE information is captured
	if fbom.SecurityInfo.TotalCVEsFound != 1 {
		t.Errorf("Expected 1 CVE found, got %d", fbom.SecurityInfo.TotalCVEsFound)
	}

	// Note: Our simplified implementation might not fully process CVE functions
	// This test verifies the structure is in place for future CVE processing
}

func TestFBOMGenerator_FilteringBehavior(t *testing.T) {
	// Test that verifies our filtering actually works
	testCode := `
package main

import (
	"fmt"
	"strings"
)

func main() {
	userFunction()
	fmt.Println("test")
	strings.Contains("a", "b")
}

func userFunction() {
	// User-defined function
}
`

	callGraph, ssaProgram, tmpDir, err := buildCallGraphFromCodeWithDir(testCode)
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

	// Create generator in the context of the test module
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig()) // Use non-verbose for cleaner test output

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Verify filtering behavior
	for _, fn := range fbom.Functions {
		// Should only contain user-defined functions (testmodule package functions)
		if fn.Package != "testmodule" {
			t.Errorf("Found non-user function %s from package %s - should be filtered out", fn.Name, fn.Package)
		}

		// Should not contain standard library functions
		if generator.GetRules().Classifier.IsStandardLibraryPackage(fn.Package) {
			t.Errorf("Found standard library function %s from package %s - should be filtered out", fn.Name, fn.Package)
		}

		// Should not contain dependency functions
		if generator.GetRules().Classifier.IsDependencyPackage(fn.Package) {
			t.Errorf("Found dependency function %s from package %s - should be filtered out", fn.Name, fn.Package)
		}
	}

	// Should have at least main and userFunction
	if len(fbom.Functions) < 2 {
		t.Errorf("Expected at least 2 user functions (main, userFunction), got %d", len(fbom.Functions))
	}
}

// Helper function to build a call graph from Go source code (cleans up temp dir)
func buildCallGraphFromCode(code string) (*callgraph.Graph, *ssa.Program, error) {
	callGraph, ssaProgram, tmpDir, err := buildCallGraphFromCodeWithDir(code)
	if tmpDir != "" {
		defer os.RemoveAll(tmpDir)
	}
	return callGraph, ssaProgram, err
}

// Helper function to build a call graph from Go source code (returns temp dir for caller to clean up)
func buildCallGraphFromCodeWithDir(code string) (*callgraph.Graph, *ssa.Program, string, error) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "fbom_test")
	if err != nil {
		return nil, nil, "", err
	}

	// Write the code to a file in the temporary directory
	mainGoPath := filepath.Join(tmpDir, "main.go")
	err = os.WriteFile(mainGoPath, []byte(code), 0644)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a go.mod file
	goModPath := filepath.Join(tmpDir, "go.mod")
	goModContent := `module testmodule
go 1.21
`
	err = os.WriteFile(goModPath, []byte(goModContent), 0644)
	if err != nil {
		return nil, nil, "", err
	}

	// Use go/packages to load the package (modern approach)
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

	// Build SSA program
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

	// Build call graph using RTA
	var roots []*ssa.Function
	if mainPkg.Func("main") != nil {
		roots = append(roots, mainPkg.Func("main"))
	}

	// Add init functions
	if mainPkg.Func("init") != nil {
		roots = append(roots, mainPkg.Func("init"))
	}

	graph := rta.Analyze(roots, true)

	return graph.CallGraph, prog, tmpDir, nil
}

// Benchmark test to see if our optimizations actually matter
func BenchmarkFBOMGeneration(b *testing.B) {
	testCode := `
package main

import "fmt"

func main() {
	for i := 0; i < 10; i++ {
		processData(fmt.Sprintf("item %d", i))
	}
}

func processData(input string) string {
	return "processed: " + input
}
`

	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig()) // Non-verbose for benchmarking

	callGraph, ssaProgram, err := buildCallGraphFromCode(testCode)
	if err != nil {
		b.Fatalf("Failed to build call graph: %v", err)
	}

	reflectionUsage := map[string]*models.Usage{}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")
	}
}
