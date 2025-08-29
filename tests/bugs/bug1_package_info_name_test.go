package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug1_PackageInfoName tests that package_info.name is the module name, not the package name
//
// Bug Description:
// The FBOM package_info.name field was incorrectly set to the package name ("main")
// instead of the actual module name from go.mod. This made it difficult to identify
// which module/project the FBOM was generated for.
//
// Expected: package_info.name should be the module name from go.mod
// Actual (buggy): package_info.name was set to the package name
func TestBug1_PackageInfoName(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	fmt.Println("Hello world!")
}
`

	callGraph, ssaProgram, tmpDir, err := shared.BuildCallGraphFromCodeWithDir(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory and change to test module directory
	// This is crucial so the context-aware config detects the temporary "testmodule"
	// instead of the "golang-fbom-generator/tests/bugs" module we're running from
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change to test directory: %v", err)
	}

	// Now create the generator in the context of the temporary module
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Bug: package_info.name should be the actual module name, not "main" (the package name)
	// Now that we've changed to the temporary directory, it should detect "testmodule"
	expectedPackageName := "testmodule"
	if fbom.PackageInfo.Name != expectedPackageName {
		t.Errorf("Bug 1 - Package info name incorrect: expected %q, got %q", expectedPackageName, fbom.PackageInfo.Name)
	}
}
