package generator

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

func TestDiscoverMainFunctions(t *testing.T) {
	// Create a temporary directory structure that mimics multi-component-project
	tempDir := t.TempDir()

	// Create the directory structure
	createTestProjectStructure(t, tempDir)

	tests := []struct {
		name     string
		basePath string
		expected []MainFunctionInfo
	}{
		{
			name:     "Discover all main functions in multi-component project",
			basePath: tempDir,
			expected: []MainFunctionInfo{
				{
					PackagePath: "github.com/example/test-project",
					FilePath:    filepath.Join(tempDir, "main.go"),
					Directory:   tempDir,
				},
				{
					PackagePath: "github.com/example/test-project/cmd/controller",
					FilePath:    filepath.Join(tempDir, "cmd", "controller", "main.go"),
					Directory:   filepath.Join(tempDir, "cmd", "controller"),
				},
				{
					PackagePath: "github.com/example/test-project/cmd/cli",
					FilePath:    filepath.Join(tempDir, "cmd", "cli", "main.go"),
					Directory:   filepath.Join(tempDir, "cmd", "cli"),
				},
				{
					PackagePath: "github.com/example/test-project/cmd/operator",
					FilePath:    filepath.Join(tempDir, "cmd", "operator", "main.go"),
					Directory:   filepath.Join(tempDir, "cmd", "operator"),
				},
				{
					PackagePath: "github.com/example/test-project/component-operator",
					FilePath:    filepath.Join(tempDir, "component-operator", "main.go"),
					Directory:   filepath.Join(tempDir, "component-operator"),
				},
				{
					PackagePath: "github.com/example/test-project/control-plane-operator",
					FilePath:    filepath.Join(tempDir, "control-plane-operator", "main.go"),
					Directory:   filepath.Join(tempDir, "control-plane-operator"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DiscoverMainFunctions(tt.basePath)
			if err != nil {
				t.Fatalf("DiscoverMainFunctions() error = %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d main functions, got %d. Found: %v",
					len(tt.expected), len(result), result)
			}

			// Sort both slices by PackagePath for reliable comparison
			sortMainFunctionInfos(result)
			sortMainFunctionInfos(tt.expected)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DiscoverMainFunctions() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDiscoverMainFunctions_NoMainFiles(t *testing.T) {
	// Create a temporary directory with no main.go files
	tempDir := t.TempDir()

	// Create go.mod file (required for module name detection)
	goModContent := `module github.com/example/no-main-project

go 1.21
`
	createFileWithContent(t, filepath.Join(tempDir, "go.mod"), goModContent)

	// Create some non-main files
	createFileWithContent(t, filepath.Join(tempDir, "util.go"), "package util\n\nfunc Helper() {}")

	result, err := DiscoverMainFunctions(tempDir)
	if err != nil {
		t.Fatalf("DiscoverMainFunctions() error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected 0 main functions for directory with no main.go files, got %d", len(result))
	}
}

func TestDiscoverMainFunctions_InvalidDirectory(t *testing.T) {
	_, err := DiscoverMainFunctions("/nonexistent/directory")
	if err == nil {
		t.Error("Expected error for nonexistent directory, got nil")
	}
}

func TestDiscoverMainFunctions_NoGoMod(t *testing.T) {
	// Create a temporary directory without go.mod
	tempDir := t.TempDir()

	// Create a main.go file
	createFileWithContent(t, filepath.Join(tempDir, "main.go"), "package main\n\nfunc main() {}")

	_, err := DiscoverMainFunctions(tempDir)
	if err == nil {
		t.Error("Expected error for directory without go.mod, got nil")
	}
}

func TestDiscoverMainFunctions_SingleMainOnly(t *testing.T) {
	// Create a temporary directory with only a root main.go
	tempDir := t.TempDir()

	// Create go.mod
	goModContent := `module github.com/example/single-main

go 1.21
`
	createFileWithContent(t, filepath.Join(tempDir, "go.mod"), goModContent)

	// Create only root main.go
	rootMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Single main")
}
`
	createFileWithContent(t, filepath.Join(tempDir, "main.go"), rootMainContent)

	result, err := DiscoverMainFunctions(tempDir)
	if err != nil {
		t.Fatalf("DiscoverMainFunctions() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 main function, got %d", len(result))
	}

	if result[0].PackagePath != "github.com/example/single-main" {
		t.Errorf("Expected package path 'github.com/example/single-main', got '%s'", result[0].PackagePath)
	}
}

func TestDiscoverMainFunctions_VendorSkipped(t *testing.T) {
	// Create a temporary directory structure with vendor directory
	tempDir := t.TempDir()

	// Create go.mod
	goModContent := `module github.com/example/vendor-test

go 1.21
`
	createFileWithContent(t, filepath.Join(tempDir, "go.mod"), goModContent)

	// Create root main.go
	createFileWithContent(t, filepath.Join(tempDir, "main.go"), "package main\n\nfunc main() {}")

	// Create vendor directory with main.go (should be skipped)
	vendorDir := filepath.Join(tempDir, "vendor", "example.com", "dep")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatalf("Failed to create vendor dir: %v", err)
	}
	createFileWithContent(t, filepath.Join(vendorDir, "main.go"), "package main\n\nfunc main() {}")

	result, err := DiscoverMainFunctions(tempDir)
	if err != nil {
		t.Fatalf("DiscoverMainFunctions() error = %v", err)
	}

	// Should only find the root main.go, not the vendor one
	if len(result) != 1 {
		t.Fatalf("Expected 1 main function (vendor should be skipped), got %d", len(result))
	}

	if result[0].PackagePath != "github.com/example/vendor-test" {
		t.Errorf("Expected package path 'github.com/example/vendor-test', got '%s'", result[0].PackagePath)
	}
}

func TestGenerateFBOMWithAutoDiscovery_SingleMain(t *testing.T) {
	// Test the fallback behavior when only one main function is found
	tempDir := t.TempDir()

	// Create simple project structure
	goModContent := `module github.com/example/single-main

go 1.21
`
	createFileWithContent(t, filepath.Join(tempDir, "go.mod"), goModContent)

	rootMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Single main")
}
`
	createFileWithContent(t, filepath.Join(tempDir, "main.go"), rootMainContent)

	// Change to the temp directory for the test
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Logf("Warning: failed to restore directory: %v", err)
		}
	}()

	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Should fall back to single FBOM generation
	result, err := generateFBOMWithAutoDiscoveryInternal(".", "", false, "rta", []string{}, output.DefaultAnalysisConfig())
	if err != nil {
		t.Fatalf("GenerateFBOMWithAutoDiscovery() error = %v", err)
	}

	// Verify basic structure
	if result.CallGraph.TotalFunctions == 0 {
		t.Error("Expected some functions to be found")
	}

	// Should have exactly one main entry point
	mainEntryPoints := 0
	for _, ep := range result.EntryPoints {
		if ep.Name == "main" {
			mainEntryPoints++
		}
	}

	if mainEntryPoints != 1 {
		t.Errorf("Expected exactly 1 main entry point for single main project, got %d", mainEntryPoints)
	}
}

func TestGenerateFBOMWithAutoDiscovery(t *testing.T) {
	// Create a temporary multi-component project
	tempDir := t.TempDir()
	createTestProjectStructure(t, tempDir)

	// Change to the temp directory for the test
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Logf("Warning: failed to restore directory: %v", err)
		}
	}()

	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Test that GenerateFBOMWithAutoDiscovery discovers all main functions
	// and produces a unified analysis
	result, err := generateFBOMWithAutoDiscoveryInternal(".", "", false, "rta", []string{}, output.DefaultAnalysisConfig())
	if err != nil {
		t.Fatalf("GenerateFBOMWithAutoDiscovery() error = %v", err)
	}

	// Verify that the result contains functions from multiple components
	// This is a basic smoke test - we expect some functions to be found
	if result.CallGraph.TotalFunctions == 0 {
		t.Error("Expected some functions to be found in unified analysis")
	}

	// Verify that multiple entry points were discovered
	mainEntryPoints := 0
	for _, ep := range result.EntryPoints {
		if ep.Name == "main" {
			mainEntryPoints++
		}
	}

	// We should find multiple main entry points (one per component)
	if mainEntryPoints < 2 {
		t.Errorf("Expected at least 2 main entry points, got %d", mainEntryPoints)
	}
}

// Helper functions

// MainFunctionInfo, DiscoverMainFunctions, and GenerateFBOMWithAutoDiscovery
// are now implemented in main_discovery.go

// createTestProjectStructure creates a realistic multi-component project structure for testing
func createTestProjectStructure(t *testing.T, baseDir string) {
	// Create go.mod (without external dependencies to avoid go.sum issues in tests)
	goModContent := `module github.com/example/test-project

go 1.21
`
	createFileWithContent(t, filepath.Join(baseDir, "go.mod"), goModContent)

	// Create root main.go
	rootMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Root main")
}
`
	createFileWithContent(t, filepath.Join(baseDir, "main.go"), rootMainContent)

	// Create cmd/controller/main.go
	controllerDir := filepath.Join(baseDir, "cmd", "controller")
	if err := os.MkdirAll(controllerDir, 0755); err != nil {
		t.Fatalf("Failed to create controller dir: %v", err)
	}
	controllerMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Controller main")
}
`
	createFileWithContent(t, filepath.Join(controllerDir, "main.go"), controllerMainContent)

	// Create cmd/cli/main.go
	cliDir := filepath.Join(baseDir, "cmd", "cli")
	if err := os.MkdirAll(cliDir, 0755); err != nil {
		t.Fatalf("Failed to create cli dir: %v", err)
	}
	cliMainContent := `package main

import "fmt"

func main() {
	fmt.Println("CLI main")
}
`
	createFileWithContent(t, filepath.Join(cliDir, "main.go"), cliMainContent)

	// Create cmd/operator/main.go
	operatorDir := filepath.Join(baseDir, "cmd", "operator")
	if err := os.MkdirAll(operatorDir, 0755); err != nil {
		t.Fatalf("Failed to create operator dir: %v", err)
	}
	operatorMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Operator main")
}
`
	createFileWithContent(t, filepath.Join(operatorDir, "main.go"), operatorMainContent)

	// Create component-operator/main.go
	componentOpDir := filepath.Join(baseDir, "component-operator")
	if err := os.MkdirAll(componentOpDir, 0755); err != nil {
		t.Fatalf("Failed to create component-operator dir: %v", err)
	}
	componentOpMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Component operator main")
}
`
	createFileWithContent(t, filepath.Join(componentOpDir, "main.go"), componentOpMainContent)

	// Create control-plane-operator/main.go
	controlPlaneOpDir := filepath.Join(baseDir, "control-plane-operator")
	if err := os.MkdirAll(controlPlaneOpDir, 0755); err != nil {
		t.Fatalf("Failed to create control-plane-operator dir: %v", err)
	}
	controlPlaneOpMainContent := `package main

import "fmt"

func main() {
	fmt.Println("Control plane operator main")
}
`
	createFileWithContent(t, filepath.Join(controlPlaneOpDir, "main.go"), controlPlaneOpMainContent)
}

func createFileWithContent(t *testing.T, filePath, content string) {
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create file %s: %v", filePath, err)
	}
}

func sortMainFunctionInfos(infos []MainFunctionInfo) {
	// Simple bubble sort by PackagePath for testing
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].PackagePath > infos[j].PackagePath {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
}
