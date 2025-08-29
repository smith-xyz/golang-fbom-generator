package generator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/reflection"
	"github.com/smith-xyz/golang-fbom-generator/pkg/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// MainFunctionInfo represents information about a discovered main function
type MainFunctionInfo struct {
	PackagePath string // Full package path (e.g., "github.com/example/project/cmd/controller")
	FilePath    string // Absolute path to main.go file
	Directory   string // Directory containing the main.go file
}

// DiscoverMainFunctions discovers all main.go files in a project and returns their info
func DiscoverMainFunctions(basePath string) ([]MainFunctionInfo, error) {
	var mainFunctions []MainFunctionInfo

	// Check if the base path exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return nil, err
	}

	// Read the go.mod file to get the module name
	moduleName, err := getModuleName(basePath)
	if err != nil {
		return nil, err
	}

	// Walk through the directory tree looking for main.go files
	err = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor directories
		if info.IsDir() && info.Name() == "vendor" {
			return filepath.SkipDir
		}

		// Look for main.go files
		if !info.IsDir() && info.Name() == "main.go" {
			// Get the directory containing this main.go
			dir := filepath.Dir(path)

			// Calculate the package path relative to the base
			relPath, err := filepath.Rel(basePath, dir)
			if err != nil {
				return err
			}

			// Build the full package path
			var packagePath string
			if relPath == "." {
				// Root main.go
				packagePath = moduleName
			} else {
				// Subdirectory main.go
				packagePath = moduleName + "/" + filepath.ToSlash(relPath)
			}

			mainFunctions = append(mainFunctions, MainFunctionInfo{
				PackagePath: packagePath,
				FilePath:    path,
				Directory:   dir,
			})
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return mainFunctions, nil
}

// getModuleName reads the go.mod file and extracts the module name
func getModuleName(basePath string) (string, error) {
	goModPath := filepath.Join(basePath, "go.mod")
	goModPath = filepath.Clean(goModPath)
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			moduleName := strings.TrimSpace(strings.TrimPrefix(line, "module"))
			return moduleName, nil
		}
	}

	return "", fmt.Errorf("module name not found in go.mod")
}

// GenerateFBOMWithAutoDiscovery generates a unified FBOM by auto-discovering all main functions and returns it
func GenerateFBOMWithAutoDiscovery(packageSpec, cveFile string, verbose bool, algorithm string, entryPointList []string, analysisConfig output.AnalysisConfig) (*models.FBOM, error) {
	return generateFBOMWithAutoDiscoveryInternal(packageSpec, cveFile, verbose, algorithm, entryPointList, analysisConfig)
}

// generateFBOMWithAutoDiscoveryInternal is the internal implementation that returns the FBOM for testing
func generateFBOMWithAutoDiscoveryInternal(packageSpec, cveFile string, verbose bool, algorithm string, entryPointList []string, analysisConfig output.AnalysisConfig) (*models.FBOM, error) {
	// Resolve the working directory and target package
	workingDir, targetPackage, err := resolvePackageToDirectory(packageSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve package %s: %w", packageSpec, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Resolved package '%s' to directory: %s\n", packageSpec, workingDir)
	}

	// Discover all main functions in the project
	mainFunctions, err := DiscoverMainFunctions(workingDir)
	if err != nil {
		return nil, fmt.Errorf("failed to discover main functions: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Discovered %d main functions\n", len(mainFunctions))
		for _, mf := range mainFunctions {
			fmt.Fprintf(os.Stderr, "  - %s (%s)\n", mf.PackagePath, mf.FilePath)
		}
	}

	// If no main functions found, fall back to regular analysis
	if len(mainFunctions) == 0 {
		return generateSingleFBOMInternal(packageSpec, cveFile, verbose, algorithm, entryPointList, analysisConfig)
	}

	// If only one main function found, use regular analysis
	if len(mainFunctions) == 1 {
		return generateSingleFBOMInternal(packageSpec, cveFile, verbose, algorithm, entryPointList, analysisConfig)
	}

	// For multiple main functions, we need to perform unified analysis
	// Change to working directory for analysis
	originalDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	if err := os.Chdir(workingDir); err != nil {
		return nil, fmt.Errorf("failed to change to working directory: %w", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to restore directory: %v\n", err)
		}
	}()

	fbom, err := generateUnifiedFBOMInternal(mainFunctions, targetPackage, cveFile, verbose, algorithm, entryPointList, analysisConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate unified FBOM: %w", err)
	}

	return fbom, nil
}

// generateSingleFBOMInternal generates FBOM for a single package and returns the FBOM object
func generateSingleFBOMInternal(packageSpec, cveFile string, verbose bool, algorithm string, entryPointList []string, analysisConfig output.AnalysisConfig) (*models.FBOM, error) {
	// Use the existing GenerateFBOM function but capture its output instead of printing
	// For now, we'll need to temporarily redirect stdout or use the underlying logic
	// This is a simplified implementation - in a real scenario we'd refactor the existing logic

	workingDir, targetPackage, err := resolvePackageToDirectory(packageSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve package %s: %w", packageSpec, err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	if err := os.Chdir(workingDir); err != nil {
		return nil, fmt.Errorf("failed to change to working directory: %w", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to restore directory: %v", err)
		}
	}()

	// Import the necessary analysis components
	callGraphGen := callgraph.NewGenerator(targetPackage, verbose)
	err = callGraphGen.SetAlgorithm(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to set call graph algorithm: %w", err)
	}
	callGraph, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate call graph: %w", err)
	}

	// Analyze reflection usage
	reflectionDetector := reflection.NewDetector(verbose)
	reflectionUsage, err := reflectionDetector.AnalyzePackage(targetPackage, ssaProgram)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze reflection: %w", err)
	}

	// Load CVE data if provided - this should be handled by caller but let's be safe
	var cveDatabase *cveloader.CVEDatabase
	// Note: CVE file loading is handled by the caller, so we don't do it here

	// Generate FBOM using buildFBOM to avoid double output
	fbomGenerator := output.NewFBOMGenerator(verbose, analysisConfig)
	err = fbomGenerator.SetAdditionalEntryPoints(entryPointList)
	if err != nil {
		return nil, fmt.Errorf("failed to set additional entry points: %w", err)
	}

	mainPackageName := determineMainPackageName(packageSpec)

	// Use BuildFBOM directly instead of Generate to avoid stdout output
	fbom := fbomGenerator.BuildFBOM(cveDatabase, reflectionUsage, callGraph, ssaProgram, mainPackageName)

	return &fbom, nil
}

// generateUnifiedFBOMInternal generates a unified FBOM by analyzing all main functions together and returns the FBOM
func generateUnifiedFBOMInternal(mainFunctions []MainFunctionInfo, targetPackage, cveFile string, verbose bool, algorithm string, entryPointList []string, analysisConfig output.AnalysisConfig) (*models.FBOM, error) {
	// For now, let's use a simpler approach: analyze all packages by including them all
	// in the call graph generation. We'll use the "..." pattern to include all packages
	// under the root module.

	// Extract the root module name from the first main function
	rootModulePath := mainFunctions[0].PackagePath
	moduleParts := strings.Split(rootModulePath, "/")
	moduleName := moduleParts[0]
	if len(moduleParts) > 1 {
		// Reconstruct the full module path (e.g., github.com/example/project)
		moduleName = strings.Join(moduleParts[:3], "/")
	}

	// Use the "..." pattern to analyze all packages under the module
	analyzeTarget := moduleName + "/..."

	if verbose {
		fmt.Fprintf(os.Stderr, "Performing unified analysis of module: %s\n", analyzeTarget)
		fmt.Fprintf(os.Stderr, "Discovered main functions in packages:\n")
		for _, mf := range mainFunctions {
			fmt.Fprintf(os.Stderr, "  - %s\n", mf.PackagePath)
		}
	}

	// Import necessary components for unified analysis
	callGraphGen := callgraph.NewGenerator(analyzeTarget, verbose)
	err := callGraphGen.SetAlgorithm(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to set call graph algorithm: %w", err)
	}

	callGraph, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate call graph: %w", err)
	}

	// Analyze reflection usage across all packages
	reflectionDetector := reflection.NewDetector(verbose)
	reflectionUsage, err := reflectionDetector.AnalyzePackage(analyzeTarget, ssaProgram)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze reflection: %w", err)
	}

	// Generate unified FBOM
	fbomGenerator := output.NewFBOMGenerator(verbose, analysisConfig)
	err = fbomGenerator.SetAdditionalEntryPoints(entryPointList)
	if err != nil {
		return nil, fmt.Errorf("failed to set additional entry points: %w", err)
	}

	// Use BuildFBOM directly instead of Generate to avoid stdout output
	fbom := fbomGenerator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, moduleName)

	return &fbom, nil
}
