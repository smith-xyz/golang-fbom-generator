package generator

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis"
	"github.com/smith-xyz/golang-fbom-generator/pkg/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
)

// PackageSpec represents a parsed package specification
type PackageSpec struct {
	Name     string
	Version  string
	IsStdlib bool
}

// GenerateFBOM generates an FBOM for any package (local, external, or stdlib)
func GenerateFBOM(packagePath, cveFile string, verbose bool, algorithm string, entryPointList []string) error {
	// Set default package path if not specified
	if packagePath == "" {
		packagePath = "."
	}

	// Handle external packages with @version syntax
	var workingDir string
	var cleanupFunc func() error
	originalDir := packagePath

	if strings.Contains(packagePath, "@") {
		// Parse the package spec to determine if it's stdlib or external
		spec, err := ParsePackageSpec(packagePath)
		if err != nil {
			return fmt.Errorf("failed to parse package specification %s: %w", packagePath, err)
		}

		if spec.IsStdlib {
			// Stdlib packages with @version - treat as regular stdlib packages
			packagePath = spec.Name // Remove the @version part
			currentDir, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %w", err)
			}
			workingDir = currentDir
		} else {
			// External package specification (e.g., github.com/gin-gonic/gin@v1.9.1)
			// Create temporary workspace for external package analysis
			tempDir, cleanup, err := createTempWorkspace(spec.Name, spec.Version, verbose)
			if err != nil {
				return fmt.Errorf("failed to create temporary workspace for %s: %w", packagePath, err)
			}

			workingDir = tempDir
			cleanupFunc = cleanup
			packagePath = "." // Analyze the current directory in the temp workspace

			defer func() {
				if cleanupFunc != nil {
					if cleanupErr := cleanupFunc(); cleanupErr != nil && verbose {
						fmt.Fprintf(os.Stderr, "Warning: failed to cleanup temporary workspace: %v\n", cleanupErr)
					}
				}
			}()
		}
	} else {
		// Local package or stdlib without version - use current working directory
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		workingDir = currentDir
	}

	// Load CVE data if provided
	var assessments []analysis.Assessment
	if cveFile != "" {
		loader := cve.NewLoader(verbose)
		cveData, err := loader.LoadFromFile(cveFile)
		if err != nil {
			return fmt.Errorf("failed to load CVE data: %w", err)
		}

		engine := analysis.NewEngine(verbose)
		assessments, _ = engine.AnalyzeAll(&analysis.AnalysisContext{CVEDatabase: cveData})
	}

	// Generate call graph in the appropriate working directory

	// Change to working directory for analysis
	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	if workingDir != originalWd {
		if err := os.Chdir(workingDir); err != nil {
			return fmt.Errorf("failed to change to working directory %s: %w", workingDir, err)
		}
		defer func() {
			if chdirErr := os.Chdir(originalWd); chdirErr != nil && verbose {
				fmt.Fprintf(os.Stderr, "Warning: failed to return to original directory: %v\n", chdirErr)
			}
		}()
	}

	callGraphGen := callgraph.NewGenerator(packagePath, verbose)
	err = callGraphGen.SetAlgorithm(algorithm)
	if err != nil {
		return fmt.Errorf("failed to set call graph algorithm: %w", err)
	}
	callGraph, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate call graph: %w", err)
	}

	// Analyze reflection usage
	reflectionDetector := reflection.NewDetector(verbose)
	reflectionUsage, err := reflectionDetector.AnalyzePackage(packagePath, ssaProgram)
	if err != nil {
		return fmt.Errorf("failed to analyze reflection: %w", err)
	}

	// Generate FBOM
	fbomGenerator := output.NewFBOMGenerator(verbose)
	err = fbomGenerator.SetAdditionalEntryPoints(entryPointList)
	if err != nil {
		return fmt.Errorf("failed to set additional entry points: %w", err)
	}

	mainPackageName := determineMainPackageName(originalDir)
	err = fbomGenerator.Generate(assessments, reflectionUsage, callGraph, ssaProgram, mainPackageName)
	if err != nil {
		return fmt.Errorf("failed to generate FBOM: %w", err)
	}

	return nil
}

// determineMainPackageName determines the main package name from the package path
func determineMainPackageName(packagePath string) string {
	if packagePath == "." || packagePath == "./" {
		return "main"
	}
	return packagePath
}

// createTempWorkspace creates a temporary Go module workspace for analyzing external packages
func createTempWorkspace(packageName, version string, verbose bool) (string, func() error, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "fbom-analysis-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	// Cleanup function
	cleanup := func() error {
		return os.RemoveAll(tempDir)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Creating temporary workspace: %s\n", tempDir)
	}

	// Initialize go module in temp directory
	goModContent := fmt.Sprintf("module temp-analysis\n\ngo 1.21\n\nrequire %s %s\n", packageName, version)
	goModPath := filepath.Join(tempDir, "go.mod")

	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cleanup failed: %v\n", cleanupErr)
		}
		return "", nil, fmt.Errorf("failed to create go.mod: %w", err)
	}

	// Create a dummy main.go that imports the package for analysis
	mainGoContent := fmt.Sprintf(`package main

import _ "%s"

func main() {
	// This is a dummy main for FBOM analysis
}
`, packageName)

	mainGoPath := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(mainGoPath, []byte(mainGoContent), 0644); err != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cleanup failed: %v\n", cleanupErr)
		}
		return "", nil, fmt.Errorf("failed to create main.go: %w", err)
	}

	// Run go mod tidy to fetch the dependency
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = tempDir
	if verbose {
		fmt.Fprintf(os.Stderr, "Downloading %s@%s...\n", packageName, version)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cleanup failed: %v\n", cleanupErr)
		}
		return "", nil, fmt.Errorf("failed to download package %s@%s: %w\nOutput: %s", packageName, version, err, string(output))
	}

	return tempDir, cleanup, nil
}

// ParsePackageSpec parses a package specification in the format "package[@version]"
func ParsePackageSpec(spec string) (*PackageSpec, error) {
	if spec == "" {
		return nil, fmt.Errorf("package specification cannot be empty")
	}

	// Check for invalid format (multiple @ symbols)
	parts := strings.Split(spec, "@")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid package specification format: %s", spec)
	}

	packageName := parts[0]
	var version string

	if len(parts) == 2 {
		version = parts[1]
	}

	// Determine if it's a stdlib package
	isStdlib := isStandardLibraryPackage(packageName)

	// For stdlib packages, use Go version as version if not specified
	if isStdlib && version == "" {
		goVersion := runtime.Version() // e.g., "go1.21.0"
		version = goVersion
	}

	// For external packages, resolve version if not specified
	if !isStdlib && version == "" {
		resolvedVersion, err := resolveLatestVersion(packageName)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve version for %s: %w", packageName, err)
		}
		version = resolvedVersion
	}

	return &PackageSpec{
		Name:     packageName,
		Version:  version,
		IsStdlib: isStdlib,
	}, nil
}

// isStandardLibraryPackage determines if a package is part of the Go standard library
func isStandardLibraryPackage(packageName string) bool {
	// Load configuration to get stdlib patterns
	cfg, err := config.DefaultConfig()
	if err != nil {
		// Fallback to basic heuristic if config fails to load
		if strings.Contains(packageName, ".") && strings.Contains(packageName, "/") {
			return false // External package
		}
		return !strings.Contains(packageName, "/") || strings.HasPrefix(packageName, "internal/")
	}

	return cfg.IsStandardLibrary(packageName)
}

// resolveLatestVersion resolves the latest version of an external package
func resolveLatestVersion(packageName string) (string, error) {
	// Use go list to get the latest version
	cmd := exec.Command("go", "list", "-m", "-versions", packageName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("package not found or unable to resolve: %s", packageName)
	}

	// Parse output to get the latest version
	lines := strings.TrimSpace(string(output))
	parts := strings.Fields(lines)
	if len(parts) < 2 {
		return "", fmt.Errorf("unable to parse version information for %s", packageName)
	}

	// The last version in the list is typically the latest
	versions := parts[1:]
	if len(versions) == 0 {
		return "latest", nil
	}

	return versions[len(versions)-1], nil
}
