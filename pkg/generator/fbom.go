package generator

import (
	"fmt"
	"os"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/reflection"
	"github.com/smith-xyz/golang-fbom-generator/pkg/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
)

// GenerateFBOM generates an FBOM for any package (local, external, or stdlib) and returns it
func GenerateFBOM(packageSpec, cveFile string, verbose bool, algorithm string, entryPointList []string, analysisConfig output.AnalysisConfig) (*models.FBOM, error) {
	// Set default package spec if not specified
	if packageSpec == "" {
		packageSpec = "."
	}

	workingDir, targetPackage, err := resolvePackageToDirectory(packageSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve package %s: %w", packageSpec, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Resolved package '%s' to directory: %s\n", packageSpec, workingDir)
	}

	originalDir := packageSpec

	// Change to working directory for analysis using utils
	var fbom *models.FBOM
	err = utils.WithDirectoryChange(workingDir, func() error {
		callGraphGen := callgraph.NewGenerator(targetPackage, verbose)
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
		reflectionUsage, err := reflectionDetector.AnalyzePackage(targetPackage, ssaProgram)
		if err != nil {
			return fmt.Errorf("failed to analyze reflection: %w", err)
		}

		mainPackageName := determineMainPackageName(originalDir)

		// Load CVE data if provided
		var cveDatabase *cveloader.CVEDatabase
		if cveFile != "" {
			loader := cveloader.NewLoader(verbose)
			cveData, err := loader.LoadFromFile(cveFile)
			if err != nil {
				return fmt.Errorf("failed to load CVE data: %w", err)
			}
			cveDatabase = cveData
		}

		// Generate FBOM with all data
		fbomGenerator := output.NewFBOMGenerator(verbose, analysisConfig)
		err = fbomGenerator.SetAdditionalEntryPoints(entryPointList)
		if err != nil {
			return fmt.Errorf("failed to set additional entry points: %w", err)
		}

		// Use BuildFBOM to get the FBOM without output
		fbomResult := fbomGenerator.BuildFBOM(cveDatabase, reflectionUsage, callGraph, ssaProgram, mainPackageName)
		fbom = &fbomResult
		return nil
	})

	if err != nil {
		return nil, err
	}
	return fbom, nil
}

func resolvePackageToDirectory(packageSpec string) (workingDir string, targetPackage string, err error) {
	// Handle relative paths (local packages)
	if packageSpec == "." || packageSpec == "./" {
		wd, err := os.Getwd()
		if err != nil {
			return "", "", fmt.Errorf("failed to get working directory: %w", err)
		}
		return wd, packageSpec, nil
	}

	// Handle explicit local paths like ./examples/hello-world
	if packageSpec[0] == '.' {
		wd, err := os.Getwd()
		if err != nil {
			return "", "", fmt.Errorf("failed to get working directory: %w", err)
		}
		return wd, packageSpec, nil
	}

	// Remove version specifier if present for package type detection
	pkg := packageSpec
	if idx := strings.Index(packageSpec, "@"); idx != -1 {
		pkg = packageSpec[:idx]
	}

	// Try to create context-aware config for better package classification
	var contextAwareConfig *config.ContextAwareConfig
	rootPackage, err := utils.GetCurrentGoModule()
	if err == nil {
		contextAwareConfig, err = config.NewContextAwareConfig(rootPackage)
		if err != nil {
			contextAwareConfig = nil
		}
	}

	// Use context-aware config if available, otherwise fall back to base config
	var isStdlib, isDep bool
	if contextAwareConfig != nil {
		isStdlib = contextAwareConfig.IsStandardLibrary(pkg)
		isDep = contextAwareConfig.IsDependency(pkg)
	} else {
		// Fallback to base config
		cfg, err := config.DefaultConfig()
		if err != nil {
			cfg = &config.Config{}
		}
		isStdlib = cfg.IsStandardLibrary(pkg)
		isDep = cfg.IsDependency(pkg)
	}

	// Reject standard library packages
	if isStdlib {
		return "", "", fmt.Errorf("standard library packages are not supported: %s", packageSpec)
	}

	// With context-aware config, we can now support local packages with external-looking names
	if contextAwareConfig != nil && contextAwareConfig.IsUserDefined(pkg) {
		// This is a user-defined package (potentially the local project)
		// Assume we should analyze it from the current working directory
		wd, err := os.Getwd()
		if err != nil {
			return "", "", fmt.Errorf("failed to get working directory: %w", err)
		}
		return wd, pkg, nil
	}

	// Reject external packages
	if isDep {
		return "", "", fmt.Errorf("external packages are not supported: %s", packageSpec)
	}

	// Assume local package - analyze from current directory
	wd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("failed to get working directory: %w", err)
	}
	return wd, pkg, nil
}

// determineMainPackageName determines the main package name from the package path
func determineMainPackageName(packagePath string) string {
	if packagePath == "." || packagePath == "./" {
		return "main"
	}
	return packagePath
}
