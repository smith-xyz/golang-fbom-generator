package generator

import (
	"fmt"
	"os"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis"
	"github.com/smith-xyz/golang-fbom-generator/pkg/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
)

// GenerateFBOM generates an FBOM for any package (local, external, or stdlib)
func GenerateFBOM(packageSpec, cveFile string, verbose bool, algorithm string, entryPointList []string) error {
	// Set default package spec if not specified
	if packageSpec == "" {
		packageSpec = "."
	}

	workingDir, targetPackage, err := resolvePackageToDirectory(packageSpec)
	if err != nil {
		return fmt.Errorf("failed to resolve package %s: %w", packageSpec, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Resolved package '%s' to directory: %s\n", packageSpec, workingDir)
	}

	originalDir := packageSpec

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

	// Generate FBOM first to get dependency clusters
	fbomGenerator := output.NewFBOMGenerator(verbose)
	err = fbomGenerator.SetAdditionalEntryPoints(entryPointList)
	if err != nil {
		return fmt.Errorf("failed to set additional entry points: %w", err)
	}

	mainPackageName := determineMainPackageName(originalDir)

	// Generate FBOM without assessments first to get dependency clusters
	err = fbomGenerator.Generate(nil, reflectionUsage, callGraph, ssaProgram, mainPackageName)
	if err != nil {
		return fmt.Errorf("failed to generate FBOM: %w", err)
	}

	// Extract dependency clusters from the generated FBOM
	fbomData := fbomGenerator.GetFBOM()
	var dependencyClusters []analysis.DependencyCluster
	for _, cluster := range fbomData.DependencyClusters {
		var entryPoints []analysis.DependencyEntry
		for _, ep := range cluster.EntryPoints {
			entryPoints = append(entryPoints, analysis.DependencyEntry{
				Function:   ep.Function,
				CalledFrom: ep.CalledFrom,
			})
		}

		dependencyClusters = append(dependencyClusters, analysis.DependencyCluster{
			Name:             cluster.Name,
			EntryPoints:      entryPoints,
			ClusterFunctions: cluster.ClusterFunctions,
			TotalBlastRadius: cluster.TotalBlastRadius,
		})
	}

	// Analyze CVEs with complete context including dependency clusters
	var assessments []analysis.Assessment
	if cveFile != "" {
		loader := cve.NewLoader(verbose)
		cveData, err := loader.LoadFromFile(cveFile)
		if err != nil {
			return fmt.Errorf("failed to load CVE data: %w", err)
		}

		engine := analysis.NewEngine(verbose)
		assessments, _ = engine.AnalyzeAll(&analysis.AnalysisContext{
			CallGraph:          callGraph,
			SSAProgram:         ssaProgram,
			ReflectionUsage:    reflectionUsage,
			CVEDatabase:        cveData,
			EntryPoints:        []string{}, // TODO: extract entry points if needed
			DependencyClusters: dependencyClusters,
		})

		// Re-generate FBOM with CVE assessments
		err = fbomGenerator.Generate(assessments, reflectionUsage, callGraph, ssaProgram, mainPackageName)
		if err != nil {
			return fmt.Errorf("failed to regenerate FBOM with CVE data: %w", err)
		}
	}

	return nil
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

	// Load config to use for package detection
	cfg, err := config.DefaultConfig()
	if err != nil {
		// Fallback if config loading fails
		cfg = &config.Config{}
	}

	// Remove version specifier if present for package type detection
	pkg := packageSpec
	if idx := strings.Index(packageSpec, "@"); idx != -1 {
		pkg = packageSpec[:idx]
	}

	// Reject standard library packages
	if cfg.IsStandardLibrary(pkg) {
		return "", "", fmt.Errorf("standard library packages are not supported: %s", packageSpec)
	}

	// Reject external packages
	if cfg.IsDependency(pkg) {
		return "", "", fmt.Errorf("external packages are not supported: %s", packageSpec)
	}

	// Reject anything else that's not explicitly a local package
	return "", "", fmt.Errorf("unsupported package specification: %s (only local packages starting with '.' are supported)", packageSpec)
}

// determineMainPackageName determines the main package name from the package path
func determineMainPackageName(packagePath string) string {
	if packagePath == "." || packagePath == "./" {
		return "main"
	}
	return packagePath
}
