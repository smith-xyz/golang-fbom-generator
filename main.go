package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis"
	"github.com/smith-xyz/golang-fbom-generator/pkg/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
	"github.com/smith-xyz/golang-fbom-generator/pkg/reflection"
	"github.com/smith-xyz/golang-fbom-generator/pkg/standalone"
	"github.com/smith-xyz/golang-fbom-generator/pkg/version"
)

func main() {
	var (
		packagePath  = flag.String("package", "", "Go package path to analyze")
		cveFile      = flag.String("cve", "", "Path to CVE data file (JSON) - optional")
		verbose      = flag.Bool("v", false, "Verbose output")
		entryPoints  = flag.String("entry-points", "", "Comma-separated list of additional entry point patterns")
		algorithm    = flag.String("algo", "rta", "Call graph algorithm (rta, cha, static, vta)")
		showVersion  = flag.Bool("version", false, "Show version information and exit")
		generateFBOM = flag.String("generate-fbom", "", "Generate FBOM for specified package (format: package[@version])")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.GetVersionWithCommit())
		os.Exit(0)
	}

	// Validate flag combinations
	if err := validateFlags(*packagePath, *generateFBOM); err != nil {
		log.Fatalf("Invalid flag combination: %v", err)
	}

	// Handle standalone FBOM generation
	if *generateFBOM != "" {
		if err := generateStandaloneFBOM(*generateFBOM, *verbose); err != nil {
			log.Fatalf("Standalone FBOM generation failed: %v", err)
		}
		return
	}

	// Handle regular FBOM generation for user application
	var entryPointList []string
	if *entryPoints != "" {
		entryPointList = strings.Split(*entryPoints, ",")
		for i := range entryPointList {
			entryPointList[i] = strings.TrimSpace(entryPointList[i])
		}
	}
	if err := generateAppFBOM(*packagePath, *cveFile, *verbose, *algorithm, entryPointList); err != nil {
		log.Fatalf("FBOM generation failed: %v", err)
	}
}

// validateFlags validates the combination of command-line flags
func validateFlags(packagePath, generateFBOM string) error {
	if packagePath != "" && generateFBOM != "" {
		return fmt.Errorf("flags -package and -generate-fbom are mutually exclusive")
	}
	if packagePath == "" && generateFBOM == "" {
		return fmt.Errorf("must specify either -package or -generate-fbom")
	}
	return nil
}

// generateStandaloneFBOM generates an FBOM for a standalone package
func generateStandaloneFBOM(packageSpec string, verbose bool) error {
	spec, err := standalone.ParsePackageSpec(packageSpec)
	if err != nil {
		return fmt.Errorf("invalid package specification: %w", err)
	}

	if verbose {
		if spec.IsStdlib {
			fmt.Fprintf(os.Stderr, "Generating FBOM for stdlib package: %s (%s)\n", spec.Name, spec.Version)
		} else {
			fmt.Fprintf(os.Stderr, "Generating FBOM for external package: %s@%s\n", spec.Name, spec.Version)
		}
	}

	if err := standalone.GenerateFBOM(spec); err != nil {
		return fmt.Errorf("failed to generate FBOM for %s: %w", spec.Name, err)
	}

	// Report success
	cacheType := "external"
	if spec.IsStdlib {
		cacheType = "stdlib"
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "✅ FBOM successfully generated and cached for %s\n", spec.Name)
		fmt.Fprintf(os.Stderr, "Cache location: ./fboms/%s/\n", cacheType)
		// TODO: In Phase 3, report more detailed success information:
		// TODO: 1. Show actual file path of generated FBOM
		// TODO: 2. Report FBOM file size and dependency count
		// TODO: 3. Show generation time and performance metrics
	} else {
		fmt.Printf("FBOM generated for %s\n", spec.Name)
	}

	return nil
}

// generateAppFBOM generates an FBOM for the user's application code.
func generateAppFBOM(packagePath, cveFile string, verbose bool, algorithm string, entryPointList []string) error {
	// Set default package path if not specified
	if packagePath == "" {
		packagePath = "."
	}
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

	callGraphGen := callgraph.NewGenerator(packagePath, verbose)
	err := callGraphGen.SetAlgorithm(algorithm)
	if err != nil {
		return fmt.Errorf("failed to set call graph algorithm: %w", err)
	}
	callGraph, ssaProgram, err := callGraphGen.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate call graph: %w", err)
	}

	reflectionDetector := reflection.NewDetector(verbose)
	reflectionUsage, err := reflectionDetector.AnalyzePackage(packagePath, ssaProgram)
	if err != nil {
		return fmt.Errorf("failed to analyze reflection: %w", err)
	}

	fbomGenerator := output.NewFBOMGenerator(verbose)
	err = fbomGenerator.SetAdditionalEntryPoints(entryPointList)
	if err != nil {
		return fmt.Errorf("failed to set additional entry points: %w", err)
	}
	mainPackageName := determineMainPackageName(packagePath)
	err = fbomGenerator.Generate(assessments, reflectionUsage, callGraph, ssaProgram, mainPackageName)
	if err != nil {
		return fmt.Errorf("failed to generate FBOM: %w", err)
	}

	return nil
}

// determineMainPackageName determines the main package name from the package path.
func determineMainPackageName(packagePath string) string {
	if packagePath == "." || packagePath == "./" {
		return "main"
	}
	return packagePath
}
