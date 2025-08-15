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
	"github.com/smith-xyz/golang-fbom-generator/pkg/version"
)

func main() {
	var (
		packagePath = flag.String("package", ".", "Go package path to analyze")
		cveFile     = flag.String("cve", "", "Path to CVE data file (JSON) - optional")
		verbose     = flag.Bool("v", false, "Verbose output")
		entryPoints = flag.String("entry-points", "", "Comma-separated list of additional entry point patterns")
		algorithm   = flag.String("algo", "rta", "Call graph algorithm (rta, cha, static, vta)")
		showVersion = flag.Bool("version", false, "Show version information and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.GetVersionWithCommit())
		os.Exit(0)
	}

	var entryPointList []string
	if *entryPoints != "" {
		entryPointList = strings.Split(*entryPoints, ",")
		for i := range entryPointList {
			entryPointList[i] = strings.TrimSpace(entryPointList[i])
		}
	}
	if err := generateFBOM(*packagePath, *cveFile, *verbose, *algorithm, entryPointList); err != nil {
		log.Fatalf("FBOM generation failed: %v", err)
	}
}

// generateFBOM generates an FBOM for the user's application code.
func generateFBOM(packagePath, cveFile string, verbose bool, algorithm string, entryPointList []string) error {
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
