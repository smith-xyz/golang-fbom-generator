package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/smith-xyz/golang-fbom-generator/pkg/generator"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
	"github.com/smith-xyz/golang-fbom-generator/pkg/version"
	"github.com/smith-xyz/golang-fbom-generator/pkg/vulncheck"
)

func main() {
	var (
		packagePath     = flag.String("package", ".", "Go package path to analyze (local, external with @version, or stdlib)")
		cveFile         = flag.String("cve", "", "Path to CVE data file (JSON) - optional")
		verbose         = flag.Bool("v", false, "Verbose output")
		entryPoints     = flag.String("entry-points", "", "Comma-separated list of additional entry point patterns")
		algorithm       = flag.String("algo", "rta", "Call graph algorithm (rta, cha, static, vta)")
		autoDiscover    = flag.Bool("auto-discover", false, "Auto-discover all main functions for unified multi-component analysis")
		showVersion     = flag.Bool("version", false, "Show version information and exit")
		liveCVEScan     = flag.Bool("live-cve-scan", false, "Perform live CVE scanning using govulncheck")
		cveCheckPackage = flag.String("cve-check-package", "", "Check specific package for vulnerabilities (requires --live-cve-scan)")
		outputToFile    = flag.Bool("o", false, "Write output to <package-name>.fbom.json file instead of stdout")
		maxDepth        = flag.Int("max-depth", 3, "Maximum traversal depth for dependency attack paths (default: 3)")
		maxEdges        = flag.Int("max-edges", 5, "Maximum edges to traverse per node in attack paths (default: 5)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.GetVersionWithCommit())
		os.Exit(0)
	}

	// Parse entry points
	entryPointList := utils.ParseCommaDelimited(*entryPoints)

	// Create analysis configuration
	analysisConfig := output.AnalysisConfig{
		AttackPathMaxDepth: *maxDepth,
		AttackPathMaxEdges: *maxEdges,
	}

	// Handle live CVE scanning
	var finalCVEFile string
	var cleanupFunc func()

	if *liveCVEScan {
		integration, err := vulncheck.NewIntegration(*verbose)
		if err != nil {
			log.Fatalf("Failed to create CVE integration: %v", err)
		}

		// Perform live CVE scan
		liveCVEData, err := integration.ScanAndConvert(*packagePath, *cveCheckPackage)
		if err != nil {
			log.Fatalf("Live CVE scan failed: %v", err)
		}

		// If we also have an existing CVE file, merge them
		if *cveFile != "" {
			liveCVEData, err = integration.MergeWithExistingCVEFile(*cveFile, liveCVEData)
			if err != nil {
				log.Fatalf("Failed to merge CVE data: %v", err)
			}
		}

		// Create temporary file for generator (needed for existing interface)
		finalCVEFile, cleanupFunc, err = integration.CreateTempCVEFileFromDatabase(liveCVEData)
		if err != nil {
			log.Fatalf("Failed to create temporary CVE file: %v", err)
		}
		defer cleanupFunc() // Clean up temp file when done
	} else {
		// Use existing CVE file if no live scan
		finalCVEFile = *cveFile
	}

	// Generate FBOM using auto-discovery or traditional approach
	var fbom *models.FBOM
	var err error

	if *autoDiscover {
		// Use auto-discovery for unified multi-component analysis
		fbom, err = generator.GenerateFBOMWithAutoDiscovery(*packagePath, finalCVEFile, *verbose, *algorithm, entryPointList, analysisConfig)
		if err != nil {
			log.Fatalf("FBOM generation failed: %v", err)
		}
	} else {
		// Use traditional single-package analysis
		fbom, err = generator.GenerateFBOM(*packagePath, finalCVEFile, *verbose, *algorithm, entryPointList, analysisConfig)
		if err != nil {
			log.Fatalf("FBOM generation failed: %v", err)
		}
	}

	// Handle output based on user preference
	if *outputToFile {
		// Write to file with automatic filename generation
		outputFilename, err := utils.GenerateOutputFilename(*packagePath)
		if err != nil {
			log.Fatalf("Failed to generate output filename: %v", err)
		}

		err = writeFBOMToFile(fbom, outputFilename)
		if err != nil {
			log.Fatalf("Failed to write FBOM to file: %v", err)
		}
	} else {
		// Write to stdout (default behavior for backwards compatibility)
		err = writeFBOMToStdout(fbom)
		if err != nil {
			log.Fatalf("Failed to write FBOM to stdout: %v", err)
		}
	}
}

// writeFBOMToFile writes an FBOM to the specified file
func writeFBOMToFile(fbom *models.FBOM, filename string) error {
	file, err := utils.SafeCreateFile(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", filename, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(fbom)
	if err != nil {
		return fmt.Errorf("failed to write FBOM to file %s: %w", filename, err)
	}

	fmt.Fprintf(os.Stderr, "FBOM successfully written to: %s\n", filename)
	return nil
}

// writeFBOMToStdout writes an FBOM to stdout
func writeFBOMToStdout(fbom *models.FBOM) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(fbom)
}
