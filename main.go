package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/smith-xyz/golang-fbom-generator/pkg/generator"
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
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.GetVersionWithCommit())
		os.Exit(0)
	}

	// Parse entry points
	entryPointList := utils.ParseCommaDelimited(*entryPoints)

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
	if *autoDiscover {
		// Use auto-discovery for unified multi-component analysis
		if err := generator.GenerateFBOMWithAutoDiscovery(*packagePath, finalCVEFile, *verbose, *algorithm, entryPointList); err != nil {
			log.Fatalf("FBOM generation failed: %v", err)
		}
	} else {
		// Use traditional single-package analysis
		if err := generator.GenerateFBOM(*packagePath, finalCVEFile, *verbose, *algorithm, entryPointList); err != nil {
			log.Fatalf("FBOM generation failed: %v", err)
		}
	}
}
