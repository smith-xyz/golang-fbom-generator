package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/smith-xyz/golang-fbom-generator/pkg/generator"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
	"github.com/smith-xyz/golang-fbom-generator/pkg/version"
)

func main() {
	var (
		packagePath  = flag.String("package", ".", "Go package path to analyze (local, external with @version, or stdlib)")
		cveFile      = flag.String("cve", "", "Path to CVE data file (JSON) - optional")
		verbose      = flag.Bool("v", false, "Verbose output")
		entryPoints  = flag.String("entry-points", "", "Comma-separated list of additional entry point patterns")
		algorithm    = flag.String("algo", "rta", "Call graph algorithm (rta, cha, static, vta)")
		autoDiscover = flag.Bool("auto-discover", false, "Auto-discover all main functions for unified multi-component analysis")
		showVersion  = flag.Bool("version", false, "Show version information and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.GetVersionWithCommit())
		os.Exit(0)
	}

	// Parse entry points
	entryPointList := utils.ParseCommaDelimited(*entryPoints)

	// Generate FBOM using auto-discovery or traditional approach
	if *autoDiscover {
		// Use auto-discovery for unified multi-component analysis
		if err := generator.GenerateFBOMWithAutoDiscovery(*packagePath, *cveFile, *verbose, *algorithm, entryPointList); err != nil {
			log.Fatalf("FBOM generation failed: %v", err)
		}
	} else {
		// Use traditional single-package analysis
		if err := generator.GenerateFBOM(*packagePath, *cveFile, *verbose, *algorithm, entryPointList); err != nil {
			log.Fatalf("FBOM generation failed: %v", err)
		}
	}
}
