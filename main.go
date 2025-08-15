package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/generator"
	"github.com/smith-xyz/golang-fbom-generator/pkg/version"
)

func main() {
	var (
		packagePath = flag.String("package", ".", "Go package path to analyze (local, external with @version, or stdlib)")
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

	// Parse entry points
	var entryPointList []string
	if *entryPoints != "" {
		entryPointList = strings.Split(*entryPoints, ",")
		for i := range entryPointList {
			entryPointList[i] = strings.TrimSpace(entryPointList[i])
		}
	}

	// Generate FBOM using unified generator
	if err := generator.GenerateFBOM(*packagePath, *cveFile, *verbose, *algorithm, entryPointList); err != nil {
		log.Fatalf("FBOM generation failed: %v", err)
	}
}
