package packageanalyzer

import (
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/ssa"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
)

// Analyzer handles package-level analysis and discovery
type Analyzer struct {
	logger  *slog.Logger
	verbose bool
	config  *Config
}

// Config holds configuration for package analysis
type Config struct {
	Verbose bool
}

// NewAnalyzer creates a new package analyzer
func NewAnalyzer(logger *slog.Logger, config *Config) *Analyzer {
	if config == nil {
		config = &Config{}
	}
	return &Analyzer{
		logger:  logger,
		verbose: config.Verbose,
		config:  config,
	}
}

// ExtractAllPackages extracts all packages from the SSA program
func (a *Analyzer) ExtractAllPackages(ssaProgram *ssa.Program) []string {
	a.logger.Debug("extractAllPackages called")
	var packages []string
	if ssaProgram != nil {
		for _, pkg := range ssaProgram.AllPackages() {
			packages = append(packages, pkg.Pkg.Path())
		}
	}
	a.logger.Debug("extracted packages", "count", len(packages))
	return packages
}

// ExtractMainModuleName extracts the main module name from the SSA program
func (a *Analyzer) ExtractMainModuleName(ssaProgram *ssa.Program, fallback string) string {
	// Try to find and parse go.mod using Go's modfile package
	if moduleName := a.FindModuleNameFromGoMod(); moduleName != "" {
		return moduleName
	}

	// Fallback: analyze SSA program to find user-defined packages
	if ssaProgram == nil {
		return fallback
	}

	// Look for user-defined packages and extract the module name
	for _, pkg := range ssaProgram.AllPackages() {
		if pkg.Pkg != nil {
			packagePath := pkg.Pkg.Path()
			// Skip standard library and known dependency packages
			if !rules.IsStandardLibraryByPattern(packagePath) && !rules.IsDependencyByPattern(packagePath) {
				// For user packages, return the package path which should be the module name
				return packagePath
			}
		}
	}

	return fallback
}

// FindModuleNameFromGoMod finds module name from go.mod file
func (a *Analyzer) FindModuleNameFromGoMod() string {
	// Start from current directory and walk up to find go.mod
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if !filepath.IsAbs(goModPath) {
			goModPath = filepath.Clean(goModPath)
		}
		if content, err := os.ReadFile(goModPath); err == nil {
			// Parse go.mod using Go's official parser
			parsed, err := modfile.Parse(goModPath, content, nil)
			if err == nil && parsed.Module != nil {
				return parsed.Module.Mod.Path
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return ""
}
