package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	callgraphanalyzer "github.com/smith-xyz/golang-fbom-generator/pkg/analysis/callgraph"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/dependency"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/function"
	packageanalyzer "github.com/smith-xyz/golang-fbom-generator/pkg/analysis/package"
	reflectionanalyzer "github.com/smith-xyz/golang-fbom-generator/pkg/analysis/reflection"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/shared"
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
	"github.com/smith-xyz/golang-fbom-generator/pkg/version"
)

// AnalysisConfig is an alias for the shared configuration type
type AnalysisConfig = models.AnalysisConfig

// DefaultAnalysisConfig returns sensible defaults for all analysis features
func DefaultAnalysisConfig() AnalysisConfig {
	return AnalysisConfig{
		AttackPathMaxDepth:        3,
		AttackPathMaxEdges:        5,
		CallGraphMaxDepth:         10,
		CallGraphMaxEdges:         100,
		ReflectionAnalysisEnabled: true,
		ReflectionMaxDepth:        5,
		CVEAnalysisEnabled:        true,
		LiveCVEScan:               false,
		Verbose:                   false,
	}
}

// FBOMGenerator handles FBOM generation for user applications
type FBOMGenerator struct {
	logger                *slog.Logger
	verbose               bool
	config                *config.Config
	contextAwareConfig    *config.ContextAwareConfig
	additionalEntryPoints []string
	generatedFBOM         *models.FBOM   // Store the last generated FBOM
	analysisConfig        AnalysisConfig // Configuration for various analysis features

	// Business rules and utilities
	rules          *rules.Rules
	sharedAnalyzer *shared.SharedAnalyzer

	// Specialized analyzers (modular architecture)
	cveAnalyzer          *cve.Analyzer
	dataPopulator        *cve.DataPopulator
	reflectionIntegrator *cve.ReflectionIntegrator
	riskAssessor         *cve.RiskAssessor
	dependencyAnalyzer   *dependency.Analyzer
	attackPathAnalyzer   *dependency.AttackPathAnalyzer
	functionAnalyzer     *function.Analyzer
	packageAnalyzer      *packageanalyzer.Analyzer
	callGraphAnalyzer    *callgraphanalyzer.Analyzer
	entryPointAnalyzer   *callgraphanalyzer.EntryPointAnalyzer
	reflectionAnalyzer   *reflectionanalyzer.Analyzer
}

// CVE Analysis Types (moved from analysis package)

// NewFBOMGenerator creates a new FBOM generator
func NewFBOMGenerator(verbose bool, analysisConfig AnalysisConfig) *FBOMGenerator {
	// Create logger that outputs to stderr to avoid contaminating JSON output
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: func() slog.Level {
			if verbose {
				return slog.LevelDebug
			}
			return slog.LevelInfo
		}(),
	}))

	cfg, err := config.DefaultConfig()
	if err != nil {
		// Fallback to a basic config if default config fails to load
		cfg = &config.Config{}
	}

	// Try to detect root package for context-aware configuration
	var contextAwareConfig *config.ContextAwareConfig
	rootPackage, err := utils.GetCurrentGoModule()
	if err != nil {
		if verbose {
			logger.Debug("Failed to detect root package, using non-context-aware config", "error", err)
		}
		// Fall back to non-context-aware config (original behavior)
		contextAwareConfig = nil
	} else {
		contextAwareConfig, err = config.NewContextAwareConfig(rootPackage)
		if err != nil {
			if verbose {
				logger.Debug("Failed to create context-aware config, using non-context-aware config", "error", err)
			}
			contextAwareConfig = nil
		} else if verbose {
			logger.Debug("Using context-aware config", "rootPackage", rootPackage)
		}
	}

	rules := rules.NewRules(contextAwareConfig, cfg)

	// Initialize CVE analyzer with its own config
	cveConfig := &cve.Config{
		Verbose: verbose,
	}
	cveAnalyzer := cve.NewAnalyzer(logger, cveConfig)
	dataPopulator := cve.NewDataPopulator(logger, verbose)
	reflectionIntegrator := cve.NewReflectionIntegrator(logger, verbose)
	riskAssessor := cve.NewRiskAssessor(logger, verbose)

	// Initialize dependency analyzers
	depConfig := &dependency.Config{
		Verbose:            verbose,
		MaxAttackPathDepth: analysisConfig.AttackPathMaxDepth,
		MaxAttackPathEdges: analysisConfig.AttackPathMaxEdges,
	}
	dependencyAnalyzer := dependency.NewAnalyzer(logger, depConfig)
	attackPathAnalyzer := dependency.NewAttackPathAnalyzer(logger, verbose, depConfig, rules)

	// Initialize package analyzers
	pkgConfig := &packageanalyzer.Config{Verbose: verbose}
	packageAnalyzer := packageanalyzer.NewAnalyzer(logger, pkgConfig)

	// Initialize call graph analyzers
	cgConfig := &callgraphanalyzer.Config{
		Verbose:          verbose,
		MaxDepthAnalysis: analysisConfig.CallGraphMaxDepth,
	}
	sharedAnalyzer := shared.NewSharedAnalyzer(logger, rules)
	callGraphAnalyzer := callgraphanalyzer.NewAnalyzer(logger, cgConfig, &analysisConfig, rules, sharedAnalyzer)
	entryPointAnalyzer := callgraphanalyzer.NewEntryPointAnalyzer(logger, verbose, rules, sharedAnalyzer)

	// Initialize function analyzers
	funcConfig := &function.Config{
		Verbose:                 verbose,
		IncludeUnreachableFuncs: true,
	}
	functionAnalyzer := function.NewAnalyzer(logger, funcConfig, rules, sharedAnalyzer)

	// Initialize reflection analyzer
	reflectionConfig := &reflectionanalyzer.Config{
		Verbose:                     verbose,
		MaxReflectionDepth:          analysisConfig.ReflectionMaxDepth,
		IncludeDetailedTargets:      false, // Reduce noise by default
		FocusOnSecurityImplications: true,
	}
	reflectionAnalyzer := reflectionanalyzer.NewAnalyzer(logger, reflectionConfig)

	return &FBOMGenerator{
		logger:                logger,
		verbose:               verbose,
		config:                cfg,
		contextAwareConfig:    contextAwareConfig,
		additionalEntryPoints: make([]string, 0),
		analysisConfig:        analysisConfig,
		rules:                 rules,
		sharedAnalyzer:        sharedAnalyzer,
		cveAnalyzer:           cveAnalyzer,
		dataPopulator:         dataPopulator,
		reflectionIntegrator:  reflectionIntegrator,
		riskAssessor:          riskAssessor,
		dependencyAnalyzer:    dependencyAnalyzer,
		attackPathAnalyzer:    attackPathAnalyzer,
		functionAnalyzer:      functionAnalyzer,
		packageAnalyzer:       packageAnalyzer,
		callGraphAnalyzer:     callGraphAnalyzer,
		entryPointAnalyzer:    entryPointAnalyzer,
		reflectionAnalyzer:    reflectionAnalyzer,
	}
}

// SetAdditionalEntryPoints configures additional entry point patterns beyond main and init
func (g *FBOMGenerator) SetAdditionalEntryPoints(entryPoints []string) error {
	// Delegate to the rules package - this is now the single source of truth
	g.rules.Classifier.SetAdditionalEntryPoints(entryPoints)
	g.logger.Debug("Set additional entry points", "patterns", entryPoints)

	// Update the legacy field for backward compatibility (if needed)
	if entryPoints == nil {
		g.additionalEntryPoints = make([]string, 0)
	} else {
		g.additionalEntryPoints = utils.TrimSpaceSlice(entryPoints)
	}

	// Also update analyzers that still need direct notification (transitional)
	if g.cveAnalyzer != nil {
		g.cveAnalyzer.SetAdditionalEntryPoints(g.additionalEntryPoints)
	}
	if g.entryPointAnalyzer != nil {
		g.entryPointAnalyzer.SetAdditionalEntryPoints(g.additionalEntryPoints)
	}

	return nil
}

// Generate produces FBOM output for user applications only
func (g *FBOMGenerator) Generate(cveDatabase *cveloader.CVEDatabase, reflectionUsage map[string]*models.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program, mainPackageName string, outputFilename ...string) error {
	var outputFile string
	if len(outputFilename) > 0 {
		outputFile = outputFilename[0]
	}

	g.logger.Debug("Generate function called", "output_file", outputFile)

	fbom := g.buildFBOM(cveDatabase, reflectionUsage, callGraph, ssaProgram, mainPackageName)

	// Store the generated FBOM for later access
	g.generatedFBOM = &fbom

	// Choose output destination based on whether filename is provided
	if outputFile != "" {
		// Write to file
		file, err := utils.SafeCreateFile(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(fbom)
		if err != nil {
			return fmt.Errorf("failed to write FBOM to file %s: %w", outputFile, err)
		}

		fmt.Fprintf(os.Stderr, "FBOM successfully written to: %s\n", outputFile)
		return nil
	} else {
		// Write to stdout (original behavior)
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(fbom)
	}
}

// GetFBOM returns the last generated FBOM
func (g *FBOMGenerator) GetFBOM() *models.FBOM {
	return g.generatedFBOM
}

// GetRules returns the rules instance for testing purposes
func (g *FBOMGenerator) GetRules() *rules.Rules {
	return g.rules
}

// BuildFBOM constructs the complete FBOM structure and returns it without outputting to stdout
func (g *FBOMGenerator) BuildFBOM(cveDatabase *cveloader.CVEDatabase, reflectionUsage map[string]*models.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program, mainPackageName string) models.FBOM {
	return g.buildFBOM(cveDatabase, reflectionUsage, callGraph, ssaProgram, mainPackageName)
}

// buildFBOM constructs the complete FBOM structure
func (g *FBOMGenerator) buildFBOM(cveDatabase *cveloader.CVEDatabase, reflectionUsage map[string]*models.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program, mainPackageName string) models.FBOM {
	g.logger.Debug("buildFBOM function called")

	// Extract packages and build function inventory using new analyzers
	packages := g.packageAnalyzer.ExtractAllPackages(ssaProgram)
	allFunctions := g.functionAnalyzer.BuildUserFunctionInventory(reflectionUsage, callGraph, ssaProgram)

	callGraphInfo := g.callGraphAnalyzer.BuildCallGraphInfo(callGraph, allFunctions)
	entryPoints := g.entryPointAnalyzer.BuildEntryPoints(callGraph)

	// Get the actual module name instead of using mainPackageName
	actualModuleName := g.packageAnalyzer.ExtractMainModuleName(ssaProgram, mainPackageName)

	// Build dependency clusters for attack surface analysis using new analyzers
	dependencyClusters := g.dependencyAnalyzer.BuildDependencyClusters(callGraph, allFunctions, g.rules.Classifier, g.attackPathAnalyzer, g.attackPathAnalyzer)

	// Build reflection analysis for security assessment using new analyzer
	reflectionAnalysis := g.reflectionAnalyzer.BuildReflectionAnalysis(callGraph, g.rules.Classifier, cveDatabase)

	// Perform CVE analysis if CVE database is provided
	var assessments []models.Assessment
	if cveDatabase != nil {
		assessments = g.cveAnalyzer.AnalyzeCVEs(cveDatabase, callGraph, ssaProgram, reflectionUsage, dependencyClusters, reflectionAnalysis)
		// Update function CVE references based on analysis results
		g.dataPopulator.PopulateFunctionCVEReferences(allFunctions, assessments, dependencyClusters)
		// Update dependency cluster attack paths with vulnerability IDs
		g.dataPopulator.PopulateClusterVulnerabilityIDs(dependencyClusters, assessments)
	}

	// Build security information using the CVE analyzer
	securityInfo := g.cveAnalyzer.BuildSecurityInfo(assessments, reflectionUsage)

	return models.FBOM{
		FBOMVersion: "0.1.0",
		SPDXId:      "SPDXRef-FBOM-ROOT",
		CreationInfo: models.CreationInfo{
			Created:       strconv.FormatInt(time.Now().Unix(), 10),
			CreatedBy:     "golang-fbom-generator Function Bill of Materials Generator",
			ToolName:      "golang-fbom-generator",
			ToolVersion:   version.GetVersion(),
			Creators:      []string{"Tool: golang-fbom-generator"},
			LicenseListID: "MIT",
		},
		PackageInfo: models.PackageInfo{
			Name:       actualModuleName,
			SPDXId:     "SPDXRef-Package-" + actualModuleName,
			SourceInfo: "Local Go Package Analysis",
		},
		Functions:          allFunctions,
		CallGraph:          callGraphInfo,
		EntryPoints:        entryPoints,
		Dependencies:       g.dependencyAnalyzer.ExtractDependencies(packages, allFunctions, callGraph, *g.rules.Classifier),
		DependencyClusters: dependencyClusters,
		ReflectionAnalysis: reflectionAnalysis,
		SecurityInfo:       securityInfo,
	}
}
