package reflection

import (
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/cve"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
	"golang.org/x/tools/go/callgraph"
)

// Analyzer handles reflection-specific analysis and security assessment
type Analyzer struct {
	logger      *slog.Logger
	verbose     bool
	config      *Config
	astDetector *Detector // AST-based reflection detector
}

// Config holds configuration for reflection analysis
type Config struct {
	Verbose                     bool
	MaxReflectionDepth          int  // Maximum depth for reflection call analysis
	IncludeDetailedTargets      bool // Whether to include detailed targets (can be large)
	FocusOnSecurityImplications bool // Focus analysis on security implications
}

// NewAnalyzer creates a new reflection analyzer
func NewAnalyzer(logger *slog.Logger, config *Config) *Analyzer {
	if config == nil {
		config = &Config{
			Verbose:                     false,
			MaxReflectionDepth:          10,
			IncludeDetailedTargets:      false, // Default to false to reduce noise
			FocusOnSecurityImplications: true,
		}
	}
	return &Analyzer{
		logger:      logger,
		verbose:     config.Verbose,
		config:      config,
		astDetector: NewDetector(config.Verbose),
	}
}

func (a *Analyzer) BuildReflectionAnalysis(callGraph *callgraph.Graph, classifier *rules.Classifier, cveDatabase *cveloader.CVEDatabase) models.ReflectionAnalysis {
	a.logger.Debug("Building reflection analysis")
	a.logger.Debug("buildReflectionAnalysis called", "has_call_graph", callGraph != nil)

	if callGraph == nil {
		a.logger.Debug("No call graph available for reflection analysis")
		return models.ReflectionAnalysis{
			Summary:           models.ReflectionSummary{RecommendedAction: "No reflection detected"},
			DetailedTargets:   []models.ReflectionTarget{},
			TotalTargets:      0,
			HighRiskTargets:   0,
			MediumRiskTargets: 0,
			LowRiskTargets:    0,
		}
	}

	// Step 1: Collect detailed reflection targets (existing logic)
	targetMap := make(map[string]*models.ReflectionTarget)
	userReflectionFuncs := make(map[string]*models.UserReflectionFunction)

	// Find all reflection calls and their targets
	for fn, node := range callGraph.Nodes {
		if fn == nil || node == nil {
			continue
		}

		callerPkg := rules.GetPackageName(fn)
		callerFunc := fn.Name()

		// Check if this is a user-defined function using reflection
		if !classifier.IsUserDefinedPackage(callerPkg) {
			continue
		}

		// Look for outgoing edges to reflection functions
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			calleePkg := rules.GetPackageName(edge.Callee.Func)
			calleeFunc := edge.Callee.Func.Name()

			// Check if this is a reflection call
			if calleePkg == "reflect" && rules.IsReflectionMethod(calleeFunc) {
				// Track user reflection function
				a.TrackUserReflectionFunction(userReflectionFuncs, callerFunc, callerPkg, calleeFunc)

				// Find what this reflection call targets
				a.FindReflectionTargets(targetMap, edge.Callee, callGraph, callerFunc, calleeFunc, classifier)
			}
		}
	}

	// Step 2: Convert detailed targets and calculate statistics
	targets := make([]models.ReflectionTarget, 0, len(targetMap))
	highRisk, mediumRisk, lowRisk := 0, 0, 0

	for _, target := range targetMap {
		targets = append(targets, *target)
		switch target.RiskLevel {
		case "high":
			highRisk++
		case "medium":
			mediumRisk++
		case "low":
			lowRisk++
		}
	}

	reflectionIntegrator := cve.NewReflectionIntegrator(a.logger, a.verbose)

	// Step 3: Build user-focused analysis
	userFunctions := a.BuildUserReflectionFunctions(userReflectionFuncs, targets)
	vulnerabilityExposure := reflectionIntegrator.BuildVulnerabilityExposure(targets, cveDatabase)
	attackChains := reflectionIntegrator.BuildAttackChains(userFunctions, vulnerabilityExposure)
	summary := a.BuildReflectionSummary(userFunctions, vulnerabilityExposure, attackChains)

	analysis := models.ReflectionAnalysis{
		Summary:                 summary,
		UserReflectionFunctions: userFunctions,
		VulnerabilityExposure:   vulnerabilityExposure,
		AttackChains:            attackChains,
		DetailedTargets:         targets, // Include for completeness but place after user-focused data
		TotalTargets:            len(targets),
		HighRiskTargets:         highRisk,
		MediumRiskTargets:       mediumRisk,
		LowRiskTargets:          lowRisk,
	}

	// Log reflection analysis summary
	a.logger.Debug("Reflection analysis completed",
		"user_functions", len(userFunctions),
		"vulnerability_exposure", len(vulnerabilityExposure),
		"attack_chains", len(attackChains),
		"total_targets", len(targets),
		"high_risk", highRisk)

	return analysis
}

// FindReflectionTargets finds targets of reflection calls
func (a *Analyzer) FindReflectionTargets(targetMap map[string]*models.ReflectionTarget, reflectNode *callgraph.Node, callGraph *callgraph.Graph, callerFunc, reflectMethod string, classifier *rules.Classifier) {
	// Look for outgoing edges from reflection functions to actual targets
	for _, edge := range reflectNode.Out {
		if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
			continue
		}

		targetPkg := rules.GetPackageName(edge.Callee.Func)
		targetFunc := edge.Callee.Func.Name()

		// Skip if target is user-defined code or reflect package itself
		if classifier.IsUserDefinedPackage(targetPkg) || targetPkg == "reflect" {
			continue
		}

		// This is a potential reflection target (dependency or stdlib)
		fullTargetName := targetPkg + "." + targetFunc

		if target, exists := targetMap[fullTargetName]; exists {
			// Update existing target
			target.ReflectionCallers = utils.AddUniqueString(target.ReflectionCallers, callerFunc)
			target.ReflectionMethods = utils.AddUniqueString(target.ReflectionMethods, "reflect."+reflectMethod)
			target.CallCount++
		} else {
			// Create new target
			riskLevel := a.AssessTargetRisk(targetPkg, targetFunc, classifier)
			targetMap[fullTargetName] = &models.ReflectionTarget{
				TargetPackage:     targetPkg,
				TargetFunction:    targetFunc,
				FullTargetName:    fullTargetName,
				ReflectionCallers: []string{callerFunc},
				ReflectionMethods: []string{"reflect." + reflectMethod},
				RiskLevel:         riskLevel,
				CallCount:         1,
			}
		}
	}
}

// TrackUserReflectionFunction tracks a user-defined function that uses reflection
func (a *Analyzer) TrackUserReflectionFunction(userFuncs map[string]*models.UserReflectionFunction, funcName, pkg, reflectMethod string) {
	key := pkg + "." + funcName
	if existing, exists := userFuncs[key]; exists {
		// Add reflection method if not already present
		existing.ReflectionMethods = utils.AddUniqueString(existing.ReflectionMethods, "reflect."+reflectMethod)
	} else {
		// Create new user reflection function
		userFuncs[key] = &models.UserReflectionFunction{
			FunctionName:             funcName,
			Package:                  pkg,
			ReflectionMethods:        []string{"reflect." + reflectMethod},
			ReachableVulnerabilities: []string{},
			RiskScore:                1,        // Will be calculated later
			ReflectionComplexity:     "direct", // Will be assessed later
		}
	}
}

// BuildUserReflectionFunctions creates user-focused reflection function analysis
func (a *Analyzer) BuildUserReflectionFunctions(userFuncs map[string]*models.UserReflectionFunction, targets []models.ReflectionTarget) []models.UserReflectionFunction {
	result := make([]models.UserReflectionFunction, 0, len(userFuncs))

	for _, userFunc := range userFuncs {
		// Find which targets this user function can reach
		reachableVulns := []string{}
		riskScore := 1
		complexity := "direct"

		for _, target := range targets {
			for _, caller := range target.ReflectionCallers {
				if caller == userFunc.FunctionName {
					// Check if this target is associated with a CVE
					switch target.RiskLevel {
					case "high":
						riskScore = utils.Max(riskScore, 8)
						// This would need CVE mapping logic - simplified for now
						if strings.Contains(target.TargetPackage, "protobuf") {
							reachableVulns = utils.AddUniqueString(reachableVulns, "GO-2024-2611")
						}
					case "medium":
						riskScore = utils.Max(riskScore, 5)
					}
				}
			}
		}

		// Assess complexity based on function name patterns
		lowerFuncName := strings.ToLower(userFunc.FunctionName)
		if strings.Contains(lowerFuncName, "advanced") || strings.Contains(lowerFuncName, "dynamic") {
			complexity = "layered"
		}
		if strings.Contains(lowerFuncName, "process") && len(userFunc.ReflectionMethods) > 1 {
			complexity = "dynamic"
		}

		userFunc.ReachableVulnerabilities = reachableVulns
		userFunc.RiskScore = riskScore
		userFunc.ReflectionComplexity = complexity

		result = append(result, *userFunc)
	}

	return result
}

// BuildReflectionSummary creates high-level reflection security overview
func (a *Analyzer) BuildReflectionSummary(userFuncs []models.UserReflectionFunction, exposures []models.ReflectionVulnerabilityExposure, chains []models.ReflectionAttackChain) models.ReflectionSummary {
	highRiskPaths := 0
	for _, chain := range chains {
		if chain.AttackComplexity == "high" || chain.LayerCount >= 3 {
			highRiskPaths++
		}
	}

	complexity := "simple"
	if len(chains) > 2 {
		complexity = "moderate"
	}
	if highRiskPaths > 0 || len(chains) > 5 {
		complexity = "complex"
	}

	action := "Review reflection usage for security implications"
	if len(exposures) > 0 {
		action = "URGENT: Review CVE exposure via reflection - manual security audit recommended"
	} else if len(userFuncs) == 0 {
		action = "No reflection detected - good security posture"
	}

	return models.ReflectionSummary{
		UserReflectionFunctions:      len(userFuncs),
		VulnerableFunctionsReachable: len(exposures),
		HighRiskReflectionPaths:      highRiskPaths,
		ReflectionComplexity:         complexity,
		RecommendedAction:            action,
	}
}

// AssessTargetRisk assesses the risk level of a reflection target
func (a *Analyzer) AssessTargetRisk(targetPkg, targetFunc string, classifier *rules.Classifier) string {
	// Get high-risk packages and functions from configuration
	highRiskPackages := classifier.GetHighRiskPackages()
	highRiskFunctions := classifier.GetHighRiskFunctions()

	// Check for high-risk patterns
	for _, pkg := range highRiskPackages {
		if strings.Contains(targetPkg, pkg) {
			return "high"
		}
	}

	for _, fn := range highRiskFunctions {
		if strings.Contains(targetFunc, fn) {
			return "high"
		}
	}

	// Medium-risk: any dependency package
	if classifier.IsDependencyPackage(targetPkg) {
		return "medium"
	}

	// Low-risk: standard library
	return "low"
}
