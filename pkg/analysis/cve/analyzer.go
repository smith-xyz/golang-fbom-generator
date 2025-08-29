package cve

import (
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Analyzer handles CVE analysis operations independently of FBOMGenerator
type Analyzer struct {
	logger                *slog.Logger
	verbose               bool
	config                *Config
	additionalEntryPoints []string
}

// Config holds configuration for CVE analysis
type Config struct {
	Verbose bool
	// Add other CVE-specific config options as needed
}

// NewAnalyzer creates a new CVE analyzer instance
func NewAnalyzer(logger *slog.Logger, config *Config) *Analyzer {
	if config == nil {
		config = &Config{}
	}
	return &Analyzer{
		logger:                logger,
		verbose:               config.Verbose,
		config:                config,
		additionalEntryPoints: make([]string, 0),
	}
}

// SetAdditionalEntryPoints configures additional entry point patterns for reachability analysis
func (a *Analyzer) SetAdditionalEntryPoints(entryPoints []string) {
	a.additionalEntryPoints = make([]string, len(entryPoints))
	copy(a.additionalEntryPoints, entryPoints)
	if a.verbose {
		a.logger.Debug("Set additional entry points for CVE analyzer", "patterns", a.additionalEntryPoints)
	}
}

func (a *Analyzer) BuildSecurityInfo(assessments []models.Assessment, reflectionUsage map[string]*models.Usage) models.SecurityInfo {
	vulnerableFunctionMap := make(map[string]*models.VulnerableFunction)
	unreachableVulnerabilities := make([]string, 0)
	reachableCount := 0

	// Process each CVE assessment
	for _, assessment := range assessments {
		if assessment.ReachabilityStatus == models.NotReachable {
			unreachableVulnerabilities = append(unreachableVulnerabilities, assessment.CVE.ID)
		} else {
			reachableCount++

			// Create vulnerable function entries for reachable CVEs
			for _, path := range assessment.CallPaths {
				// Extract package and function name for better identification
				packagePath, functionName := a.ExtractPackageAndFunction(path.VulnerableFunc)
				fullName := path.VulnerableFunc // Use the full name as provided
				if packagePath != "" && functionName != "" {
					fullName = packagePath + "." + functionName
				}

				// Use full name as the key for deduplication
				if existing, exists := vulnerableFunctionMap[fullName]; exists {
					// Merge CVEs and reachability paths
					existing.CVEs = utils.AddUniqueString(existing.CVEs, assessment.CVE.ID)
					existing.ReachabilityPaths = utils.AddUniqueString(existing.ReachabilityPaths, path.EntryPoint)
					// Update risk score if this one is higher
					newRiskScore := a.CalculateRiskScore(assessment)
					if newRiskScore > existing.RiskScore {
						existing.RiskScore = newRiskScore
						existing.Impact = strings.ToLower(assessment.CalculatedPriority)
					}
				} else {
					// Create new vulnerable function entry
					vulnFunc := &models.VulnerableFunction{
						FunctionId:        functionName,
						FullName:          fullName,
						CVEs:              []string{assessment.CVE.ID},
						ReachabilityPaths: []string{path.EntryPoint},
						RiskScore:         a.CalculateRiskScore(assessment),
						Impact:            strings.ToLower(assessment.CalculatedPriority),
					}
					vulnerableFunctionMap[fullName] = vulnFunc
				}
			}
		}
	}

	// Convert map to slice
	vulnerableFunctions := make([]models.VulnerableFunction, 0, len(vulnerableFunctionMap))
	for _, vulnFunc := range vulnerableFunctionMap {
		vulnerableFunctions = append(vulnerableFunctions, *vulnFunc)
	}

	return models.SecurityInfo{
		VulnerableFunctions:        vulnerableFunctions,
		UnreachableVulnerabilities: unreachableVulnerabilities,
		ReflectionCallsCount:       len(reflectionUsage),
		TotalCVEsFound:             len(assessments),
		TotalReachableCVEs:         reachableCount,
	}
}

// AnalyzeCVEs performs analysis on all CVEs in the database
func (a *Analyzer) AnalyzeCVEs(cveDatabase *cveloader.CVEDatabase, callGraph *callgraph.Graph, ssaProgram *ssa.Program, reflectionUsage map[string]*models.Usage, dependencyClusters []models.DependencyCluster, reflectionAnalysis models.ReflectionAnalysis) []models.Assessment {
	if a.verbose {
		a.logger.Debug("Starting CVE analysis", "cve_count", len(cveDatabase.CVEs))
	}

	var assessments []models.Assessment
	for _, vulnCVE := range cveDatabase.CVEs {
		assessment := a.AnalyzeCVE(vulnCVE, callGraph, ssaProgram, reflectionUsage, dependencyClusters, reflectionAnalysis)
		if assessment != nil {
			assessments = append(assessments, *assessment)
		}
	}

	if a.verbose {
		a.logger.Debug("Completed CVE analysis", "assessment_count", len(assessments))
	}

	return assessments
}

// AnalyzeCVE performs detailed analysis on a single CVE
func (a *Analyzer) AnalyzeCVE(targetCVE models.CVE, callGraph *callgraph.Graph, ssaProgram *ssa.Program, reflectionUsage map[string]*models.Usage, dependencyClusters []models.DependencyCluster, reflectionAnalysis models.ReflectionAnalysis) *models.Assessment {
	if a.verbose {
		a.logger.Debug("Analyzing CVE", "cve_id", targetCVE.ID, "package", targetCVE.VulnerablePackage)
	}

	assessment := &models.Assessment{
		CVE:              targetCVE,
		OriginalPriority: targetCVE.OriginalSeverity,
	}

	reflectionIntegrator := NewReflectionIntegrator(a.logger, a.verbose)
	riskAssessor := NewRiskAssessor(a.logger, a.verbose)
	reachabilityAnalyzer := NewReachabilityAnalyzer(a.logger, a.verbose)

	vulnerableNodes := a.FindVulnerableFunctions(callGraph, targetCVE)
	if len(vulnerableNodes) == 0 {
		if reflectionIntegrator.CheckReflectionAnalysisForCVE(targetCVE, reflectionAnalysis) {
			assessment.ReachabilityStatus = models.ReflectionPossible
			assessment.ReflectionRisk = models.RiskHigh
			assessment.CallPaths = []models.CallPath{{
				EntryPoint:     "USER_CODE -> reflect.Call",
				VulnerableFunc: strings.Join(targetCVE.VulnerableFunctions, ","),
				Steps:          []string{"reflection-based call detected"},
			}}
			if a.verbose {
				a.logger.Debug("CVE reachable via reflection analysis", "cve_id", targetCVE.ID)
			}
			return assessment
		}

		assessment.ReachabilityStatus = models.NotReachable

		// ENHANCED: Check for high reflection risk even when functions aren't directly reachable
		// This is critical for cases where vulnerable functions might be called via reflection
		maxReflectionRisk := riskAssessor.AssessGlobalReflectionRisk(reflectionUsage, targetCVE.VulnerablePackage)
		assessment.ReflectionRisk = maxReflectionRisk

		if maxReflectionRisk >= models.RiskHigh {
			assessment.CalculatedPriority = "UNCERTAIN (High reflection risk - manual review required)"
			assessment.Justification = "Vulnerable functions not in static call graph, but high-risk reflection detected"
			assessment.RequiresManualReview = true
		} else {
			assessment.CalculatedPriority = "Low (Vulnerable function not found in call graph)"
			assessment.Justification = "Vulnerable functions not found in call graph"
		}
		return assessment
	}

	// Step 2: Analyze reachability from entry points
	var reachability models.ReachabilityResult
	// Use cluster-based analysis if dependency clusters are available
	if len(dependencyClusters) > 0 {
		reachability = reachabilityAnalyzer.AnalyzeReachabilityWithClusters(vulnerableNodes, targetCVE, dependencyClusters)
	} else {
		// Fallback to traditional path-finding
		entryPoints := a.additionalEntryPoints // Use configured entry points
		reachability = reachabilityAnalyzer.AnalyzeReachability(callGraph, vulnerableNodes, entryPoints)
	}

	// Step 2.5: Check reflection analysis even if cluster analysis found/didn't find reachability
	// This is critical for reflection-based vulnerabilities that clusters might miss
	if reachability.Status == models.NotReachable && reflectionIntegrator.CheckReflectionAnalysisForCVE(targetCVE, reflectionAnalysis) {
		// Override cluster analysis result with reflection-based reachability
		reachability.Status = models.ReflectionPossible
		reachability.Paths = []models.CallPath{{
			EntryPoint:     "USER_CODE -> reflect.Call",
			VulnerableFunc: strings.Join(targetCVE.VulnerableFunctions, ","),
			Steps:          []string{"reflection-based call detected"},
		}}
		reachability.MinDistance = 1 // Reflection calls are considered 1 hop
		a.logger.Debug("CVE reachability upgraded via reflection analysis",
			"cve_id", targetCVE.ID,
			"package", targetCVE.VulnerablePackage)
	}

	assessment.ReachabilityStatus = reachability.Status
	assessment.CallPaths = reachability.Paths
	assessment.EntryPointDistance = reachability.MinDistance

	// Step 3: Check for reflection usage in call paths
	reflectionRisk := riskAssessor.AssessReflectionRisk(reflectionUsage, reachability.Paths)
	assessment.ReflectionRisk = reflectionRisk

	// Step 4: Calculate final priority using sophisticated algorithm
	assessment.CalculatedPriority = riskAssessor.CalculatePriority(targetCVE, reachability, reflectionRisk)
	assessment.Justification = riskAssessor.GenerateJustification(assessment)
	assessment.RequiresManualReview = a.RequiresManualReview(assessment)

	if a.verbose {
		a.logger.Debug("CVE analysis complete", "cve_id", targetCVE.ID, "reachability_status", assessment.ReachabilityStatus, "vulnerable_nodes", len(vulnerableNodes), "call_paths", len(reachability.Paths))
	}

	return assessment
}

// FindVulnerableFunctions finds call graph nodes that match vulnerable functions
func (a *Analyzer) FindVulnerableFunctions(callGraph *callgraph.Graph, targetCVE models.CVE) []*callgraph.Node {
	var vulnerableNodes []*callgraph.Node

	if callGraph == nil {
		if a.verbose {
			a.logger.Debug("Call graph is nil, cannot find vulnerable functions")
		}
		return vulnerableNodes
	}

	if a.verbose {
		a.logger.Debug("Finding vulnerable functions", "cve_id", targetCVE.ID, "vulnerable_package", targetCVE.VulnerablePackage, "vulnerable_functions", targetCVE.VulnerableFunctions, "total_nodes", len(callGraph.Nodes))
	}

	// Find direct vulnerable functions
	vulnerableNodes = a.FindDirectVulnerableFunctions(callGraph, targetCVE)

	if a.verbose {
		a.logger.Debug("Found vulnerable functions", "total_count", len(vulnerableNodes))
	}

	return vulnerableNodes
}

// FindDirectVulnerableFunctions finds directly vulnerable functions in the call graph
func (a *Analyzer) FindDirectVulnerableFunctions(callGraph *callgraph.Graph, targetCVE models.CVE) []*callgraph.Node {
	var vulnerableNodes []*callgraph.Node

	for fn, node := range callGraph.Nodes {
		if fn == nil || node == nil {
			continue
		}

		// Check if package information is available
		if fn.Pkg == nil || fn.Pkg.Pkg == nil {
			continue
		}

		funcName := fn.Name()
		packagePath := fn.Pkg.Pkg.Path()

		// Check if this function matches the vulnerable package and functions
		if strings.HasPrefix(packagePath, targetCVE.VulnerablePackage) {
			for _, vulnFunc := range targetCVE.VulnerableFunctions {
				if strings.Contains(funcName, vulnFunc) {
					vulnerableNodes = append(vulnerableNodes, node)
					if a.verbose {
						a.logger.Debug("Found direct vulnerable function", "function", funcName, "package", packagePath)
					}
				}
			}
		}
	}

	return vulnerableNodes
}

// CalculateRiskScore calculates numerical risk score for an assessment
func (a *Analyzer) CalculateRiskScore(assessment models.Assessment) float64 {
	baseScore := 5.0 // Default medium risk

	// Adjust based on reachability
	switch assessment.ReachabilityStatus {
	case models.DirectlyReachable:
		baseScore += 3.0
	case models.TransitivelyReachable:
		baseScore += 1.0
	case models.ReflectionPossible:
		baseScore += 0.5
	}

	// Adjust based on distance from entry points
	if assessment.EntryPointDistance > 0 {
		distancePenalty := float64(assessment.EntryPointDistance) * 0.2
		baseScore = baseScore - distancePenalty
	}

	// Ensure score is within 0-10 range
	if baseScore > 10.0 {
		baseScore = 10.0
	}
	if baseScore < 0.0 {
		baseScore = 0.0
	}

	return baseScore
}

// ExtractPackageAndFunction parses package/function from strings
func (a *Analyzer) ExtractPackageAndFunction(fullFuncName string) (packagePath, functionName string) {
	// Handle common patterns:
	// 1. "package/path.FunctionName"
	// 2. "(*Type).MethodName"
	// 3. "package/path.(*Type).MethodName"
	// 4. Just "FunctionName"

	if fullFuncName == "" {
		return "", ""
	}

	// Handle method receivers like (*Type).Method
	if strings.Contains(fullFuncName, ").") {
		// Find the last occurrence of ").MethodName"
		if idx := strings.LastIndex(fullFuncName, ")."); idx != -1 {
			methodName := fullFuncName[idx+2:]
			beforeMethod := fullFuncName[:idx]

			// Now extract package from the part before the method
			if lastDot := strings.LastIndex(beforeMethod, "."); lastDot != -1 {
				packagePath = beforeMethod[:lastDot]
				// Type name is between last dot and opening paren
				if parenIdx := strings.LastIndex(beforeMethod, "("); parenIdx != -1 {
					typeName := beforeMethod[lastDot+1 : parenIdx]
					// Include type in the function name for clarity
					functionName = "(" + typeName + ")." + methodName
				} else {
					functionName = methodName
				}
			} else {
				functionName = methodName
			}
			return packagePath, functionName
		}
	}

	// Handle regular function calls like "package/path.FunctionName"
	if lastDot := strings.LastIndex(fullFuncName, "."); lastDot != -1 {
		packagePath = fullFuncName[:lastDot]
		functionName = fullFuncName[lastDot+1:]
		return packagePath, functionName
	}

	// No package separator found, treat as just function name
	return "", fullFuncName
}

// RequiresManualReview determines if an assessment requires manual review
func (a *Analyzer) RequiresManualReview(assessment *models.Assessment) bool {
	return assessment.ReflectionRisk >= models.RiskHigh ||
		strings.Contains(assessment.CalculatedPriority, "UNCERTAIN")
}
