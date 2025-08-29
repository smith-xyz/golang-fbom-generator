package cve

import (
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cveloader"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
)

// ReflectionIntegrator handles integration between CVE analysis and reflection analysis
type ReflectionIntegrator struct {
	logger  *slog.Logger
	verbose bool
}

// NewReflectionIntegrator creates a new reflection integrator
func NewReflectionIntegrator(logger *slog.Logger, verbose bool) *ReflectionIntegrator {
	return &ReflectionIntegrator{
		logger:  logger,
		verbose: verbose,
	}
}

// CheckReflectionAnalysisForCVE checks reflection analysis for CVE matches
func (r *ReflectionIntegrator) CheckReflectionAnalysisForCVE(targetCVE models.CVE, reflectionAnalysis models.ReflectionAnalysis) bool {
	r.logger.Debug("Checking CVE against reflection targets",
		"cve_id", targetCVE.ID,
		"reflection_targets", len(reflectionAnalysis.DetailedTargets),
		"cve_package", targetCVE.VulnerablePackage,
		"cve_functions", targetCVE.VulnerableFunctions)

	// Check if any reflection targets match the vulnerable package and functions
	for _, target := range reflectionAnalysis.DetailedTargets {
		// Check if target package matches vulnerable package
		if strings.HasPrefix(target.TargetPackage, targetCVE.VulnerablePackage) {
			// Check if target function matches any vulnerable function
			for _, vulnFunc := range targetCVE.VulnerableFunctions {
				if strings.Contains(target.TargetFunction, vulnFunc) {
					if r.verbose {
						r.logger.Debug("Found reflection target matching CVE",
							"cve_id", targetCVE.ID,
							"target_package", target.TargetPackage,
							"target_function", target.TargetFunction,
							"vulnerable_function", vulnFunc,
							"risk_level", target.RiskLevel,
							"callers", target.ReflectionCallers)
					}
					return true
				}
			}
		}
	}
	return false
}

// BuildVulnerabilityExposure builds vulnerability exposure from reflection targets
func (r *ReflectionIntegrator) BuildVulnerabilityExposure(targets []models.ReflectionTarget, cveDatabase *cveloader.CVEDatabase) []models.ReflectionVulnerabilityExposure {
	exposureMap := make(map[string]*models.ReflectionVulnerabilityExposure)

	for _, target := range targets {
		if target.RiskLevel != "high" {
			continue // Focus on high-risk targets that likely have CVEs
		}

		// Look up CVEs from the database that match this reflection target
		var matchingCVEs []models.CVE
		if cveDatabase != nil {
			// Find CVEs that affect the target package
			packageCVEs := cveDatabase.FindByPackage(target.TargetPackage)
			for _, cve := range packageCVEs {
				// Check if any vulnerable functions match the target function
				for _, vulnFunc := range cve.VulnerableFunctions {
					if strings.Contains(target.TargetFunction, vulnFunc) || vulnFunc == target.TargetFunction {
						matchingCVEs = append(matchingCVEs, cve)
						break
					}
				}
			}
		}

		// Process each matching CVE
		for _, cve := range matchingCVEs {
			cveId := cve.ID
			if existing, exists := exposureMap[cveId]; exists {
				// Merge reflection functions
				for _, caller := range target.ReflectionCallers {
					existing.YourReflectionFunctions = utils.AddUniqueString(existing.YourReflectionFunctions, caller)
				}
			} else {
				// Create new exposure record
				complexity := "medium"
				likelihood := "medium"

				// Assess complexity based on reflection caller patterns
				if len(target.ReflectionCallers) > 3 {
					complexity = "high"
					likelihood = "high"
				}

				exposureMap[cveId] = &models.ReflectionVulnerabilityExposure{
					CVEId:                   cveId,
					VulnerableFunction:      target.FullTargetName,
					YourReflectionFunctions: append([]string{}, target.ReflectionCallers...),
					AttackComplexity:        complexity,
					ExploitLikelihood:       likelihood,
				}
			}
		}

		// Log when no CVEs found for high-risk target (for debugging)
		if len(matchingCVEs) == 0 && r.verbose {
			r.logger.Debug("No CVEs found for high-risk reflection target",
				"package", target.TargetPackage,
				"function", target.TargetFunction,
				"risk_level", target.RiskLevel)
		}
	}

	result := make([]models.ReflectionVulnerabilityExposure, 0, len(exposureMap))
	for _, exposure := range exposureMap {
		result = append(result, *exposure)
	}

	return result
}

// BuildAttackChains builds attack chains from reflection analysis
func (r *ReflectionIntegrator) BuildAttackChains(userFuncs []models.UserReflectionFunction, exposures []models.ReflectionVulnerabilityExposure) []models.ReflectionAttackChain {
	var chains []models.ReflectionAttackChain

	for _, exposure := range exposures {
		for _, userFunc := range userFuncs {
			// Check if this user function can reach this vulnerability
			for _, reachableVuln := range userFunc.ReachableVulnerabilities {
				if reachableVuln == exposure.CVEId {
					// Build attack chain
					entryPoint := r.InferEntryPoint(userFunc.FunctionName)
					steps := r.buildChainSteps(userFunc, exposure)
					layerCount := r.CountReflectionLayers(steps)

					chain := models.ReflectionAttackChain{
						CVEId:            exposure.CVEId,
						EntryPoint:       entryPoint,
						ChainSteps:       steps,
						LayerCount:       layerCount,
						AttackComplexity: r.assessChainComplexity(layerCount, userFunc.ReflectionComplexity),
					}

					chains = append(chains, chain)
				}
			}
		}
	}

	return chains
}

// Helper functions for attack chain analysis
func (r *ReflectionIntegrator) InferEntryPoint(funcName string) string {
	lowerName := strings.ToLower(funcName)
	if strings.Contains(lowerName, "handler") || strings.Contains(lowerName, "handle") {
		return "HTTP endpoint"
	}
	if strings.Contains(lowerName, "process") {
		return "Processing function"
	}
	return "User function: " + funcName
}

func (r *ReflectionIntegrator) buildChainSteps(userFunc models.UserReflectionFunction, exposure models.ReflectionVulnerabilityExposure) []string {
	steps := []string{
		"Entry: " + userFunc.FunctionName + "()",
	}

	// Add reflection steps based on complexity
	switch userFunc.ReflectionComplexity {
	case "layered":
		steps = append(steps, "Layer 1: Reflection call dispatch")
		steps = append(steps, "Layer 2: Dynamic method resolution")
	case "dynamic":
		steps = append(steps, "Dynamic reflection routing")
		steps = append(steps, "Runtime method selection")
	}

	steps = append(steps, "Target: "+exposure.VulnerableFunction)
	steps = append(steps, "Exploit: "+exposure.CVEId)

	return steps
}

func (r *ReflectionIntegrator) CountReflectionLayers(steps []string) int {
	layers := 0
	for _, step := range steps {
		if strings.Contains(step, "Layer") || strings.Contains(step, "reflection") {
			layers++
		}
	}
	return utils.Max(layers, 1) // At least 1 layer for any reflection
}

func (r *ReflectionIntegrator) assessChainComplexity(layerCount int, userComplexity string) string {
	if layerCount >= 3 || userComplexity == "dynamic" {
		return "high"
	}
	if layerCount >= 2 || userComplexity == "layered" {
		return "medium"
	}
	return "low"
}
