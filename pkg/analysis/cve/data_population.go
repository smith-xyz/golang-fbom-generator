package cve

import (
	"log/slog"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
)

// DataPopulator handles CVE data mapping and population
type DataPopulator struct {
	logger  *slog.Logger
	verbose bool
	// Performance optimization: Pre-built lookup indices
	functionNameIndex   map[string][]*models.Function // name -> functions with that name
	functionSuffixIndex map[string][]*models.Function // suffix -> functions ending with that suffix
	indexedFunctions    map[string]*models.Function   // Tracks which function map was indexed
}

// NewDataPopulator creates a new data populator
func NewDataPopulator(logger *slog.Logger, verbose bool) *DataPopulator {
	return &DataPopulator{
		logger:  logger,
		verbose: verbose,
	}
}

// PopulateClusterVulnerabilityIDs maps CVEs to dependency clusters
func (d *DataPopulator) PopulateClusterVulnerabilityIDs(dependencyClusters []models.DependencyCluster, assessments []models.Assessment) {
	if d.verbose {
		d.logger.Debug("Populating cluster vulnerability IDs", "clusters", len(dependencyClusters), "assessments", len(assessments))
	}

	// Create a map of vulnerable functions to their CVE IDs
	vulnerableFunctionToCVEs := make(map[string][]string)

	for _, assessment := range assessments {
		if assessment.ReachabilityStatus == models.DirectlyReachable || assessment.ReachabilityStatus == models.TransitivelyReachable || assessment.ReachabilityStatus == models.ReflectionPossible {
			// Map all functions in call paths to this CVE
			for _, callPath := range assessment.CallPaths {
				for _, step := range callPath.Steps {
					functionName := step
					if functionName != "" {
						if _, exists := vulnerableFunctionToCVEs[functionName]; !exists {
							vulnerableFunctionToCVEs[functionName] = []string{}
						}
						vulnerableFunctionToCVEs[functionName] = utils.AddUniqueString(vulnerableFunctionToCVEs[functionName], assessment.CVE.ID)
					}
				}
			}
		}
	}

	// Update attack paths in dependency clusters
	for i, cluster := range dependencyClusters {
		for j, attackPath := range cluster.AttackPaths {
			var vulnerabilityIDs []string

			// Check each path step for vulnerabilities
			for _, pathStep := range attackPath.Path {
				if cveList, found := vulnerableFunctionToCVEs[pathStep.Function]; found {
					for _, cveID := range cveList {
						vulnerabilityIDs = utils.AddUniqueString(vulnerabilityIDs, cveID)
					}
				}
			}

			// Update the attack path with found vulnerability IDs
			dependencyClusters[i].AttackPaths[j].VulnerabilityIDs = vulnerabilityIDs

			if len(vulnerabilityIDs) > 0 && d.verbose {
				d.logger.Debug("Updated attack path with vulnerability IDs",
					"cluster", cluster.Name,
					"entry_function", attackPath.EntryFunction,
					"vulnerability_count", len(vulnerabilityIDs),
					"vulnerability_ids", vulnerabilityIDs)
			}
		}
	}

	if d.verbose {
		// Log statistics
		totalVulnerablePaths := 0
		totalVulnerabilityIDs := 0
		for _, cluster := range dependencyClusters {
			for _, attackPath := range cluster.AttackPaths {
				if len(attackPath.VulnerabilityIDs) > 0 {
					totalVulnerablePaths++
					totalVulnerabilityIDs += len(attackPath.VulnerabilityIDs)
				}
			}
		}
		d.logger.Debug("Completed cluster vulnerability ID population",
			"vulnerable_attack_paths", totalVulnerablePaths,
			"total_vulnerability_mappings", totalVulnerabilityIDs)
	}
}

// PopulateFunctionCVEReferences maps CVEs to functions
func (d *DataPopulator) PopulateFunctionCVEReferences(functions []models.Function, assessments []models.Assessment, dependencyClusters []models.DependencyCluster) {
	// Create a map for fast function lookup by full name
	functionMap := make(map[string]*models.Function)
	// Also create a map for short name lookups (just the function name)
	shortNameMap := make(map[string]*models.Function)

	for i := range functions {
		functionMap[functions[i].FullName] = &functions[i]
		// Also map by short name (last part after the last dot)
		shortName := functions[i].Name
		if shortName != "" {
			shortNameMap[shortName] = &functions[i]
		}
	}

	if d.verbose {
		d.logger.Debug("Function maps created", "full_name_count", len(functionMap), "short_name_count", len(shortNameMap))
	}

	// For each CVE assessment, update the CVE references of involved functions
	for _, assessment := range assessments {
		if assessment.ReachabilityStatus == models.NotReachable {
			continue // Skip unreachable CVEs
		}

		// Process each call path to find functions involved
		for _, path := range assessment.CallPaths {
			if d.verbose {
				d.logger.Debug("Processing call path", "cve_id", assessment.CVE.ID, "vulnerable_func", path.VulnerableFunc, "entry_point", path.EntryPoint, "steps", len(path.Steps))
			}

			// Add CVE reference to the vulnerable function
			vulnFunc := d.findFunctionInMaps(path.VulnerableFunc, functionMap, shortNameMap)
			if vulnFunc != nil {
				vulnFunc.UsageInfo.CVEReferences = utils.AddUniqueString(vulnFunc.UsageInfo.CVEReferences, assessment.CVE.ID)
				if d.verbose {
					d.logger.Debug("Added CVE reference to vulnerable function", "function", path.VulnerableFunc, "cve_id", assessment.CVE.ID)
				}
			} else if d.verbose {
				d.logger.Debug("Vulnerable function not found in function map", "function", path.VulnerableFunc, "cve_id", assessment.CVE.ID)
			}

			// Add CVE reference to the entry point function
			entryFunc := d.findFunctionInMaps(path.EntryPoint, functionMap, shortNameMap)
			if entryFunc != nil {
				entryFunc.UsageInfo.CVEReferences = utils.AddUniqueString(entryFunc.UsageInfo.CVEReferences, assessment.CVE.ID)
				if d.verbose {
					d.logger.Debug("Added CVE reference to entry point function", "function", path.EntryPoint, "cve_id", assessment.CVE.ID)
				}
			} else if d.verbose {
				d.logger.Debug("Entry point function not found in function map", "function", path.EntryPoint, "cve_id", assessment.CVE.ID)
			}

			// Add CVE reference to any intermediate functions in the path
			for _, stepFunc := range path.Steps {
				stepFunction := d.findFunctionInMaps(stepFunc, functionMap, shortNameMap)
				if stepFunction != nil {
					stepFunction.UsageInfo.CVEReferences = utils.AddUniqueString(stepFunction.UsageInfo.CVEReferences, assessment.CVE.ID)
					if d.verbose {
						d.logger.Debug("Added CVE reference to step function", "function", stepFunc, "cve_id", assessment.CVE.ID)
					}
				} else if d.verbose {
					d.logger.Debug("Step function not found in function map", "function", stepFunc, "cve_id", assessment.CVE.ID)
				}
			}
		}
	}

	d.PropagateTransitiveCVEReferences(functions, functionMap, dependencyClusters)

	if d.verbose {
		// Log statistics about CVE reference population
		totalFunctionsWithCVEs := 0
		for _, function := range functions {
			if len(function.UsageInfo.CVEReferences) > 0 {
				totalFunctionsWithCVEs++
			}
		}
		d.logger.Debug("Populated CVE references (including transitive)", "functions_with_cves", totalFunctionsWithCVEs, "total_assessments", len(assessments))
	}
}

// PropagateTransitiveCVEReferences propagates transitive CVE references
func (d *DataPopulator) PropagateTransitiveCVEReferences(functions []models.Function, functionMap map[string]*models.Function, dependencyClusters []models.DependencyCluster) {
	if d.verbose {
		d.logger.Debug("Starting transitive CVE reference propagation")
	}

	// Build a reverse call graph from dependency clusters: external function -> list of user functions that call it
	callerMap := make(map[string][]*models.Function)

	// Extract call relationships from dependency clusters
	for _, cluster := range dependencyClusters {
		for _, entryPoint := range cluster.EntryPoints {
			// entryPoint.Function is the external function (e.g., "Parse")
			// entryPoint.CalledFrom contains user functions that call it (e.g., ["parseHTML", "parseLanguageTags"])
			externalFuncName := entryPoint.Function

			for _, callerName := range entryPoint.CalledFrom {
				// Find the user function that calls this external function
				if userFunc := d.findFunctionInMaps(callerName, functionMap, nil); userFunc != nil {
					callerMap[externalFuncName] = append(callerMap[externalFuncName], userFunc)
					if d.verbose {
						d.logger.Debug("Mapped call relationship from dependency cluster",
							"external_func", externalFuncName,
							"user_func", userFunc.FullName,
							"cluster", cluster.Name)
					}
				}
			}
		}
	}

	if d.verbose {
		d.logger.Debug("Built reverse call graph from dependency clusters", "external_functions", len(callerMap))
	}

	// Find all functions that currently have CVE references (initial vulnerable functions)
	// These are external library functions like "Parse", "init"
	var vulnerableFunctions []*models.Function
	for i := range functions {
		if len(functions[i].UsageInfo.CVEReferences) > 0 {
			vulnerableFunctions = append(vulnerableFunctions, &functions[i])
		}
	}

	if d.verbose {
		d.logger.Debug("Found initial vulnerable functions", "count", len(vulnerableFunctions))
	}

	// Step 1: Propagate CVE references from external vulnerable functions to user functions that call them
	userFunctionsToPropagate := make([]*models.Function, 0)
	propagatedCount := 0

	for _, vulnFunc := range vulnerableFunctions {
		// vulnFunc.Name is something like "Parse" or "init"
		// Look up which user functions call this external function
		if callers, exists := callerMap[vulnFunc.Name]; exists {
			for _, userFunc := range callers {
				// Propagate CVE references from external function to user function
				for _, cveID := range vulnFunc.UsageInfo.CVEReferences {
					userFunc.UsageInfo.CVEReferences = utils.AddUniqueString(userFunc.UsageInfo.CVEReferences, cveID)
				}
				userFunctionsToPropagate = append(userFunctionsToPropagate, userFunc)
				propagatedCount++

				if d.verbose {
					d.logger.Debug("Propagated CVE references from external to user function",
						"external_func", vulnFunc.Name,
						"user_func", userFunc.FullName,
						"cve_count", len(vulnFunc.UsageInfo.CVEReferences))
				}
			}
		}
	}

	// Step 2: Build user function call graph and propagate transitively within user functions
	// Build reverse call graph for user functions: user function -> list of user functions that call it
	userCallerMap := make(map[string][]*models.Function)
	for i := range functions {
		fn := &functions[i]
		for _, calledFunc := range fn.UsageInfo.Calls {
			if targetFunc, exists := functionMap[calledFunc]; exists {
				userCallerMap[targetFunc.FullName] = append(userCallerMap[targetFunc.FullName], fn)
			}
		}
	}

	// Step 3: Continue propagating within user function call chains using BFS
	visited := make(map[string]bool)
	queue := make([]*models.Function, 0, len(userFunctionsToPropagate))

	// Initialize queue with user functions that now have CVE references
	for _, userFunc := range userFunctionsToPropagate {
		queue = append(queue, userFunc)
		visited[userFunc.FullName] = true
	}

	for len(queue) > 0 {
		currentFunc := queue[0]
		queue = queue[1:]

		// Find user functions that call this user function
		if callers, exists := userCallerMap[currentFunc.FullName]; exists {
			for _, caller := range callers {
				if !visited[caller.FullName] {
					// Propagate all CVE references from the current function to its caller
					for _, cveID := range currentFunc.UsageInfo.CVEReferences {
						caller.UsageInfo.CVEReferences = utils.AddUniqueString(caller.UsageInfo.CVEReferences, cveID)
					}

					visited[caller.FullName] = true
					queue = append(queue, caller)
					propagatedCount++

					if d.verbose {
						d.logger.Debug("Propagated CVE references transitively within user functions",
							"from", currentFunc.FullName,
							"to", caller.FullName,
							"cve_count", len(currentFunc.UsageInfo.CVEReferences))
					}
				}
			}
		}
	}

	if d.verbose {
		d.logger.Debug("Transitive CVE propagation completed", "propagated_to_functions", propagatedCount)
	}
}

// findFunctionInMaps tries to find a function using sophisticated matching strategies
func (d *DataPopulator) findFunctionInMaps(name string, fullNameMap map[string]*models.Function, shortNameMap map[string]*models.Function) *models.Function {
	if d.verbose {
		d.logger.Debug("Searching for function", "name", name)
	}

	// Strategy 1: Try exact match with full name
	if fn, exists := fullNameMap[name]; exists {
		if d.verbose {
			d.logger.Debug("Found exact full name match", "name", name, "matched", fn.FullName)
		}
		return fn
	}

	// Strategy 2: Handle patterns like "USER_CODE -> functionName"
	if strings.Contains(name, " -> ") {
		parts := strings.Split(name, " -> ")
		if len(parts) >= 2 {
			targetFunc := parts[len(parts)-1] // Get the last part (actual function name)
			if d.verbose {
				d.logger.Debug("Extracted function name from path", "original", name, "extracted", targetFunc)
			}
			return d.findBestUserFunctionMatch(targetFunc, fullNameMap, shortNameMap)
		}
	}

	// Strategy 3: For simple names, try to find the best user function match
	return d.findBestUserFunctionMatch(name, fullNameMap, shortNameMap)
}

// buildFunctionIndices creates optimized lookup indices for faster function matching
func (d *DataPopulator) buildFunctionIndices(fullNameMap map[string]*models.Function) {
	// Skip if already indexed for this function map
	if d.indexedFunctions != nil && len(d.indexedFunctions) == len(fullNameMap) {
		// Quick check if it's the same map
		for k, v := range fullNameMap {
			if existing, exists := d.indexedFunctions[k]; !exists || existing != v {
				break // Different map, need to rebuild
			}
			return // Same map, indices are still valid
		}
	}

	if d.verbose {
		d.logger.Debug("Building function lookup indices", "total_functions", len(fullNameMap))
	}

	d.functionNameIndex = make(map[string][]*models.Function)
	d.functionSuffixIndex = make(map[string][]*models.Function)
	d.indexedFunctions = make(map[string]*models.Function)

	// Build indices for fast lookups
	for k, fn := range fullNameMap {
		d.indexedFunctions[k] = fn

		// Index by function name
		d.functionNameIndex[fn.Name] = append(d.functionNameIndex[fn.Name], fn)

		// Index by suffixes (for partial matching)
		name := fn.Name
		for i := 1; i <= len(name) && i <= 10; i++ { // Limit suffix length to avoid excessive memory
			suffix := name[len(name)-i:]
			d.functionSuffixIndex[suffix] = append(d.functionSuffixIndex[suffix], fn)
		}
	}

	if d.verbose {
		d.logger.Debug("Function lookup indices built", "name_entries", len(d.functionNameIndex), "suffix_entries", len(d.functionSuffixIndex))
	}
}

// findBestUserFunctionMatch finds the best matching user function for a given name using optimized indices
func (d *DataPopulator) findBestUserFunctionMatch(name string, fullNameMap map[string]*models.Function, shortNameMap map[string]*models.Function) *models.Function {
	// First try exact short name match (most common case)
	if fn, exists := shortNameMap[name]; exists {
		if d.verbose {
			d.logger.Debug("Found exact short name match", "name", name, "matched", fn.FullName)
		}
		return fn
	}

	// OPTIMIZATION: Build indices if not already done
	d.buildFunctionIndices(fullNameMap)

	// OPTIMIZATION: Use name index for exact name matches
	if candidates, exists := d.functionNameIndex[name]; exists {
		if len(candidates) == 1 {
			if d.verbose {
				d.logger.Debug("Found single name index match", "name", name, "matched", candidates[0].FullName)
			}
			return candidates[0]
		} else if len(candidates) > 1 {
			if d.verbose {
				var candidateNames []string
				for _, c := range candidates {
					candidateNames = append(candidateNames, c.FullName)
				}
				d.logger.Debug("Multiple name candidates found, returning first", "name", name, "candidates", candidateNames)
			}
			return candidates[0]
		}
	}

	// OPTIMIZATION: Use suffix index for partial matches
	if candidates, exists := d.functionSuffixIndex[name]; exists {
		if len(candidates) == 1 {
			if d.verbose {
				d.logger.Debug("Found single suffix match", "name", name, "matched", candidates[0].FullName)
			}
			return candidates[0]
		} else if len(candidates) > 1 {
			if d.verbose {
				var candidateNames []string
				for _, c := range candidates {
					candidateNames = append(candidateNames, c.FullName)
				}
				d.logger.Debug("Multiple suffix candidates found, returning first", "name", name, "candidates", candidateNames)
			}
			return candidates[0]
		}
	}

	if d.verbose {
		d.logger.Debug("No function match found in indices", "name", name)
	}
	return nil
}
