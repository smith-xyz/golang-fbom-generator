package function

import (
	"go/types"
	"log/slog"
	"runtime"
	"sync"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/shared"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/utils"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Analyzer handles function-level analysis and inventory building
type Analyzer struct {
	logger          *slog.Logger
	verbose         bool
	config          *Config
	rules           *rules.Rules
	sharedAnalyzer  *shared.SharedAnalyzer
	instrumentation *utils.Instrumentation
}

// Config holds configuration for function analysis
type Config struct {
	Verbose                 bool
	IncludeUnreachableFuncs bool // Whether to include unreachable functions in inventory
}

// NewAnalyzer creates a new function analyzer
func NewAnalyzer(logger *slog.Logger, config *Config, rules *rules.Rules, sharedAnalyzer *shared.SharedAnalyzer) *Analyzer {
	if config == nil {
		config = &Config{
			Verbose:                 false,
			IncludeUnreachableFuncs: true,
		}
	}
	return &Analyzer{
		logger:          logger,
		verbose:         config.Verbose,
		config:          config,
		rules:           rules,
		sharedAnalyzer:  sharedAnalyzer,
		instrumentation: utils.NewInstrumentation(logger, config.Verbose),
	}
}

// BuildUserFunctionInventory builds inventory of user-defined functions only
func (a *Analyzer) BuildUserFunctionInventory(reflectionUsage map[string]*models.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program) []models.Function {
	tracker := a.instrumentation.NewPhaseTracker("Function Analysis")
	functionMap := make(map[string]models.Function)

	if callGraph != nil {
		tracker.StartPhase("Call Graph Analysis")

		// Performance optimization: Pre-filter user-defined functions
		var userDefinedFunctions []*ssa.Function
		_ = a.instrumentation.TimedOperation("Filtering user-defined functions", func() error {
			userDefinedFunctions = a.filterUserDefinedFunctions(callGraph)
			totalNodes := len(callGraph.Nodes)
			userNodes := len(userDefinedFunctions)
			a.logger.Debug("Filtered functions", "total_nodes", totalNodes, "user_defined_nodes", userNodes)
			return nil
		})

		// Process functions in parallel for better performance
		_ = a.instrumentation.TimedOperation("Processing functions in parallel", func() error {
			a.processFunctionsInParallel(userDefinedFunctions, functionMap, callGraph, reflectionUsage)
			return nil
		})
	}

	// Process unreachable functions from SSA program (user-defined packages only)
	if ssaProgram != nil {
		tracker.StartPhase("SSA Analysis (Unreachable Functions)")

		beforeCount := len(functionMap)
		_ = a.instrumentation.TimedOperation("Processing unreachable functions", func() error {
			a.processUnreachableFunctionsInParallel(ssaProgram, functionMap, callGraph, reflectionUsage)
			afterCount := len(functionMap)
			ssaFunctions := afterCount - beforeCount
			a.logger.Debug("SSA analysis completed", "additional_functions", ssaFunctions)
			return nil
		})
	}

	// Populate call relationships
	tracker.StartPhase("Call Relationship Analysis")
	_ = a.instrumentation.TimedOperation("Populating call relationships", func() error {
		a.PopulateCallRelationships(functionMap, callGraph)
		return nil
	})

	// Convert map to slice
	functions := make([]models.Function, 0, len(functionMap))
	for _, function := range functionMap {
		functions = append(functions, function)
	}

	tracker.Complete(len(functions))
	return functions
}

// filterUserDefinedFunctions creates a pre-filtered slice of user-defined functions from the call graph
// This optimization avoids calling IsUserDefinedFunction for every node in large call graphs
func (a *Analyzer) filterUserDefinedFunctions(callGraph *callgraph.Graph) []*ssa.Function {
	// Always return a valid slice, never nil
	userFunctions := make([]*ssa.Function, 0)

	if callGraph == nil {
		return userFunctions
	}

	totalNodes := len(callGraph.Nodes)
	processedNodes := 0

	for fn := range callGraph.Nodes {
		processedNodes++
		if fn == nil {
			continue
		}

		// Use classifier to determine if this is a user-defined function
		if a.rules.Classifier.IsUserDefinedFunction(fn) {
			userFunctions = append(userFunctions, fn)
		} else if a.verbose {
			pkg := "unknown"
			if fn.Pkg != nil && fn.Pkg.Pkg != nil {
				pkg = fn.Pkg.Pkg.Path()
			}
			remaining := totalNodes - processedNodes
			a.logger.Debug("Skipping non-user function", "function", fn.Name(), "package", pkg, "processed", processedNodes, "remaining", remaining)
		}
	}

	if a.verbose {
		a.logger.Debug("Filtered user-defined functions", "user_functions", len(userFunctions), "total_functions", len(callGraph.Nodes))
	}

	return userFunctions
}

// processFunctionsInParallel processes user-defined functions in parallel for better performance
func (a *Analyzer) processFunctionsInParallel(userDefinedFunctions []*ssa.Function, functionMap map[string]models.Function, callGraph *callgraph.Graph, reflectionUsage map[string]*models.Usage) {
	// MAJOR OPTIMIZATION: Pre-calculate ALL distances and reachability in one pass instead of per-function
	var allDistances map[string]int
	var reachabilityCache map[string]bool
	if a.sharedAnalyzer != nil && callGraph != nil {
		if a.verbose {
			a.logger.Debug("Pre-calculating all function distances from entry points")
		}
		allDistances = a.sharedAnalyzer.CalculateAllDistancesFromEntryPoints(callGraph)

		// Pre-calculate reachability to avoid redundant calls
		reachabilityCache = make(map[string]bool)
		for _, fn := range userDefinedFunctions {
			functionID := rules.GenerateFunctionID(fn)
			reachabilityCache[functionID] = rules.IsFunctionReachable(fn, callGraph)
		}

		if a.verbose {
			a.logger.Debug("Pre-calculated function metadata", "distances", len(allDistances), "reachability", len(reachabilityCache))
		}
	}

	// Determine number of workers based on available CPUs
	numWorkers := runtime.NumCPU()
	if numWorkers > len(userDefinedFunctions) {
		numWorkers = len(userDefinedFunctions)
	}

	// Channel for distributing work
	functionChan := make(chan *ssa.Function, len(userDefinedFunctions))

	// Channel for collecting results
	resultChan := make(chan models.Function, len(userDefinedFunctions))

	// WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup

	progress := a.instrumentation.NewProgressTracker("Processing functions", len(userDefinedFunctions))

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			if a.verbose {
				a.logger.Debug("Worker started", "worker_id", workerID)
			}

			processed := 0
			for fn := range functionChan {
				if fn == nil {
					continue
				}

				processed++

				if a.verbose {
					a.logger.Debug("Processing function", "worker_id", workerID, "function", fn.Name(), "package", rules.GetPackageName(fn), "progress", processed)
				}

				// Build function using rules package utilities
				functionID := rules.GenerateFunctionID(fn)
				packagePath := rules.GetPackageName(fn)

				// OPTIMIZATION: Use pre-calculated reachability
				var isReachable bool
				if reachabilityCache != nil {
					isReachable = reachabilityCache[functionID]
				} else {
					// Fallback to individual calculation if pre-calculation failed
					isReachable = rules.IsFunctionReachable(fn, callGraph)
				}

				// OPTIMIZATION: Use pre-calculated distance instead of expensive per-function calculation
				var distanceFromEntry int = -1
				if allDistances != nil {
					if distance, found := allDistances[functionID]; found {
						distanceFromEntry = distance
					}
				} else {
					// Fallback to individual calculation if pre-calculation failed
					distanceFromEntry = a.CalculateDistanceFromEntry(fn, callGraph)
				}

				function := models.Function{
					SPDXId:       rules.GenerateSPDXId("Function", fn),
					Name:         fn.Name(),
					FullName:     functionID,
					Package:      packagePath,
					FilePath:     rules.ExtractFilePath(fn),
					StartLine:    rules.ExtractStartLine(fn),
					EndLine:      rules.ExtractEndLine(fn),
					Signature:    rules.ExtractFunctionSignature(fn),
					Visibility:   rules.InferVisibility(fn),
					FunctionType: rules.InferFunctionType(fn),
					IsExported:   rules.IsFunctionExported(fn),
					Parameters:   rules.ExtractParameters(fn),
					ReturnTypes:  rules.ExtractReturnTypes(fn),
					UsageInfo: models.UsageInfo{
						IsReachable:         isReachable,
						ReachabilityType:    rules.DetermineReachabilityType(fn, callGraph, a.rules.Classifier.IsEntryPoint),
						DistanceFromEntry:   distanceFromEntry,
						InCriticalPath:      false,
						HasReflectionAccess: rules.HasReflectionRisk(reflectionUsage[functionID]),
						IsEntryPoint:        a.rules.Classifier.IsEntryPoint(fn),
						CVEReferences:       []string{},
						Calls:               []string{},
						CalledBy:            []string{},
					},
				}

				resultChan <- function

				if a.verbose && processed%50 == 0 {
					a.logger.Debug("Worker batch completed", "worker_id", workerID, "processed", processed)
				}
			}

			if a.verbose {
				a.logger.Debug("Worker completed", "worker_id", workerID, "total_processed", processed)
			}
		}(i)
	}

	// Send all functions to workers
	go func() {
		for _, fn := range userDefinedFunctions {
			functionChan <- fn
		}
		close(functionChan)
	}()

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect all results back into the function map with progress tracking
	for function := range resultChan {
		functionMap[function.FullName] = function
		progress.Update(1)
	}

	progress.Complete()
}

// processUnreachableFunctionsInParallel processes unreachable functions from SSA program in parallel
func (a *Analyzer) processUnreachableFunctionsInParallel(ssaProgram *ssa.Program, functionMap map[string]models.Function, callGraph *callgraph.Graph, reflectionUsage map[string]*models.Usage) {
	if ssaProgram == nil {
		return
	}

	a.logger.Debug("Processing unreachable functions from SSA program")

	// OPTIMIZATION: Pre-filter user-defined packages to avoid processing stdlib/dependencies
	allPackages := ssaProgram.AllPackages()
	userPackages := make([]*ssa.Package, 0)

	for _, pkg := range allPackages {
		if pkg.Pkg == nil {
			continue
		}

		packagePath := pkg.Pkg.Path()
		if a.rules.Classifier.IsStandardLibraryPackage(packagePath) || a.rules.Classifier.IsDependencyPackage(packagePath) {
			continue
		}

		userPackages = append(userPackages, pkg)
	}

	if a.verbose {
		a.logger.Debug("Filtered SSA packages for parallel processing", "total_packages", len(allPackages), "user_packages", len(userPackages))
	}

	if len(userPackages) == 0 {
		return
	}

	// OPTIMIZATION: Pre-extract all functions from packages for better load balancing
	var allFunctions []*ssa.Function
	var allTypes []*ssa.Type
	packageMap := make(map[*ssa.Function]string) // Track which package each function belongs to

	for _, pkg := range userPackages {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		packagePath := pkg.Pkg.Path()

		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				allFunctions = append(allFunctions, fn)
				packageMap[fn] = packagePath
			}
			if typ, ok := member.(*ssa.Type); ok {
				allTypes = append(allTypes, typ)
			}
		}
	}

	if a.verbose {
		a.logger.Debug("Pre-extracted functions for load balancing", "packages", len(userPackages), "functions", len(allFunctions), "types", len(allTypes))
	}

	if len(allFunctions) == 0 && len(allTypes) == 0 {
		return
	}

	// Determine number of workers based on available CPUs and total functions
	numWorkers := runtime.NumCPU()
	totalWork := len(allFunctions) + len(allTypes)
	if numWorkers > totalWork {
		numWorkers = totalWork
	}

	// Channel for distributing individual functions (better load balancing)
	functionChan := make(chan *ssa.Function, len(allFunctions))
	typeChan := make(chan *ssa.Type, len(allTypes))

	// Channel for collecting results
	resultChan := make(chan models.Function, totalWork*2) // Conservative estimate

	// WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup

	// Mutex to protect functionMap access (check for existing functions)
	var mapMutex sync.RWMutex

	ssaProgress := a.instrumentation.NewProgressTracker("Processing SSA functions", totalWork)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			if a.verbose {
				a.logger.Debug("SSA worker started", "worker_id", workerID)
			}

			processed := 0
			functionsFound := 0

			// Process functions from function channel
			functionsDone := false
			typesDone := false

			for !functionsDone || !typesDone {
				select {
				case fn, ok := <-functionChan:
					if !ok {
						functionsDone = true
						continue
					}

					processed++
					packagePath := packageMap[fn]
					functionID := rules.GenerateFunctionID(fn)

					if a.verbose && processed%50 == 0 {
						a.logger.Debug("Processing SSA function", "worker_id", workerID, "function", fn.Name(), "package", packagePath, "progress", processed)
					}

					// This is an unreachable user-defined function
					function := models.Function{
						SPDXId:       rules.GenerateSPDXId("Function", fn),
						Name:         fn.Name(),
						FullName:     functionID,
						Package:      packagePath,
						FilePath:     rules.ExtractFilePath(fn),
						StartLine:    rules.ExtractStartLine(fn),
						EndLine:      rules.ExtractEndLine(fn),
						Signature:    rules.ExtractFunctionSignature(fn),
						Visibility:   rules.InferVisibility(fn),
						FunctionType: rules.InferFunctionType(fn),
						IsExported:   rules.IsFunctionExported(fn),
						Parameters:   rules.ExtractParameters(fn),
						ReturnTypes:  rules.ExtractReturnTypes(fn),
						UsageInfo: models.UsageInfo{
							IsReachable:         false, // Unreachable since not in call graph
							ReachabilityType:    "unreachable",
							DistanceFromEntry:   -1, // Unreachable
							InCriticalPath:      false,
							HasReflectionAccess: rules.HasReflectionRisk(reflectionUsage[functionID]),
							IsEntryPoint:        false,
							CVEReferences:       []string{},
							Calls:               []string{},
							CalledBy:            []string{},
						},
					}

					resultChan <- function
					functionsFound++
					ssaProgress.Update(1)

				case typ, ok := <-typeChan:
					if !ok {
						typesDone = true
						continue
					}

					processed++

					// Find the package path for this type
					var packagePath string
					for _, pkg := range userPackages {
						if pkg != nil && pkg.Pkg != nil {
							for _, member := range pkg.Members {
								if member == typ {
									packagePath = pkg.Pkg.Path()
									break
								}
							}
							if packagePath != "" {
								break
							}
						}
					}

					if a.verbose && processed%50 == 0 {
						a.logger.Debug("Processing SSA type", "worker_id", workerID, "type", typ.String(), "package", packagePath, "progress", processed)
					}

					// Create a temporary map for this worker's methods
					tempMethodMap := make(map[string]models.Function)
					a.processMethods(typ, packagePath, tempMethodMap, callGraph, ssaProgram, reflectionUsage)

					// Send all methods found to the result channel
					for _, method := range tempMethodMap {
						resultChan <- method
						functionsFound++
					}
					ssaProgress.Update(1)
				}
			}
			if a.verbose {
				a.logger.Debug("SSA worker completed", "worker_id", workerID, "total_processed", processed, "total_functions_found", functionsFound)
			}
		}(i)
	}

	// Send all functions and types to workers for better load balancing
	go func() {
		// Send all functions
		for _, fn := range allFunctions {
			functionChan <- fn
		}
		close(functionChan)

		// Send all types
		for _, typ := range allTypes {
			typeChan <- typ
		}
		close(typeChan)
	}()

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect all results back into the function map with deduplication
	processedCount := 0
	duplicateCount := 0
	for function := range resultChan {
		// Thread-safe addition to function map with deduplication
		mapMutex.Lock()
		if _, exists := functionMap[function.FullName]; !exists {
			functionMap[function.FullName] = function
			processedCount++
		} else {
			duplicateCount++
		}
		mapMutex.Unlock()
	}

	ssaProgress.Complete()
}

// processMethods processes methods attached to types
func (a *Analyzer) processMethods(typ *ssa.Type, packagePath string, functionMap map[string]models.Function, callGraph *callgraph.Graph, ssaProgram *ssa.Program, reflectionUsage map[string]*models.Usage) {
	if typ == nil || typ.Type() == nil {
		return
	}

	// Get the method set for this type (both value and pointer receivers)
	methodSet := ssaProgram.MethodSets.MethodSet(typ.Type())
	if methodSet != nil {
		for i := 0; i < methodSet.Len(); i++ {
			selection := methodSet.At(i)

			// Get the method function from the SSA program
			methodFunc := ssaProgram.MethodValue(selection)
			if methodFunc == nil {
				continue
			}

			// Only process user-defined methods (skip if from other packages)
			if !a.rules.Classifier.IsUserDefinedFunction(methodFunc) {
				continue
			}

			functionID := rules.GenerateFunctionID(methodFunc)

			// Skip if we already processed this method from call graph
			if _, exists := functionMap[functionID]; exists {
				continue
			}

			// Check if this method is reachable via the call graph
			isReachable := rules.IsFunctionReachable(methodFunc, callGraph)

			function := models.Function{
				SPDXId:       rules.GenerateSPDXId("Function", methodFunc),
				Name:         methodFunc.Name(),
				FullName:     functionID,
				Package:      packagePath,
				FilePath:     rules.ExtractFilePath(methodFunc),
				StartLine:    rules.ExtractStartLine(methodFunc),
				EndLine:      rules.ExtractEndLine(methodFunc),
				Signature:    rules.ExtractFunctionSignature(methodFunc),
				Visibility:   rules.InferVisibility(methodFunc),
				FunctionType: rules.InferFunctionType(methodFunc),
				IsExported:   rules.IsFunctionExported(methodFunc),
				Parameters:   rules.ExtractParameters(methodFunc),
				ReturnTypes:  rules.ExtractReturnTypes(methodFunc),
				UsageInfo: models.UsageInfo{
					IsReachable:         isReachable,
					ReachabilityType:    rules.DetermineReachabilityType(methodFunc, callGraph, a.rules.Classifier.IsEntryPoint),
					DistanceFromEntry:   a.CalculateDistanceFromEntry(methodFunc, callGraph),
					InCriticalPath:      false,
					HasReflectionAccess: rules.HasReflectionRisk(reflectionUsage[functionID]),
					IsEntryPoint:        a.rules.Classifier.IsEntryPoint(methodFunc),
					CVEReferences:       []string{},
					Calls:               []string{},
					CalledBy:            []string{},
				},
			}

			functionMap[functionID] = function
		}
	}

	// Also check pointer type methods if this is not already a pointer type
	if !rules.IsPointer(typ.Type()) {
		ptrType := types.NewPointer(typ.Type())
		ptrMethodSet := ssaProgram.MethodSets.MethodSet(ptrType)
		if ptrMethodSet != nil {
			for i := 0; i < ptrMethodSet.Len(); i++ {
				selection := ptrMethodSet.At(i)

				methodFunc := ssaProgram.MethodValue(selection)
				if methodFunc == nil {
					continue
				}

				if !a.rules.Classifier.IsUserDefinedFunction(methodFunc) {
					continue
				}

				functionID := rules.GenerateFunctionID(methodFunc)

				if _, exists := functionMap[functionID]; exists {
					continue
				}

				isReachable := rules.IsFunctionReachable(methodFunc, callGraph)

				function := models.Function{
					SPDXId:       rules.GenerateSPDXId("Function", methodFunc),
					Name:         methodFunc.Name(),
					FullName:     functionID,
					Package:      packagePath,
					FilePath:     rules.ExtractFilePath(methodFunc),
					StartLine:    rules.ExtractStartLine(methodFunc),
					EndLine:      rules.ExtractEndLine(methodFunc),
					Signature:    rules.ExtractFunctionSignature(methodFunc),
					Visibility:   rules.InferVisibility(methodFunc),
					FunctionType: rules.InferFunctionType(methodFunc),
					IsExported:   rules.IsFunctionExported(methodFunc),
					Parameters:   rules.ExtractParameters(methodFunc),
					ReturnTypes:  rules.ExtractReturnTypes(methodFunc),
					UsageInfo: models.UsageInfo{
						IsReachable:         isReachable,
						ReachabilityType:    rules.DetermineReachabilityType(methodFunc, callGraph, a.rules.Classifier.IsEntryPoint),
						DistanceFromEntry:   a.CalculateDistanceFromEntry(methodFunc, callGraph),
						InCriticalPath:      false,
						HasReflectionAccess: rules.HasReflectionRisk(reflectionUsage[functionID]),
						IsEntryPoint:        a.rules.Classifier.IsEntryPoint(methodFunc),
						CVEReferences:       []string{},
						Calls:               []string{},
						CalledBy:            []string{},
					},
				}

				functionMap[functionID] = function
			}
		}
	}
}

// CalculateDistanceFromEntry calculates the distance of a function from entry points
func (a *Analyzer) CalculateDistanceFromEntry(fn *ssa.Function, callGraph *callgraph.Graph) int {
	// Delegate to the shared analyzer which has the authoritative implementation
	if a.sharedAnalyzer != nil {
		return a.sharedAnalyzer.CalculateDistanceFromEntry(fn, callGraph)
	}

	// Fallback if no shared analyzer available
	if fn == nil {
		return -1
	}

	// Basic fallback: entry points are distance 0, others are distance 1 if reachable
	if a.rules.Classifier.IsEntryPoint(fn) {
		return 0
	}

	if callGraph != nil {
		if node := callGraph.Nodes[fn]; node != nil && len(node.In) > 0 {
			return 1 // Safe fallback
		}
	}

	return -1 // Not reachable
}

// ProcessMethods processes all methods of a given type and adds them to the function map
func (a *Analyzer) ProcessMethods(typ *ssa.Type, packagePath string, functionMap map[string]models.Function, callGraph *callgraph.Graph, ssaProgram *ssa.Program) {
	// Simplified implementation - in the full version this would be more complex
	a.logger.Debug("ProcessMethods called", "type", typ.String(), "package", packagePath)

	if typ == nil || typ.Type() == nil {
		return
	}

	// Get the method set for this type (both value and pointer receivers)
	methodSet := ssaProgram.MethodSets.MethodSet(typ.Type())
	if methodSet != nil {
		for i := 0; i < methodSet.Len(); i++ {
			selection := methodSet.At(i)

			// Get the method function from the SSA program
			methodFunc := ssaProgram.MethodValue(selection)
			if methodFunc == nil {
				continue
			}

			// Only process user-defined methods (skip if from other packages)
			if !a.rules.Classifier.IsUserDefinedFunction(methodFunc) {
				continue
			}

			functionID := rules.GenerateFunctionID(methodFunc)

			// Skip if we already processed this method from call graph
			if _, exists := functionMap[functionID]; exists {
				continue
			}

			// Check if this method is reachable via the call graph
			isReachable := rules.IsFunctionReachable(methodFunc, callGraph)

			function := models.Function{
				SPDXId:       rules.GenerateSPDXId("Function", methodFunc),
				Name:         methodFunc.Name(),
				FullName:     functionID,
				Package:      packagePath,
				FilePath:     rules.ExtractFilePath(methodFunc),
				StartLine:    rules.ExtractStartLine(methodFunc),
				EndLine:      rules.ExtractEndLine(methodFunc),
				Signature:    rules.ExtractFunctionSignature(methodFunc),
				Visibility:   rules.InferVisibility(methodFunc),
				FunctionType: rules.InferFunctionType(methodFunc),
				IsExported:   rules.IsFunctionExported(methodFunc),
				Parameters:   rules.ExtractParameters(methodFunc),
				ReturnTypes:  rules.ExtractReturnTypes(methodFunc),
				UsageInfo: models.UsageInfo{
					IsReachable:         isReachable,
					ReachabilityType:    rules.DetermineReachabilityType(methodFunc, callGraph, a.rules.Classifier.IsEntryPoint),
					DistanceFromEntry:   a.CalculateDistanceFromEntry(methodFunc, callGraph),
					InCriticalPath:      false,
					HasReflectionAccess: false,
					IsEntryPoint:        a.rules.Classifier.IsEntryPoint(methodFunc),
					CVEReferences:       []string{},
					Calls:               []string{},
					CalledBy:            []string{},
				},
			}

			functionMap[functionID] = function
		}
	}

	// Also check pointer type methods if this is not already a pointer type
	if !rules.IsPointer(typ.Type()) {
		ptrType := types.NewPointer(typ.Type())
		ptrMethodSet := ssaProgram.MethodSets.MethodSet(ptrType)
		if ptrMethodSet != nil {
			for i := 0; i < ptrMethodSet.Len(); i++ {
				selection := ptrMethodSet.At(i)

				// Get the method function from the SSA program
				methodFunc := ssaProgram.MethodValue(selection)
				if methodFunc == nil {
					continue
				}

				// Only process user-defined methods
				if !a.rules.Classifier.IsUserDefinedFunction(methodFunc) {
					continue
				}

				functionID := rules.GenerateFunctionID(methodFunc)

				// Skip if we already processed this method
				if _, exists := functionMap[functionID]; exists {
					continue
				}

				// Check if this method is reachable via the call graph
				isReachable := rules.IsFunctionReachable(methodFunc, callGraph)

				function := models.Function{
					SPDXId:       rules.GenerateSPDXId("Function", methodFunc),
					Name:         methodFunc.Name(),
					FullName:     functionID,
					Package:      packagePath,
					FilePath:     rules.ExtractFilePath(methodFunc),
					StartLine:    rules.ExtractStartLine(methodFunc),
					EndLine:      rules.ExtractEndLine(methodFunc),
					Signature:    rules.ExtractFunctionSignature(methodFunc),
					Visibility:   rules.InferVisibility(methodFunc),
					FunctionType: rules.InferFunctionType(methodFunc),
					IsExported:   rules.IsFunctionExported(methodFunc),
					Parameters:   rules.ExtractParameters(methodFunc),
					ReturnTypes:  rules.ExtractReturnTypes(methodFunc),
					UsageInfo: models.UsageInfo{
						IsReachable:         isReachable,
						ReachabilityType:    rules.DetermineReachabilityType(methodFunc, callGraph, a.rules.Classifier.IsEntryPoint),
						DistanceFromEntry:   a.CalculateDistanceFromEntry(methodFunc, callGraph),
						InCriticalPath:      false,
						HasReflectionAccess: false,
						IsEntryPoint:        a.rules.Classifier.IsEntryPoint(methodFunc),
						CVEReferences:       []string{},
						Calls:               []string{}, // Initialize as empty slice
						CalledBy:            []string{}, // Initialize as empty slice
					},
				}

				functionMap[functionID] = function
			}
		}
	}
}

// PopulateCallRelationships populates call relationships between functions
func (a *Analyzer) PopulateCallRelationships(functionMap map[string]models.Function, callGraph *callgraph.Graph) {
	if callGraph == nil {
		return
	}

	for callerFn, node := range callGraph.Nodes {
		if callerFn == nil || node == nil {
			continue
		}

		callerID := rules.GenerateFunctionID(callerFn)
		caller, exists := functionMap[callerID]
		if !exists {
			continue
		}

		// Process outgoing edges (calls made by this function)
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			calleeFn := edge.Callee.Func
			calleeID := rules.GenerateFunctionID(calleeFn)

			// Add to caller's Calls list
			caller.UsageInfo.Calls = append(caller.UsageInfo.Calls, calleeID)

			// Add external calls if callee is not user-defined
			if !a.rules.Classifier.IsUserDefinedFunction(calleeFn) {
				packagePath := ""
				if calleeFn.Pkg != nil && calleeFn.Pkg.Pkg != nil {
					packagePath = calleeFn.Pkg.Pkg.Path()
				}

				if a.rules.Classifier.IsStandardLibraryPackage(packagePath) {
					// Standard library call
					stdlibCall := rules.FormatFunctionCall(calleeFn)
					caller.UsageInfo.StdlibCalls = append(caller.UsageInfo.StdlibCalls, stdlibCall)
				} else if a.rules.Classifier.IsDependencyPackage(packagePath) {
					// External dependency call
					externalCall := rules.FormatFunctionCall(calleeFn)
					caller.UsageInfo.ExternalCalls = append(caller.UsageInfo.ExternalCalls, externalCall)
				}
			}

			// Update callee's CalledBy list if it exists in our function map
			if callee, calleeExists := functionMap[calleeID]; calleeExists {
				callee.UsageInfo.CalledBy = append(callee.UsageInfo.CalledBy, callerID)
				functionMap[calleeID] = callee
			}
		}

		functionMap[callerID] = caller
	}
}
