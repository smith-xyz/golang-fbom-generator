package function

import (
	"go/types"
	"log/slog"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/shared"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Analyzer handles function-level analysis and inventory building
type Analyzer struct {
	logger         *slog.Logger
	verbose        bool
	config         *Config
	rules          *rules.Rules
	sharedAnalyzer *shared.SharedAnalyzer
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
		logger:         logger,
		verbose:        config.Verbose,
		config:         config,
		rules:          rules,
		sharedAnalyzer: sharedAnalyzer,
	}
}

// BuildUserFunctionInventory builds inventory of user-defined functions only
func (a *Analyzer) BuildUserFunctionInventory(reflectionUsage map[string]*models.Usage, callGraph *callgraph.Graph, ssaProgram *ssa.Program) []models.Function {
	a.logger.Debug("buildUserFunctionInventory called")
	functionMap := make(map[string]models.Function)

	if callGraph != nil {
		totalNodes := len(callGraph.Nodes)
		processedNodes := 0
		a.logger.Debug("Processing call graph functions", "total_nodes", totalNodes)

		for fn := range callGraph.Nodes {
			processedNodes++
			if fn == nil {
				continue
			}

			// Use classifier to determine if this is a user-defined function
			if !a.rules.Classifier.IsUserDefinedFunction(fn) {
				if a.verbose {
					pkg := "unknown"
					if fn.Pkg != nil && fn.Pkg.Pkg != nil {
						pkg = fn.Pkg.Pkg.Path()
					}
					remaining := totalNodes - processedNodes
					a.logger.Debug("Skipping non-user function", "function", fn.Name(), "package", pkg, "processed", processedNodes, "remaining", remaining)
				}
				continue
			}

			// Build function using rules package utilities
			functionID := rules.GenerateFunctionID(fn)
			isReachable := rules.IsFunctionReachable(fn, callGraph)
			packagePath := rules.GetPackageName(fn)

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
					DistanceFromEntry:   a.CalculateDistanceFromEntry(fn, callGraph),
					InCriticalPath:      false,
					HasReflectionAccess: rules.HasReflectionRisk(reflectionUsage[functionID]),
					IsEntryPoint:        a.rules.Classifier.IsEntryPoint(fn),
					CVEReferences:       []string{},
					Calls:               []string{},
					CalledBy:            []string{},
				},
			}

			functionMap[functionID] = function
		}
	}

	// Process unreachable functions from SSA program (user-defined packages only)
	if ssaProgram != nil {
		a.logger.Debug("Processing unreachable functions from SSA program")
		for _, pkg := range ssaProgram.AllPackages() {
			if pkg.Pkg == nil {
				continue
			}

			packagePath := pkg.Pkg.Path()
			if a.rules.Classifier.IsStandardLibraryPackage(packagePath) || a.rules.Classifier.IsDependencyPackage(packagePath) {
				continue
			}

			for _, member := range pkg.Members {
				if fn, ok := member.(*ssa.Function); ok {
					functionID := rules.GenerateFunctionID(fn)

					// Skip if we already processed this function
					if _, exists := functionMap[functionID]; exists {
						continue
					}

					// This is an unreachable user-defined function
					packagePath := rules.GetPackageName(fn)
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

					functionMap[functionID] = function
				}

				// Process methods attached to types
				if typ, ok := member.(*ssa.Type); ok {
					a.processMethods(typ, packagePath, functionMap, callGraph, ssaProgram, reflectionUsage)
				}
			}
		}
	}

	// Populate call relationships
	a.PopulateCallRelationships(functionMap, callGraph)

	// Convert map to slice
	functions := make([]models.Function, 0, len(functionMap))
	for _, function := range functionMap {
		functions = append(functions, function)
	}

	a.logger.Debug("Built user function inventory", "count", len(functions))
	return functions
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
