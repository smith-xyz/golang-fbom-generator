package reflection

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"golang.org/x/tools/go/ssa"
)

// NOTE: Consider refactoring - this detector duplicates analysis done elsewhere.
// Future improvement: consolidate reflection detection into a unified analyzer that
// works directly with SSA instead of re-parsing source files.

// Detector analyzes Go code for reflection usage.
type Detector struct {
	verbose bool
	fset    *token.FileSet
}

// NewDetector creates a new reflection detector.
func NewDetector(verbose bool) *Detector {
	return &Detector{
		verbose: verbose,
		fset:    token.NewFileSet(),
	}
}

// AnalyzeDirectory analyzes all Go files in a directory for reflection usage
func (d *Detector) AnalyzeDirectory(dir string) (map[string]*models.Usage, error) {
	if d.verbose {
		fmt.Fprintf(os.Stderr, "Analyzing reflection usage in directory: %s\n", dir)
	}

	pkgs, err := parser.ParseDir(d.fset, dir, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse directory %s: %w", dir, err)
	}

	usageMap := make(map[string]*models.Usage)

	for pkgName, pkg := range pkgs {
		for fileName, file := range pkg.Files {
			// Check if this file imports reflect
			hasReflectImport := d.hasReflectImport(file)
			if !hasReflectImport {
				continue // Skip files that don't import reflect
			}

			if d.verbose {
				fmt.Fprintf(os.Stderr, "Found reflect import in file: %s\n", fileName)
			}

			// Analyze functions in this file
			d.analyzeFunctions(file, pkgName, fileName, usageMap)
		}
	}

	return usageMap, nil
}

// AnalyzePackage analyzes reflection usage using SSA packages for accurate naming
func (d *Detector) AnalyzePackage(packagePath string, ssaProgram *ssa.Program) (map[string]*models.Usage, error) {
	if d.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] AnalyzePackage called with packagePath: %s\n", packagePath)
		fmt.Fprintf(os.Stderr, "[DEBUG] Analyzing %d SSA packages\n", len(ssaProgram.AllPackages()))
	}

	usageMap := make(map[string]*models.Usage)

	// Get the current module name from go.mod
	moduleName, err := d.getCurrentModuleName()
	if err != nil && d.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] Warning: could not determine module name: %v\n", err)
	}

	// Iterate through all SSA packages
	for _, pkg := range ssaProgram.AllPackages() {
		if pkg == nil {
			continue
		}

		pkgPath := pkg.Pkg.Path()
		if d.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Checking SSA package: %s\n", pkgPath)
		}

		// Skip standard library and runtime packages
		if d.isStandardLibraryPackage(pkgPath) {
			continue
		}

		// Check if this is a local package (part of current project)
		if !d.isLocalPackage(pkgPath, moduleName) {
			continue
		}

		// For local packages, derive directory from package path
		pkgDir := d.getPackageDirectory(pkgPath, moduleName)

		if d.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Analyzing directory: %s for package: %s\n", pkgDir, pkgPath)
		}

		// Analyze this package directory
		pkgUsage, err := d.analyzePackageDirectory(pkgDir, pkgPath)
		if err != nil {
			if d.verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG] Warning: failed to analyze package %s in dir %s: %v\n", pkgPath, pkgDir, err)
			}
			continue
		}

		// Merge results
		for k, v := range pkgUsage {
			usageMap[k] = v
		}
	}

	// If no local packages found or analyzed, fall back to directory-based analysis
	if len(usageMap) == 0 {
		if d.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Fallback: analyzing current directory\n")
		}
		return d.AnalyzeDirectory(".")
	}

	if d.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] Found %d total functions with reflection usage\n", len(usageMap))
		for funcName := range usageMap {
			fmt.Fprintf(os.Stderr, "[DEBUG] Reflection function: %s\n", funcName)
		}
	}

	return usageMap, nil
}

// analyzePackageDirectory analyzes a specific package directory with proper package path
func (d *Detector) analyzePackageDirectory(dir string, packagePath string) (map[string]*models.Usage, error) {
	pkgs, err := parser.ParseDir(d.fset, dir, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse directory %s: %w", dir, err)
	}

	usageMap := make(map[string]*models.Usage)

	for _, pkg := range pkgs {
		for fileName, file := range pkg.Files {
			// Check if this file imports reflect
			hasReflectImport := d.hasReflectImport(file)
			if !hasReflectImport {
				continue // Skip files that don't import reflect
			}

			if d.verbose {
				fmt.Fprintf(os.Stderr, "Found reflect import in file: %s (package: %s)\n", fileName, packagePath)
			}

			// Analyze functions in this file with proper package path
			d.analyzeFunctionsWithPackagePath(file, packagePath, fileName, usageMap)
		}
	}

	return usageMap, nil
}

// analyzeFunctionsWithPackagePath analyzes functions with proper SSA-style package paths
func (d *Detector) analyzeFunctionsWithPackagePath(file *ast.File, packagePath, fileName string, usageMap map[string]*models.Usage) {
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		// Use SSA-style naming: packagePath.functionName
		qualifiedName := d.getSSAStyleFunctionName(funcDecl, packagePath)

		usage := &models.Usage{
			FunctionName: funcName,
			PackageName:  packagePath,
			FilePath:     fileName,
			Position:     d.fset.Position(funcDecl.Pos()),
		}

		// Analyze function body for reflection calls
		d.analyzeReflectionCalls(funcDecl.Body, usage)

		// Calculate risk level based on reflection calls
		usage.ReflectionRisk = d.calculateRiskLevel(usage.ReflectionCalls)

		if usage.UsesReflection {
			usageMap[qualifiedName] = usage
			if d.verbose {
				fmt.Fprintf(os.Stderr, "Found reflection usage in function: %s\n", qualifiedName)
			}
		}

		return true
	})
}

// getSSAStyleFunctionName generates SSA-style qualified names to match buildCompleteFunctionInventory
func (d *Detector) getSSAStyleFunctionName(funcDecl *ast.FuncDecl, packagePath string) string {
	funcName := funcDecl.Name.Name

	// Handle method receivers with SSA-style naming
	if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
		receiverType := d.getReceiverType(funcDecl.Recv.List[0].Type)
		return fmt.Sprintf("(%s).%s", receiverType, funcName)
	}

	// For regular functions, use package path
	return fmt.Sprintf("%s.%s", packagePath, funcName)
}

// hasReflectImport checks if a file imports the reflect package
func (d *Detector) hasReflectImport(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Path.Value == `"reflect"` {
			return true
		}
	}
	return false
}

// analyzeFunctions analyzes all functions in a file for reflection usage
func (d *Detector) analyzeFunctions(file *ast.File, pkgName, fileName string, usageMap map[string]*models.Usage) {
	ast.Inspect(file, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		funcName := funcDecl.Name.Name
		qualifiedName := d.getQualifiedFunctionName(funcDecl, pkgName)

		usage := &models.Usage{
			FunctionName: funcName,
			PackageName:  pkgName,
			FilePath:     fileName,
			Position:     d.fset.Position(funcDecl.Pos()),
		}

		// Analyze function body for reflection calls
		d.analyzeReflectionCalls(funcDecl.Body, usage)

		// Calculate risk level based on reflection calls
		usage.ReflectionRisk = d.calculateRiskLevel(usage.ReflectionCalls)

		if usage.UsesReflection {
			usageMap[qualifiedName] = usage
		}

		return true
	})
}

// getQualifiedFunctionName generates a qualified name for a function
func (d *Detector) getQualifiedFunctionName(funcDecl *ast.FuncDecl, pkgName string) string {
	funcName := funcDecl.Name.Name

	// Handle method receivers
	if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
		receiverType := d.getReceiverType(funcDecl.Recv.List[0].Type)
		return fmt.Sprintf("%s.(%s).%s", pkgName, receiverType, funcName)
	}

	return fmt.Sprintf("%s.%s", pkgName, funcName)
}

// getReceiverType extracts the receiver type name
func (d *Detector) getReceiverType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return "*" + ident.Name
		}
	}
	return "Unknown"
}

// analyzeReflectionCalls scans a function body for calls to reflect package
func (d *Detector) analyzeReflectionCalls(body *ast.BlockStmt, usage *models.Usage) {
	if body == nil {
		return
	}

	ast.Inspect(body, func(node ast.Node) bool {
		callExpr, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		reflectionCall := d.identifyReflectionCall(callExpr)
		if reflectionCall != nil {
			usage.UsesReflection = true
			usage.ReflectionCalls = append(usage.ReflectionCalls, *reflectionCall)

			if d.verbose {
				fmt.Fprintf(os.Stderr, "Found reflection call: %s in %s\n",
					reflectionCall.Method, usage.FunctionName)
			}
		}

		return true
	})
}

// identifyReflectionCall checks if a call expression is a reflect package call
func (d *Detector) identifyReflectionCall(callExpr *ast.CallExpr) *models.ReflectionCall {
	var method string

	switch fun := callExpr.Fun.(type) {
	case *ast.SelectorExpr:
		// reflect.Method() calls
		if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "reflect" {
			method = "reflect." + fun.Sel.Name
		}
		// value.Method() calls on reflect.Value or reflect.Type
		if d.isReflectValue(fun.X) {
			// Use "Value." for backward compatibility, but this covers both Value and Type
			method = "Value." + fun.Sel.Name
		}
	}

	if method == "" {
		return nil
	}

	return &models.ReflectionCall{
		Method:   method,
		Position: d.fset.Position(callExpr.Pos()),
		Context:  d.getCallContext(callExpr),
	}
}

// isReflectValue attempts to determine if an expression is a reflect.Value or reflect.Type
// This is a heuristic and may not catch all cases
func (d *Detector) isReflectValue(expr ast.Expr) bool {
	// This is a simplified heuristic - a full implementation would need
	// type information to properly identify reflect.Value instances
	switch e := expr.(type) {
	case *ast.Ident:
		// Common variable names that might hold reflect.Value or reflect.Type
		name := strings.ToLower(e.Name)
		return strings.Contains(name, "value") ||
			strings.Contains(name, "val") ||
			strings.Contains(name, "typ") ||
			strings.Contains(name, "type") ||
			strings.Contains(name, "fn") ||
			strings.Contains(name, "func") ||
			strings.Contains(name, "method") ||
			strings.Contains(name, "field")
	case *ast.CallExpr:
		// Handle chained calls like reflect.ValueOf(x).Method()
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "reflect" {
				// This is a reflect.Something() call, which returns a reflect Value/Type
				return sel.Sel.Name == "ValueOf" || sel.Sel.Name == "TypeOf"
			}
		}
	}
	return false
}

// getCallContext extracts surrounding code context for a function call
func (d *Detector) getCallContext(callExpr *ast.CallExpr) string {
	// This is a simplified implementation
	// A full implementation might extract more meaningful context
	pos := d.fset.Position(callExpr.Pos())
	return fmt.Sprintf("Line %d", pos.Line)
}

// calculateRiskLevel determines the security risk level based on reflection calls
func (d *Detector) calculateRiskLevel(calls []models.ReflectionCall) models.RiskLevel {
	if len(calls) == 0 {
		return models.RiskNone
	}

	maxRisk := models.RiskLow

	for _, call := range calls {
		risk := d.getMethodRisk(call.Method)
		if risk > maxRisk {
			maxRisk = risk
		}
	}

	return maxRisk
}

// getMethodRisk returns the risk level for specific reflection methods
func (d *Detector) getMethodRisk(method string) models.RiskLevel {
	// Check against global high risk method patterns
	for _, risky := range highRiskMethods {
		if strings.Contains(method, risky) {
			return models.RiskHigh
		}
	}

	// Check against global medium risk method patterns
	for _, medium := range mediumRiskMethods {
		if strings.Contains(method, medium) {
			return models.RiskMedium
		}
	}

	return models.RiskLow
}

// GetSummary returns a summary of reflection usage across all analyzed functions
func GetSummary(usageMap map[string]*models.Usage) map[models.RiskLevel]int {
	summary := make(map[models.RiskLevel]int)

	for _, usage := range usageMap {
		summary[usage.ReflectionRisk]++
	}

	return summary
}

// getCurrentModuleName reads the module name from go.mod file
func (d *Detector) getCurrentModuleName() (string, error) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return "", fmt.Errorf("failed to read go.mod: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("module declaration not found in go.mod")
}

// isStandardLibraryPackage checks if a package is part of Go standard library
func (d *Detector) isStandardLibraryPackage(pkgPath string) bool {
	// Standard library packages don't contain dots (domain names)
	// Examples: fmt, os, net/http, crypto/rand
	if strings.Contains(pkgPath, ".") {
		return false // External packages like github.com/user/repo
	}

	// Special cases for internal/build packages
	if strings.Contains(pkgPath, "internal/") ||
		strings.Contains(pkgPath, "runtime") ||
		strings.Contains(pkgPath, "vendor/") {
		return true
	}

	// golang.org/x/ packages are extended standard library
	if strings.HasPrefix(pkgPath, "golang.org/x/") {
		return true
	}

	// Standard library packages: no dots and not main
	// Can have slashes (like net/http, crypto/rand)
	return pkgPath != "main" && !strings.Contains(pkgPath, "-")
}

// isLocalPackage determines if a package belongs to the current project
func (d *Detector) isLocalPackage(pkgPath, moduleName string) bool {
	if moduleName == "" {
		// Fallback: assume packages without domain names are local
		return pkgPath == "main" || !strings.Contains(pkgPath, ".")
	}

	// Package is local if it starts with the module name
	return pkgPath == moduleName || strings.HasPrefix(pkgPath, moduleName+"/")
}

// getPackageDirectory maps a package path to its relative directory
func (d *Detector) getPackageDirectory(pkgPath, moduleName string) string {
	if moduleName == "" || pkgPath == moduleName {
		return "."
	}

	// Remove module prefix to get relative path
	if strings.HasPrefix(pkgPath, moduleName+"/") {
		return strings.TrimPrefix(pkgPath, moduleName+"/")
	}

	return "."
}
