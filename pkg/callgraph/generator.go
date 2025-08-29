package callgraph

import (
	"fmt"
	"go/token"
	"os"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
)

// Generator handles call graph generation for Go packages
type Generator struct {
	packagePath   string
	verbose       bool
	targetPkgOnly bool
	config        *config.Config
	algorithm     string
}

// NewGenerator creates a new call graph generator
func NewGenerator(packagePath string, verbose bool) *Generator {
	cfg, err := config.DefaultConfig()
	if err != nil {
		// Fallback to a basic config if default config fails to load
		cfg = &config.Config{}
	}

	return &Generator{
		packagePath:   packagePath,
		verbose:       verbose,
		targetPkgOnly: false,
		config:        cfg,
		algorithm:     "rta", // Default to RTA for backward compatibility
	}
}

// SetTargetPackageOnly configures the generator to only include the target package
func (g *Generator) SetTargetPackageOnly(targetPkgOnly bool) {
	g.targetPkgOnly = targetPkgOnly
}

// SetAlgorithm sets the call graph algorithm to use
func (g *Generator) SetAlgorithm(algorithm string) error {
	// If empty, default to RTA
	if algorithm == "" {
		algorithm = "rta"
	}

	// Validate algorithm
	validAlgorithms := map[string]bool{
		"rta":    true, // Rapid Type Analysis
		"cha":    true, // Class Hierarchy Analysis
		"static": true, // Static call graph
		"vta":    true, // Variable Type Analysis
	}

	if !validAlgorithms[algorithm] {
		return fmt.Errorf("unsupported call graph algorithm: %s. Supported algorithms: rta, cha, static, vta", algorithm)
	}

	g.algorithm = algorithm
	return nil
}

// GetAlgorithm returns the currently configured call graph algorithm
func (g *Generator) GetAlgorithm() string {
	return g.algorithm
}

// Generate creates a call graph for the specified package path
func (g *Generator) Generate() (*callgraph.Graph, *ssa.Program, error) {
	if g.verbose {
		fmt.Fprintf(os.Stderr, "Loading packages from: %s\n", g.packagePath)
	}

	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax | packages.NeedDeps | packages.NeedImports,
		Fset: token.NewFileSet(),
	}

	if g.verbose {
		fmt.Fprintf(os.Stderr, "Loading packages with dependencies for complete analysis...\n")
	}

	pkgs, err := packages.Load(cfg, g.packagePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load packages: %w", err)
	}

	// Recursively collect all dependencies into a flat map
	allPkgs := make(map[string]*packages.Package)
	var collectDeps func(*packages.Package)
	collectDeps = func(pkg *packages.Package) {
		if allPkgs[pkg.PkgPath] != nil {
			return
		}
		allPkgs[pkg.PkgPath] = pkg
		for _, dep := range pkg.Imports {
			collectDeps(dep)
		}
	}

	for _, pkg := range pkgs {
		collectDeps(pkg)
	}

	pkgs = make([]*packages.Package, 0, len(allPkgs))
	for _, pkg := range allPkgs {
		pkgs = append(pkgs, pkg)
	}

	if g.verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d total packages including dependencies\n", len(pkgs))
	}

	if packages.PrintErrors(pkgs) > 0 {
		return nil, nil, fmt.Errorf("errors encountered during package loading")
	}

	var ssaPackages []*packages.Package
	var prog *ssa.Program
	var ssaPkgs []*ssa.Package

	if g.targetPkgOnly {
		for _, pkg := range pkgs {
			if g.isTargetPackage(pkg.PkgPath) {
				ssaPackages = append(ssaPackages, pkg)
			}
		}
		if g.verbose {
			fmt.Fprintf(os.Stderr, "Target-only mode: using %d target packages from %d total\n", len(ssaPackages), len(pkgs))
		}
		prog, ssaPkgs = ssautil.Packages(ssaPackages, ssa.InstantiateGenerics)
	} else {
		ssaPackages = pkgs
		if g.verbose {
			fmt.Fprintf(os.Stderr, "Using all %d packages for accurate RTA analysis\n", len(ssaPackages))
		}
		prog, ssaPkgs = ssautil.AllPackages(ssaPackages, ssa.InstantiateGenerics)
	}
	prog.Build()

	if g.verbose {
		fmt.Fprintf(os.Stderr, "Built SSA program with %d packages\n", len(ssaPkgs))
	}

	var mains []*ssa.Function
	for _, pkg := range ssaPkgs {
		if pkg != nil {
			if main := pkg.Func("main"); main != nil {
				mains = append(mains, main)
			}
			if init := pkg.Func("init"); init != nil {
				mains = append(mains, init)
			}
		}
	}
	if len(mains) == 0 {
		if g.verbose {
			fmt.Fprintf(os.Stderr, "No main or init functions found, creating empty call graph\n")
		}
		return &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}, prog, nil
	}

	// Generate call graph using the selected algorithm
	graph, err := g.generateCallGraphWithAlgorithm(prog, mains)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate call graph with %s algorithm: %w", g.algorithm, err)
	}

	if g.verbose {
		fmt.Fprintf(os.Stderr, "Generated call graph with %d nodes before cleanup\n", len(graph.Nodes))
		count := 0
		for fn := range graph.Nodes {
			if count < 10 && fn != nil {
				pkgPath := "unknown"
				if fn.Pkg != nil && fn.Pkg.Pkg != nil {
					pkgPath = fn.Pkg.Pkg.Path()
				}
				fmt.Fprintf(os.Stderr, "  Found function: %s in package %s\n", fn.Name(), pkgPath)
				count++
			}
		}
	}
	g.deleteOnlyArtificialSyntheticNodes(graph)

	if g.verbose {
		fmt.Fprintf(os.Stderr, "Generated call graph with %d nodes after cleanup\n", len(graph.Nodes))
	}

	return graph, prog, nil
}

// deleteOnlyArtificialSyntheticNodes removes compiler-generated synthetic nodes
// while preserving synthetic nodes that represent real function calls.
func (g *Generator) deleteOnlyArtificialSyntheticNodes(graph *callgraph.Graph) {
	initialNodeCount := len(graph.Nodes)
	if initialNodeCount == 0 {
		return
	}

	var toDelete []*callgraph.Node

	for fn, node := range graph.Nodes {
		if fn == nil || node == nil {
			continue
		}

		if fn.Synthetic != "" {
			if fn.Pkg != nil && fn.Pkg.Pkg != nil {
				pkgPath := fn.Pkg.Pkg.Path()
				if g.config.IsStandardLibrary(pkgPath) || g.config.IsDependency(pkgPath) {
					continue
				}
			}
			if strings.Contains(fn.Synthetic, "wrapper") ||
				strings.Contains(fn.Synthetic, "bound") ||
				(fn.Name() == "bounds" && strings.Contains(fn.Synthetic, "check")) {
				toDelete = append(toDelete, node)
			}
		}
	}

	if len(toDelete) > initialNodeCount/2 {
		if g.verbose {
			fmt.Fprintf(os.Stderr, "Skipping synthetic node deletion: would delete %d of %d nodes (too many)\n",
				len(toDelete), initialNodeCount)
		}
		return
	}

	for _, node := range toDelete {
		graph.DeleteNode(node)
	}

	if g.verbose && len(toDelete) > 0 {
		fmt.Fprintf(os.Stderr, "Deleted %d artificial synthetic nodes\n", len(toDelete))
	}
}

// CallGraphInfo contains information about a function in the call graph
type CallGraphInfo struct {
	Function     *ssa.Function
	PackagePath  string
	FunctionName string
	IsExported   bool
	Position     token.Position
}

// GetFunctionInfo extracts structured information from a call graph node
func GetFunctionInfo(node *callgraph.Node, fset *token.FileSet) *CallGraphInfo {
	if node == nil || node.Func == nil || node.Func.Pkg == nil {
		return nil
	}

	info := &CallGraphInfo{
		Function:     node.Func,
		PackagePath:  node.Func.Pkg.Pkg.Path(),
		FunctionName: node.Func.Name(),
		IsExported:   node.Func.Object() != nil && node.Func.Object().Exported(),
	}

	if node.Func.Pos().IsValid() && fset != nil {
		info.Position = fset.Position(node.Func.Pos())
	}

	return info
}

// FindFunctionByName searches for functions matching the given package and function name
func FindFunctionByName(graph *callgraph.Graph, packagePath, functionName string) []*callgraph.Node {
	var matches []*callgraph.Node

	for _, node := range graph.Nodes {
		if node.Func == nil || node.Func.Pkg == nil {
			continue
		}

		if node.Func.Pkg.Pkg.Path() == packagePath &&
			(node.Func.Name() == functionName ||
				node.Func.String() == functionName) {
			matches = append(matches, node)
		}
	}

	return matches
}

// GetCallersOf returns all functions that call the given function
func GetCallersOf(node *callgraph.Node) []*callgraph.Node {
	var callers []*callgraph.Node

	for _, edge := range node.In {
		if edge.Caller != nil {
			callers = append(callers, edge.Caller)
		}
	}

	return callers
}

// GetCalleesOf returns all functions called by the given function
func GetCalleesOf(node *callgraph.Node) []*callgraph.Node {
	var callees []*callgraph.Node

	for _, edge := range node.Out {
		if edge.Callee != nil {
			callees = append(callees, edge.Callee)
		}
	}

	return callees
}

// isTargetPackage checks if a package matches the target for dependency FBOM generation.
func (g *Generator) isTargetPackage(packagePath string) bool {
	targetPkg := g.packagePath

	if targetPkg == packagePath {
		return true
	}

	if strings.HasPrefix(packagePath, targetPkg) {
		remainder := strings.TrimPrefix(packagePath, targetPkg)
		return remainder == "" || strings.HasPrefix(remainder, "/")
	}

	return false
}

// generateCallGraphWithAlgorithm generates a call graph using the specified algorithm
func (g *Generator) generateCallGraphWithAlgorithm(prog *ssa.Program, mains []*ssa.Function) (*callgraph.Graph, error) {
	if g.verbose {
		fmt.Fprintf(os.Stderr, "Using %s algorithm for call graph generation\n", g.algorithm)
	}

	switch g.algorithm {
	case "rta":
		result := rta.Analyze(mains, true)
		if result == nil || result.CallGraph == nil {
			return nil, fmt.Errorf("RTA analysis returned nil")
		}
		return result.CallGraph, nil

	case "cha":
		graph := cha.CallGraph(prog)
		if graph == nil {
			return nil, fmt.Errorf("CHA analysis returned nil")
		}
		return graph, nil

	case "static":
		graph := static.CallGraph(prog)
		if graph == nil {
			return nil, fmt.Errorf("static analysis returned nil")
		}
		return graph, nil

	case "vta":
		// Convert mains slice to map as required by VTA
		mainsMap := make(map[*ssa.Function]bool)
		for _, main := range mains {
			mainsMap[main] = true
		}
		result := vta.CallGraph(mainsMap, cha.CallGraph(prog))
		if result == nil {
			return nil, fmt.Errorf("VTA analysis returned nil")
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", g.algorithm)
	}
}
