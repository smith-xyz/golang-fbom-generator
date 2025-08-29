package callgraph

import (
	"log/slog"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/shared"
	"github.com/smith-xyz/golang-fbom-generator/pkg/models"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// EntryPointAnalyzer handles analysis of application entry points
type EntryPointAnalyzer struct {
	logger                *slog.Logger
	verbose               bool
	additionalEntryPoints []string
	rules                 *rules.Rules
	sharedAnalyzer        *shared.SharedAnalyzer // Reference to shared analyzer for utility methods
}

// NewEntryPointAnalyzer creates a new entry point analyzer
func NewEntryPointAnalyzer(logger *slog.Logger, verbose bool, rules *rules.Rules, sharedAnalyzer *shared.SharedAnalyzer) *EntryPointAnalyzer {
	return &EntryPointAnalyzer{
		logger:                logger,
		verbose:               verbose,
		additionalEntryPoints: make([]string, 0),
		rules:                 rules,
		sharedAnalyzer:        sharedAnalyzer,
	}
}

// SetAdditionalEntryPoints configures additional entry point patterns
func (e *EntryPointAnalyzer) SetAdditionalEntryPoints(entryPoints []string) {
	e.additionalEntryPoints = make([]string, len(entryPoints))
	copy(e.additionalEntryPoints, entryPoints)
}

// BuildEntryPoints builds a list of application entry points
func (e *EntryPointAnalyzer) BuildEntryPoints(callGraph *callgraph.Graph) []models.EntryPoint {
	entryPoints := make([]models.EntryPoint, 0)

	if callGraph != nil {
		for fn := range callGraph.Nodes {
			if e.rules.Classifier.IsEntryPoint(fn) && e.rules.Classifier.IsUserDefinedFunction(fn) {
				// Calculate reachable functions from this specific entry point
				reachableFromEntry := e.sharedAnalyzer.CalculateReachableFromEntryPoint(callGraph, fn)

				entryPoints = append(entryPoints, models.EntryPoint{
					SPDXId:             rules.GenerateSPDXId("EntryPoint", fn),
					Name:               fn.Name(),
					Type:               e.InferEntryPointType(fn),
					Package:            e.InferPackageFromFunction(fn),
					AccessibleFrom:     e.InferAccessibility(fn),
					SecurityLevel:      e.InferSecurityLevel(fn),
					ReachableFunctions: reachableFromEntry,
				})
			}
		}
	}

	return entryPoints
}

// probably should move to rules
func (e *EntryPointAnalyzer) InferEntryPointType(fn *ssa.Function) string {
	switch fn.Name() {
	case "main":
		return "main"
	case "init":
		return "init"
	default:
		if rules.IsFunctionExported(fn) {
			return "exported"
		}
		return "internal"
	}
}

func (e *EntryPointAnalyzer) InferPackageFromFunction(fn *ssa.Function) string {
	if fn.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	return "unknown"
}

func (e *EntryPointAnalyzer) InferAccessibility(fn *ssa.Function) []string {
	if fn.Name() == "main" {
		return []string{"external"}
	}
	if fn.Name() == "init" {
		return []string{"internal"}
	}
	if rules.IsFunctionExported(fn) {
		return []string{"external"}
	}
	return []string{"internal"}
}

func (e *EntryPointAnalyzer) InferSecurityLevel(fn *ssa.Function) string {
	if fn.Name() == "init" {
		return "internal"
	}
	if fn.Name() == "main" {
		return "public"
	}
	if rules.IsFunctionExported(fn) {
		return "public"
	}
	return "internal"
}
