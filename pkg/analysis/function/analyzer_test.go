package function

import (
	"log/slog"
	"os"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	sharedanalyzer "github.com/smith-xyz/golang-fbom-generator/pkg/analysis/shared"
	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// TestFilterUserDefinedFunctions tests the performance optimization for pre-filtering user-defined functions
//
// Performance Issue:
// BuildUserFunctionInventory loops through ALL nodes in the call graph and calls IsUserDefinedFunction
// for each one. In large projects, this can be tens of thousands of functions, most of which are
// stdlib/dependencies that we don't need to process.
//
// Optimization:
// Pre-filter user-defined functions once and reuse the filtered list, avoiding repeated
// IsUserDefinedFunction calls for every node.
func TestFilterUserDefinedFunctions(t *testing.T) {
	// Create minimal test setup
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg, err := config.DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	contextConfig, err := config.NewContextAwareConfig(".")
	if err != nil {
		t.Fatalf("Failed to create context config: %v", err)
	}

	rules := rules.NewRules(contextConfig, cfg)
	sharedAnalyzer := sharedanalyzer.NewSharedAnalyzer(logger, rules)

	analyzer := NewAnalyzer(logger, &Config{Verbose: false}, rules, sharedAnalyzer)

	// Create a minimal mock call graph for testing
	// This test will fail initially because filterUserDefinedFunctions doesn't exist
	mockCallGraph := &callgraph.Graph{
		Nodes: make(map[*ssa.Function]*callgraph.Node),
	}

	// Test the filterUserDefinedFunctions method
	userFunctions := analyzer.filterUserDefinedFunctions(mockCallGraph)

	// Basic validation
	if userFunctions == nil {
		t.Error("filterUserDefinedFunctions should return a slice, not nil")
	}

	// With an empty call graph, we should get an empty slice
	if len(userFunctions) != 0 {
		t.Errorf("Expected 0 user functions from empty call graph, got %d", len(userFunctions))
	}

	// Test with nil call graph
	nilResult := analyzer.filterUserDefinedFunctions(nil)
	if nilResult == nil {
		t.Error("filterUserDefinedFunctions should return empty slice for nil input, not nil")
	}
	if len(nilResult) != 0 {
		t.Errorf("Expected 0 user functions from nil call graph, got %d", len(nilResult))
	}

	t.Logf("Performance optimization test: Method works correctly with empty inputs")
}

// TestBuildUserFunctionInventoryEdgeCases tests edge cases for BuildUserFunctionInventory
func TestBuildUserFunctionInventoryEdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg, err := config.DefaultConfig()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	contextConfig, err := config.NewContextAwareConfig(".")
	if err != nil {
		t.Fatalf("Failed to create context config: %v", err)
	}

	rules := rules.NewRules(contextConfig, cfg)
	sharedAnalyzer := sharedanalyzer.NewSharedAnalyzer(logger, rules)

	analyzer := NewAnalyzer(logger, &Config{Verbose: false}, rules, sharedAnalyzer)

	// Test with nil call graph (edge case)
	functions := analyzer.BuildUserFunctionInventory(nil, nil, nil)
	if functions == nil {
		t.Error("BuildUserFunctionInventory should return empty slice, not nil")
	}
	if len(functions) != 0 {
		t.Errorf("Expected empty slice for nil inputs, got %d functions", len(functions))
	}
}
