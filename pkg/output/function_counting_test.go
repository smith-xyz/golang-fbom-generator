package output

import (
	"testing"
)

// TestFunctionCounting tests that used_functions are correctly counted
func TestFunctionCounting(t *testing.T) {
	tests := []struct {
		name                  string
		dependencyName        string
		calledFunctions       []ExternalFunctionCall
		expectedUsedFunctions int
	}{
		{
			name:           "Gin dependency with multiple called functions",
			dependencyName: "github.com/gin-gonic/gin",
			calledFunctions: []ExternalFunctionCall{
				{
					FunctionName: "Default",
					CallContext:  "direct",
					CallSites:    []string{"main.go:10"},
				},
				{
					FunctionName: "GET",
					CallContext:  "direct",
					CallSites:    []string{"main.go:15"},
				},
				{
					FunctionName: "POST",
					CallContext:  "direct",
					CallSites:    []string{"main.go:20"},
				},
				{
					FunctionName: "Run",
					CallContext:  "direct",
					CallSites:    []string{"main.go:25"},
				},
			},
			expectedUsedFunctions: 4,
		},
		{
			name:           "YAML dependency with single function",
			dependencyName: "gopkg.in/yaml.v2",
			calledFunctions: []ExternalFunctionCall{
				{
					FunctionName: "Unmarshal",
					CallContext:  "direct",
					CallSites:    []string{"config.go:15"},
				},
			},
			expectedUsedFunctions: 1,
		},
		{
			name:                  "Dependency with no called functions",
			dependencyName:        "github.com/unused/package",
			calledFunctions:       []ExternalFunctionCall{},
			expectedUsedFunctions: 0,
		},
		{
			name:           "Dependency with duplicate function calls (should count unique functions)",
			dependencyName: "github.com/example/package",
			calledFunctions: []ExternalFunctionCall{
				{
					FunctionName: "Process",
					CallContext:  "direct",
					CallSites:    []string{"main.go:10"},
				},
				{
					FunctionName: "Process", // Same function called from different places
					CallContext:  "direct",
					CallSites:    []string{"main.go:20"},
				},
				{
					FunctionName: "Validate",
					CallContext:  "direct",
					CallSites:    []string{"main.go:30"},
				},
			},
			expectedUsedFunctions: 2, // Only count unique function names
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a dependency with the test data
			dep := Dependency{
				Name:            tt.dependencyName,
				Version:         "v1.0.0",
				Type:            "go-module",
				SPDXId:          "SPDXRef-Test",
				PackageManager:  "go",
				PurlIdentifier:  "pkg:golang/" + tt.dependencyName + "@v1.0.0",
				CalledFunctions: tt.calledFunctions,
				// This should be calculated, not hardcoded
				UsedFunctions: 0, // This should be set by our counting logic
			}

			// Test the counting function we need to implement
			generator := NewFBOMGenerator(false)
			generator.calculateFunctionCounts(&dep)

			// Verify used functions count
			if dep.UsedFunctions != tt.expectedUsedFunctions {
				t.Errorf("Dependency %s: expected UsedFunctions %d, got %d",
					tt.dependencyName, tt.expectedUsedFunctions, dep.UsedFunctions)
			}

			// Additional validation: UsedFunctions should match length of unique called functions
			uniqueFunctions := make(map[string]bool)
			for _, fn := range tt.calledFunctions {
				uniqueFunctions[fn.FunctionName] = true
			}
			expectedUnique := len(uniqueFunctions)

			if dep.UsedFunctions != expectedUnique {
				t.Errorf("Dependency %s: UsedFunctions (%d) should match unique called functions (%d)",
					tt.dependencyName, dep.UsedFunctions, expectedUnique)
			}
		})
	}
}

// TestFunctionCountingIntegration tests function counting in the context of full FBOM generation
func TestFunctionCountingIntegration(t *testing.T) {
	t.Log("Testing function counting integration with real dependency data")

	// This test will verify that when we generate an FBOM, dependencies have correct function counts
	// We'll use test data that simulates a real project with external dependencies

	generator := NewFBOMGenerator(false)

	// Create test dependencies with called functions data
	dependencies := []Dependency{
		{
			Name:    "github.com/gin-gonic/gin",
			Version: "v1.9.1",
			Type:    "go-module",
			CalledFunctions: []ExternalFunctionCall{
				{FunctionName: "Default", CallContext: "direct", CallSites: []string{"main.go:10"}},
				{FunctionName: "GET", CallContext: "direct", CallSites: []string{"main.go:15"}},
				{FunctionName: "POST", CallContext: "direct", CallSites: []string{"main.go:20"}},
			},
		},
		{
			Name:    "gopkg.in/yaml.v2",
			Version: "v2.4.0",
			Type:    "go-module",
			CalledFunctions: []ExternalFunctionCall{
				{FunctionName: "Unmarshal", CallContext: "direct", CallSites: []string{"config.go:15"}},
			},
		},
	}

	// Apply function counting to each dependency
	for i := range dependencies {
		generator.calculateFunctionCounts(&dependencies[i])
	}

	// Verify gin dependency
	ginDep := dependencies[0]
	if ginDep.UsedFunctions != 3 {
		t.Errorf("Gin dependency should have UsedFunctions=3, got %d", ginDep.UsedFunctions)
	}

	// Verify yaml dependency
	yamlDep := dependencies[1]
	if yamlDep.UsedFunctions != 1 {
		t.Errorf("YAML dependency should have UsedFunctions=1, got %d", yamlDep.UsedFunctions)
	}

	// Log results for manual verification
	for _, dep := range dependencies {
		t.Logf("Dependency %s: UsedFunctions=%d, CalledFunctions=%d",
			dep.Name, dep.UsedFunctions, len(dep.CalledFunctions))
	}
}
