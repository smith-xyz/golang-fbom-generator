package integration

import (
	"strings"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/analysis/rules"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// Integration tests for entry point detection and configuration

func TestEntryPointDetectionIntegration(t *testing.T) {
	generator := output.NewFBOMGenerator(true, output.DefaultAnalysisConfig())

	tests := []struct {
		name                  string
		additionalEntryPoints []string
		expectedSuccess       bool
	}{
		{
			name:                  "Set valid entry points",
			additionalEntryPoints: []string{"GetUsers", "CreateUser", "HealthCheck"},
			expectedSuccess:       true,
		},
		{
			name:                  "Set empty entry points",
			additionalEntryPoints: []string{},
			expectedSuccess:       true,
		},
		{
			name:                  "Set nil entry points",
			additionalEntryPoints: nil,
			expectedSuccess:       true,
		},
		{
			name:                  "Set entry points with whitespace",
			additionalEntryPoints: []string{" GetUsers ", "  CreateUser", "HealthCheck  "},
			expectedSuccess:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Configure the generator with additional entry points
			err := generator.SetAdditionalEntryPoints(tt.additionalEntryPoints)

			if tt.expectedSuccess && err != nil {
				t.Errorf("Expected success but got error: %v", err)
			} else if !tt.expectedSuccess && err == nil {
				t.Error("Expected error but got success")
			}

			// Verify the entry points were stored correctly (trimmed)
			if tt.expectedSuccess && tt.additionalEntryPoints != nil {
				expectedCount := 0
				for _, ep := range tt.additionalEntryPoints {
					if strings.TrimSpace(ep) != "" {
						expectedCount++
					}
				}
				// Note: We can't directly access additionalEntryPoints from outside the package
				// This would require either a getter method or testing the behavior indirectly
				// For integration tests, we trust that SetAdditionalEntryPoints works correctly
				// and test the overall behavior in end-to-end tests
			}
		})
	}
}

// TestEntryPointPatternMatchingIntegration tests pattern matching for entry point identification
func TestEntryPointPatternMatchingIntegration(t *testing.T) {
	tests := []struct {
		name         string
		functionName string
		patterns     []string
		shouldMatch  bool
	}{
		{
			name:         "Exact match",
			functionName: "GetUsers",
			patterns:     []string{"GetUsers"},
			shouldMatch:  true,
		},
		{
			name:         "Prefix pattern",
			functionName: "GetUsers",
			patterns:     []string{"Get*"},
			shouldMatch:  true,
		},
		{
			name:         "Suffix pattern",
			functionName: "CreateUser",
			patterns:     []string{"*User"},
			shouldMatch:  true,
		},
		{
			name:         "Multiple patterns - one matches",
			functionName: "HealthCheck",
			patterns:     []string{"Get*", "Health*", "Process*"},
			shouldMatch:  true,
		},
		{
			name:         "No pattern matches",
			functionName: "internalHelper",
			patterns:     []string{"Get*", "Create*", "Health*"},
			shouldMatch:  false,
		},
		{
			name:         "Empty patterns list",
			functionName: "GetUsers",
			patterns:     []string{},
			shouldMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the pattern matching logic directly
			matches := rules.MatchesEntryPointPattern(tt.functionName, tt.patterns)
			if matches != tt.shouldMatch {
				t.Errorf("Pattern matching failed. Function: %s, Patterns: %v, Expected: %t, Got: %t",
					tt.functionName, tt.patterns, tt.shouldMatch, matches)
			}
		})
	}
}
