package rules

import (
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// TestMatchesPattern tests the pattern matching utility (basic cases)
func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		str     string
		pattern string
		want    bool
	}{
		{"main", "main", true},
		{"TestMain", "Test*", true},
		{"testhelper", "test*", true},
		{"helper", "test*", false},
		{"github.com/example", "github.com/*", true},
		{"internal/pkg", "internal/*", true},
		{"external/pkg", "internal/*", false},
		{"", "", true},
		{"different", "main", false},
	}

	for _, tt := range tests {
		t.Run(tt.str+"_matches_"+tt.pattern, func(t *testing.T) {
			got := MatchesPattern(tt.str, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.str, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestMatchesPattern_WildcardCases tests the wildcard pattern behavior
func TestMatchesPattern_WildcardCases(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		pattern string
		want    bool
	}{
		// Single wildcard should match everything
		{"wildcard matches anything", "anything", "*", true},
		{"wildcard matches empty", "", "*", true},
		{"wildcard matches complex", "very/complex/path", "*", true},

		// Suffix patterns (starting with *)
		{"suffix match", "TestMain", "*Main", true},
		{"suffix match 2", "helper", "*er", true},
		{"suffix mismatch", "TestMain", "*Test", false},

		// Contains patterns (*word*)
		{"contains match", "TestMainHelper", "*Main*", true},
		{"contains mismatch", "TestHelper", "*Main*", false},
		{"contains empty middle", "anything", "**", true}, // Edge case: ** should match anything
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesPattern(tt.str, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.str, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestMatchesEntryPointPattern tests entry point pattern matching
func TestMatchesEntryPointPattern(t *testing.T) {
	patterns := []string{
		"main",
		"Test*",
		"Benchmark*",
		"init",
	}

	tests := []struct {
		functionName string
		want         bool
	}{
		{"main", true},
		{"TestSomething", true},
		{"BenchmarkSomething", true},
		{"init", true},
		{"helper", false},
		{"normalFunction", false},
		{"testhelper", false}, // lowercase doesn't match Test*
	}

	for _, tt := range tests {
		t.Run(tt.functionName, func(t *testing.T) {
			got := MatchesEntryPointPattern(tt.functionName, patterns)
			if got != tt.want {
				t.Errorf("MatchesEntryPointPattern(%q, %v) = %v, want %v", tt.functionName, patterns, got, tt.want)
			}
		})
	}
}

// TestHasReflectionRisk tests reflection risk detection
func TestHasReflectionRisk(t *testing.T) {
	tests := []struct {
		name  string
		usage *models.Usage
		want  bool
	}{
		{
			name:  "nil usage",
			usage: nil,
			want:  false,
		},
		{
			name: "high risk usage",
			usage: &models.Usage{
				ReflectionRisk: models.RiskHigh,
			},
			want: true,
		},
		{
			name: "medium risk usage",
			usage: &models.Usage{
				ReflectionRisk: models.RiskMedium,
			},
			want: true,
		},
		{
			name: "low risk usage",
			usage: &models.Usage{
				ReflectionRisk: models.RiskLow,
			},
			want: false,
		},
		{
			name: "no risk usage",
			usage: &models.Usage{
				ReflectionRisk: models.RiskNone,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasReflectionRisk(tt.usage)
			if got != tt.want {
				t.Errorf("HasReflectionRisk() = %v, want %v", got, tt.want)
			}
		})
	}
}
