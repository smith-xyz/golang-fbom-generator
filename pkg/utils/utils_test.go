package utils

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestGetCurrentGoModule(t *testing.T) {
	// This test assumes we're running in a Go module
	module, err := GetCurrentGoModule()
	if err != nil {
		t.Fatalf("GetCurrentGoModule() failed: %v", err)
	}

	if module == "" {
		t.Error("Expected non-empty module name")
	}

	// Should be our module name
	expected := "github.com/smith-xyz/golang-fbom-generator"
	if module != expected {
		t.Errorf("Expected module %q, got %q", expected, module)
	}
}

func TestTrimSpaceSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "mixed whitespace and content",
			input:    []string{"  hello  ", "", "  world", "test  ", "   "},
			expected: []string{"hello", "world", "test"},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "all empty/whitespace",
			input:    []string{"", "  ", "   ", "\t"},
			expected: []string{},
		},
		{
			name:     "no trimming needed",
			input:    []string{"hello", "world"},
			expected: []string{"hello", "world"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimSpaceSlice(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected length %d, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("At index %d: expected %q, got %q", i, expected, result[i])
				}
			}
		})
	}
}

func TestParseCommaDelimited(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "normal comma separated",
			input:    "one,two,three",
			expected: []string{"one", "two", "three"},
		},
		{
			name:     "with whitespace",
			input:    " one , two  ,  three ",
			expected: []string{"one", "two", "three"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single item",
			input:    "single",
			expected: []string{"single"},
		},
		{
			name:     "empty items",
			input:    "one,,three,",
			expected: []string{"one", "three"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCommaDelimited(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected length %d, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("At index %d: expected %q, got %q", i, expected, result[i])
				}
			}
		})
	}
}

func TestWorkingDirectoryManager(t *testing.T) {
	// Get current directory for testing
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	wm, err := NewWorkingDirectoryManager()
	if err != nil {
		t.Fatalf("Failed to create WorkingDirectoryManager: %v", err)
	}

	if wm.GetOriginalDirectory() != originalWd {
		t.Errorf("Expected original directory %q, got %q", originalWd, wm.GetOriginalDirectory())
	}

	// Test changing to temp directory
	tempDir := os.TempDir()
	if err := wm.ChangeToDirectory(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	currentWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// On some systems like macOS, paths may resolve differently (e.g., /var vs /private/var)
	// So we'll check if they resolve to the same directory or at least that we're not in the original dir
	if currentWd == originalWd {
		t.Error("Should have changed to a different directory, but still in original directory")
	}

	// Test restoring
	if err := wm.RestoreOriginalDirectory(); err != nil {
		t.Fatalf("Failed to restore original directory: %v", err)
	}

	restoredWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get restored directory: %v", err)
	}

	if restoredWd != originalWd {
		t.Errorf("Expected to be restored to %q, but in %q", originalWd, restoredWd)
	}
}

func TestWithDirectoryChange(t *testing.T) {
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	tempDir := os.TempDir()
	var insideFunctionWd string

	err = WithDirectoryChange(tempDir, func() error {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		insideFunctionWd = wd
		return nil
	})

	if err != nil {
		t.Fatalf("WithDirectoryChange failed: %v", err)
	}

	// Just verify we changed to a different directory than where we started
	if insideFunctionWd == originalWd {
		t.Error("Should have changed to a different directory inside function, but still in original directory")
	}

	// Verify we're back to original directory
	currentWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	if currentWd != originalWd {
		t.Errorf("Expected to be restored to %q, but in %q", originalWd, currentWd)
	}
}

func TestVerboseLogger(t *testing.T) {
	// Test verbose logger
	verboseLogger := NewVerboseLogger(true)
	if !verboseLogger.IsVerbose() {
		t.Error("Expected verbose logger to be verbose")
	}

	// Test non-verbose logger
	nonVerboseLogger := NewVerboseLogger(false)
	if nonVerboseLogger.IsVerbose() {
		t.Error("Expected non-verbose logger to not be verbose")
	}

	// Note: We can't easily test the actual output without capturing stderr,
	// but we can test that the methods don't panic
	verboseLogger.Log("test message")
	verboseLogger.Logf("test %s", "formatted")
	verboseLogger.DebugLogf("debug %s", "message")

	nonVerboseLogger.Log("should not appear")
	nonVerboseLogger.Logf("should not %s", "appear")
	nonVerboseLogger.DebugLogf("should not %s", "appear")

	// Test convenience functions
	VerboseLog(true, "test")
	VerboseLogf(true, "test %s", "formatted")
	VerboseLog(false, "should not appear")
	VerboseLogf(false, "should not %s", "appear")
}

func TestCheckGovulncheckAvailable(t *testing.T) {
	// Test that CheckGovulncheckAvailable works correctly
	err := CheckGovulncheckAvailable(false)
	if err != nil {
		// This is expected if govulncheck is not installed
		if !strings.Contains(err.Error(), "govulncheck not found") {
			t.Errorf("Expected 'govulncheck not found' error, got: %v", err)
		}
		t.Skip("Skipping test - govulncheck not available (this is expected in CI/testing environments)")
	}
	// If we get here, govulncheck is available
}

func TestIsGovulncheckSuccessOrExpectedFailure(t *testing.T) {
	tests := []struct {
		name     string
		result   *GovulncheckResult
		expected bool
	}{
		{
			name: "success case",
			result: &GovulncheckResult{
				Output:   []byte("no vulnerabilities found"),
				ExitCode: 0,
				Error:    nil,
			},
			expected: true,
		},
		{
			name: "expected failure with output",
			result: &GovulncheckResult{
				Output:   []byte(`{"osv": {"id": "GO-2023-1234"}}`),
				ExitCode: 1,
				Error:    fmt.Errorf("exit status 1"),
			},
			expected: true,
		},
		{
			name: "failure without output",
			result: &GovulncheckResult{
				Output:   []byte{},
				ExitCode: 1,
				Error:    fmt.Errorf("command failed"),
			},
			expected: false,
		},
		{
			name: "unknown error",
			result: &GovulncheckResult{
				Output:   []byte{},
				ExitCode: -1,
				Error:    fmt.Errorf("unknown error"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsGovulncheckSuccessOrExpectedFailure(tt.result)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
