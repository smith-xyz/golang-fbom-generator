package bugs

import (
	"os"
	"testing"

	"golang-fbom-generator/tests/shared"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
	"github.com/smith-xyz/golang-fbom-generator/pkg/output"
)

// TestBug9_StructMethodDistance tests that struct methods have correct distance calculations
//
// Bug Description:
// ValidateToken (struct method) was showing distance 0 instead of proper call chain distance.
// The root cause was that isEntryPoint treated all exported functions in non-main packages as entry points,
// but this was also affecting struct methods incorrectly.
//
// Expected: Struct methods should have proper distance based on their call chain from actual entry points
// Actual (buggy): Exported struct methods were being treated as entry points with distance 0
func TestBug9_StructMethodDistance(t *testing.T) {
	testCode := `
package main

import "fmt"

func main() {
	service := &AuthService{}
	service.HandleRequest()
}

type AuthService struct{}

// This exported method should NOT be an entry point - it's called by main
func (s *AuthService) HandleRequest() {
	fmt.Println("Handling request")
	s.ValidateToken("test-token")
}

// This exported method should be distance 2, not 0 (entry point)
func (s *AuthService) ValidateToken(token string) bool {
	fmt.Println("Validating token:", token)
	return s.checkTokenExpiry(token)
}

// This should be distance 3, not 0
func (s *AuthService) checkTokenExpiry(token string) bool {
	fmt.Println("Checking expiry for:", token)
	return true
}
`

	callGraph, ssaProgram, tmpDir, err := shared.BuildCallGraphFromCodeWithDir(testCode)
	if err != nil {
		t.Fatalf("Failed to build call graph: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save current directory and change to test module directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change to test directory: %v", err)
	}

	// Create the generator in the context of the temporary module
	generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())

	reflectionUsage := map[string]*models.Usage{}

	fbom := generator.BuildFBOM(nil, reflectionUsage, callGraph, ssaProgram, "main")

	// Debug: Print all function distances
	t.Logf("Bug 9 Debug - Function distances:")
	for _, fn := range fbom.Functions {
		t.Logf("  %s: distance=%d, reachable=%t, isEntryPoint=%t",
			fn.Name, fn.UsageInfo.DistanceFromEntry, fn.UsageInfo.IsReachable, fn.UsageInfo.IsEntryPoint)
	}

	// Test the distance calculations
	expectedDistances := map[string]int{
		"main":             0, // Entry point
		"HandleRequest":    1, // Called by main
		"ValidateToken":    2, // Called by HandleRequest
		"checkTokenExpiry": 3, // Called by ValidateToken
	}

	for functionName, expectedDistance := range expectedDistances {
		found := false
		for _, fn := range fbom.Functions {
			if fn.Name == functionName {
				found = true
				if fn.UsageInfo.DistanceFromEntry != expectedDistance {
					t.Errorf("Bug 9 - Function %s has incorrect distance: expected %d, got %d",
						functionName, expectedDistance, fn.UsageInfo.DistanceFromEntry)
				}

				// ValidateToken should NOT be marked as an entry point
				if functionName == "ValidateToken" && fn.UsageInfo.IsEntryPoint {
					t.Errorf("Bug 9 - ValidateToken should not be marked as entry point")
				}

				// checkTokenExpiry should NOT be marked as an entry point
				if functionName == "checkTokenExpiry" && fn.UsageInfo.IsEntryPoint {
					t.Errorf("Bug 9 - checkTokenExpiry should not be marked as entry point")
				}

				break
			}
		}

		if !found {
			t.Errorf("Bug 9 - Function %s not found in FBOM", functionName)
		}
	}
}
