package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

// TestExpectation represents the expected results for a test case
type TestExpectation struct {
	TestName    string `yaml:"test_name"`
	Description string `yaml:"description"`

	Expectations struct {
		Dependencies []ExpectedDependency `yaml:"dependencies"`
		Functions    []ExpectedFunction   `yaml:"functions"`
		SecurityInfo ExpectedSecurityInfo `yaml:"security_info"`
	} `yaml:"expectations"`

	Assertions []Assertion `yaml:"assertions"`
}

type ExpectedDependency struct {
	Name                 string                 `yaml:"name"`
	CalledFunctionsCount int                    `yaml:"called_functions_count"`
	CalledFunctions      []ExpectedFunctionCall `yaml:"called_functions"`
	HasFBOMReference     bool                   `yaml:"has_fbom_reference"`
}

type ExpectedFunctionCall struct {
	FunctionName     string `yaml:"function_name"`
	CallContext      string `yaml:"call_context"`
	CallSitesContain string `yaml:"call_sites_contain"`
}

type ExpectedFunction struct {
	Name                 string   `yaml:"name"`
	HasExternalCalls     bool     `yaml:"has_external_calls"`
	StdlibCallsContain   []string `yaml:"stdlib_calls_contain"`
	ExternalCallsContain []string `yaml:"external_calls_contain"`
}

type ExpectedSecurityInfo struct {
	ReflectionCallsCount      int `yaml:"reflection_calls_count"`
	ExternalDependenciesCount int `yaml:"external_dependencies_count"`
	TotalFunctionsCount       int `yaml:"total_functions_count"`
	UserFunctionsCount        int `yaml:"user_functions_count"`
}

type Assertion struct {
	Type            string `yaml:"type"`
	Name            string `yaml:"name"`
	Dependency      string `yaml:"dependency"`
	Function        string `yaml:"function"`
	ExpectedContext string `yaml:"expected_context"`
	MinCount        int    `yaml:"min_count"`
	Caller          string `yaml:"caller"`
	Callee          string `yaml:"callee"`
	StdlibCall      string `yaml:"stdlib_call"`
}

// FBOM structure (simplified for testing)
type FBOM struct {
	Functions    []Function   `json:"functions"`
	Dependencies []Dependency `json:"dependencies"`
	EntryPoints  []EntryPoint `json:"entry_points"`
	SecurityInfo struct {
		ReflectionCallsCount      int `json:"reflection_calls_count"`
		TotalCVEsFound            int `json:"total_cves_found"`
		TotalExternalDependencies int `json:"total_external_dependencies"`
	} `json:"security_info"`
}

type Function struct {
	Name      string `json:"name"`
	FullName  string `json:"full_name"`
	Package   string `json:"package"`
	UsageInfo struct {
		Calls               []string `json:"calls"`
		ExternalCalls       []string `json:"external_calls"`
		StdlibCalls         []string `json:"stdlib_calls"`
		HasReflectionAccess bool     `json:"has_reflection_access"`
	} `json:"usage_info"`
}

type Dependency struct {
	Name            string                 `json:"name"`
	CalledFunctions []ExternalFunctionCall `json:"called_functions"`
	FBOMReference   *FBOMReference         `json:"fbom_reference"`
}

type ExternalFunctionCall struct {
	FunctionName     string   `json:"function_name"`
	CallContext      string   `json:"call_context"`
	CallSites        []string `json:"call_sites"`
	FullFunctionName string   `json:"full_function_name"`
}

type FBOMReference struct {
	ResolutionType string `json:"resolution_type"`
	SPDXDocumentId string `json:"spdx_document_id"`
}

type EntryPoint struct {
	Name               string `json:"name"`
	Type               string `json:"type"`
	Package            string `json:"package"`
	ReachableFunctions int    `json:"reachable_functions"`
}

func TestIntegration(t *testing.T) {
	// Build the binary first
	binaryPath := buildBinary(t)
	defer os.Remove(binaryPath)

	// Get all test cases
	testCasesDir := "testcases"
	testCases, err := os.ReadDir(testCasesDir)
	if err != nil {
		t.Fatalf("Failed to read test cases directory: %v", err)
	}

	for _, testCase := range testCases {
		if !testCase.IsDir() {
			continue
		}

		t.Run(testCase.Name(), func(t *testing.T) {
			runTestCase(t, binaryPath, testCase.Name())
		})
	}
}

func buildBinary(t *testing.T) string {
	// Get the project root (two levels up from tests/integration)
	projectRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	// Build the binary
	binaryPath := filepath.Join(projectRoot, "golang-fbom-generator-test")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build binary: %v\nOutput: %s", err, output)
	}

	return binaryPath
}

func runTestCase(t *testing.T, binaryPath, testCaseName string) {
	// Read expectations
	expectationPath := filepath.Join("testcases", testCaseName, "expected.yaml")
	expectationData, err := os.ReadFile(expectationPath)
	if err != nil {
		t.Fatalf("Failed to read expectations file: %v", err)
	}

	var expectations TestExpectation
	err = yaml.Unmarshal(expectationData, &expectations)
	if err != nil {
		t.Fatalf("Failed to parse expectations: %v", err)
	}

	// Get the example project path
	examplePath := filepath.Join("../../examples", testCaseName)
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Fatalf("Example project not found: %s", examplePath)
	}

	// Run the binary on the example project
	cmd := exec.Command(binaryPath, "-package", ".")
	cmd.Dir = examplePath // Set working directory to the example project
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run binary: %v\nOutput: %s", err, output)
	}

	// Parse the JSON output
	var fbom FBOM

	// The output might contain log messages before the JSON, so find the JSON part
	outputStr := string(output)
	jsonStart := strings.Index(outputStr, "{")
	if jsonStart == -1 {
		t.Fatalf("No JSON found in output: %s", outputStr)
	}

	jsonOutput := outputStr[jsonStart:]
	err = json.Unmarshal([]byte(jsonOutput), &fbom)
	if err != nil {
		t.Fatalf("Failed to parse FBOM output: %v\nOutput: %s", err, jsonOutput)
	}

	// Validate expectations
	validateExpectations(t, &fbom, &expectations)

	// Run assertions
	runAssertions(t, &fbom, expectations.Assertions)

	t.Logf("✓ Test case '%s' passed all validations", expectations.TestName)
}

func validateExpectations(t *testing.T, fbom *FBOM, expectations *TestExpectation) {
	// Validate dependencies
	for _, expectedDep := range expectations.Expectations.Dependencies {
		found := false
		for _, actualDep := range fbom.Dependencies {
			if actualDep.Name == expectedDep.Name {
				found = true

				// Check exact called functions count
				if expectedDep.CalledFunctionsCount > 0 && len(actualDep.CalledFunctions) != expectedDep.CalledFunctionsCount {
					t.Errorf("Dependency %s: expected exactly %d called functions, got %d",
						expectedDep.Name, expectedDep.CalledFunctionsCount, len(actualDep.CalledFunctions))
				}

				// Check FBOM reference
				if expectedDep.HasFBOMReference && actualDep.FBOMReference == nil {
					t.Errorf("Dependency %s: expected FBOM reference but found none", expectedDep.Name)
				}

				// Check specific called functions
				for _, expectedFunc := range expectedDep.CalledFunctions {
					funcFound := false
					for _, actualFunc := range actualDep.CalledFunctions {
						if actualFunc.FunctionName == expectedFunc.FunctionName {
							funcFound = true

							// Check call context
							if expectedFunc.CallContext != "" && actualFunc.CallContext != expectedFunc.CallContext {
								t.Errorf("Dependency %s, function %s: expected call context '%s', got '%s'",
									expectedDep.Name, expectedFunc.FunctionName, expectedFunc.CallContext, actualFunc.CallContext)
							}

							// Check call sites contain
							if expectedFunc.CallSitesContain != "" {
								containsCallSite := false
								for _, callSite := range actualFunc.CallSites {
									if strings.Contains(callSite, expectedFunc.CallSitesContain) {
										containsCallSite = true
										break
									}
								}
								if !containsCallSite {
									t.Errorf("Dependency %s, function %s: expected call sites to contain '%s', got %v",
										expectedDep.Name, expectedFunc.FunctionName, expectedFunc.CallSitesContain, actualFunc.CallSites)
								}
							}
							break
						}
					}
					if !funcFound {
						t.Errorf("Dependency %s: expected called function '%s' not found", expectedDep.Name, expectedFunc.FunctionName)
					}
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected dependency '%s' not found", expectedDep.Name)
		}
	}

	// Validate functions
	for _, expectedFunc := range expectations.Expectations.Functions {
		found := false
		for _, actualFunc := range fbom.Functions {
			if actualFunc.Name == expectedFunc.Name {
				found = true

				// Check external calls
				hasExternalCalls := len(actualFunc.UsageInfo.ExternalCalls) > 0
				if expectedFunc.HasExternalCalls != hasExternalCalls {
					t.Errorf("Function %s: expected has_external_calls=%v, got %v (actual external calls: %v)",
						expectedFunc.Name, expectedFunc.HasExternalCalls, hasExternalCalls, actualFunc.UsageInfo.ExternalCalls)
				}

				// Check stdlib calls contain
				for _, expectedStdlib := range expectedFunc.StdlibCallsContain {
					found := false
					for _, actualStdlib := range actualFunc.UsageInfo.StdlibCalls {
						if strings.Contains(actualStdlib, expectedStdlib) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Function %s: expected stdlib call containing '%s' not found in %v",
							expectedFunc.Name, expectedStdlib, actualFunc.UsageInfo.StdlibCalls)
					}
				}

				// Check external calls contain
				for _, expectedExternal := range expectedFunc.ExternalCallsContain {
					found := false
					for _, actualExternal := range actualFunc.UsageInfo.ExternalCalls {
						if strings.Contains(actualExternal, expectedExternal) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Function %s: expected external call containing '%s' not found in %v",
							expectedFunc.Name, expectedExternal, actualFunc.UsageInfo.ExternalCalls)
					}
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected function '%s' not found", expectedFunc.Name)
		}
	}

	// Validate security info with exact counts for precision
	secInfo := &expectations.Expectations.SecurityInfo

	// Check reflection calls count (exact match)
	if secInfo.ReflectionCallsCount >= 0 && fbom.SecurityInfo.ReflectionCallsCount != secInfo.ReflectionCallsCount {
		t.Errorf("Expected exactly %d reflection calls, got %d", secInfo.ReflectionCallsCount, fbom.SecurityInfo.ReflectionCallsCount)
	}

	// Check external dependencies count (exact match)
	if secInfo.ExternalDependenciesCount >= 0 && len(fbom.Dependencies) != secInfo.ExternalDependenciesCount {
		t.Errorf("Expected exactly %d external dependencies, got %d", secInfo.ExternalDependenciesCount, len(fbom.Dependencies))
	}

	// Count user functions (functions that should be user-defined after proper filtering)
	userFunctionCount := 0
	for _, fn := range fbom.Functions {
		// Count functions that are user-defined (not stdlib or dependencies)
		if !isStandardLibraryPackage(fn.Package) && !isDependencyPackage(fn.Package) {
			userFunctionCount++
		}
	}

	// Check total functions count (should be only user functions after proper filtering)
	if secInfo.TotalFunctionsCount >= 0 && len(fbom.Functions) != secInfo.TotalFunctionsCount {
		t.Errorf("Expected exactly %d total functions, got %d", secInfo.TotalFunctionsCount, len(fbom.Functions))
	}

	// Check user functions count (exact match)
	if secInfo.UserFunctionsCount >= 0 && userFunctionCount != secInfo.UserFunctionsCount {
		t.Errorf("Expected exactly %d user functions, got %d", secInfo.UserFunctionsCount, userFunctionCount)
	}
}

func runAssertions(t *testing.T, fbom *FBOM, assertions []Assertion) {
	for _, assertion := range assertions {
		switch assertion.Type {
		case "dependency_exists":
			found := false
			for _, dep := range fbom.Dependencies {
				if dep.Name == assertion.Name {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: dependency '%s' should exist", assertion.Name)
			}

		case "no_external_dependencies":
			if len(fbom.Dependencies) > 0 {
				t.Errorf("Assertion failed: expected no external dependencies, got %d", len(fbom.Dependencies))
			}

		case "function_exists":
			found := false
			for _, fn := range fbom.Functions {
				if fn.Name == assertion.Name {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: function '%s' should exist", assertion.Name)
			}

		case "function_called":
			found := false
			for _, dep := range fbom.Dependencies {
				if dep.Name == assertion.Dependency {
					for _, calledFunc := range dep.CalledFunctions {
						if calledFunc.FunctionName == assertion.Function {
							found = true
							break
						}
					}
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: function '%s' should be called in dependency '%s'", assertion.Function, assertion.Dependency)
			}

		case "call_context":
			found := false
			for _, dep := range fbom.Dependencies {
				if dep.Name == assertion.Dependency {
					for _, calledFunc := range dep.CalledFunctions {
						if calledFunc.FunctionName == assertion.Function {
							if calledFunc.CallContext == assertion.ExpectedContext {
								found = true
							} else {
								t.Errorf("Assertion failed: function '%s' in dependency '%s' expected call context '%s', got '%s'",
									assertion.Function, assertion.Dependency, assertion.ExpectedContext, calledFunc.CallContext)
							}
							break
						}
					}
					break
				}
			}
			if !found && assertion.ExpectedContext != "" {
				t.Errorf("Assertion failed: function '%s' not found in dependency '%s' for call context check", assertion.Function, assertion.Dependency)
			}

		case "reflection_detected":
			if assertion.MinCount > 0 && fbom.SecurityInfo.ReflectionCallsCount < assertion.MinCount {
				t.Errorf("Assertion failed: expected at least %d reflection calls, got %d", assertion.MinCount, fbom.SecurityInfo.ReflectionCallsCount)
			}

		case "stdlib_call_exists":
			found := false
			for _, fn := range fbom.Functions {
				if fn.Name == assertion.Function {
					for _, stdlibCall := range fn.UsageInfo.StdlibCalls {
						if strings.Contains(stdlibCall, assertion.StdlibCall) {
							found = true
							break
						}
					}
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: function '%s' should have stdlib call containing '%s'", assertion.Function, assertion.StdlibCall)
			}

		case "function_calls_function":
			found := false
			for _, fn := range fbom.Functions {
				if fn.Name == assertion.Caller {
					for _, call := range fn.UsageInfo.Calls {
						if strings.Contains(call, assertion.Callee) {
							found = true
							break
						}
					}
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: function '%s' should call function '%s'", assertion.Caller, assertion.Callee)
			}

		default:
			t.Errorf("Unknown assertion type: %s", assertion.Type)
		}
	}
}

// Helper functions for package classification
func isStandardLibraryPackage(pkg string) bool {
	stdlibPackages := []string{
		"fmt", "os", "net", "http", "encoding", "json", "reflect", "strings", "strconv",
		"time", "context", "sync", "io", "bufio", "bytes", "path", "filepath",
		"regexp", "sort", "math", "crypto", "hash", "log", "errors", "runtime",
		"unsafe", "syscall", "archive", "compress", "container", "database",
		"debug", "go", "html", "image", "index", "mime", "plugin", "testing",
		"text", "unicode", "embed", "cmp", "iter", "slices", "maps", "clear",
	}

	for _, stdlib := range stdlibPackages {
		if pkg == stdlib || strings.HasPrefix(pkg, stdlib+"/") {
			return true
		}
	}
	return false
}

func isDependencyPackage(pkg string) bool {
	// External dependencies typically have domain names
	return strings.Contains(pkg, ".") && (strings.Contains(pkg, "/") || strings.Contains(pkg, "github.com") || strings.Contains(pkg, "gopkg.in") || strings.Contains(pkg, "golang.org"))
}

// TestAlgorithmSelection tests that different call graph algorithms can be used
func TestAlgorithmSelection(t *testing.T) {
	binaryPath := buildBinary(t)
	defer os.Remove(binaryPath)

	// Test different algorithms on the hello-world example (simple case)
	examplePath := "../../examples/hello-world"
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Fatalf("Hello-world example not found: %s", examplePath)
	}

	algorithms := []string{"rta", "cha", "static", "vta"}

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			// Run the binary with the specified algorithm
			cmd := exec.Command(binaryPath, "-package", ".", "-algo", algorithm)
			cmd.Dir = examplePath
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to run binary with algorithm %s: %v\nOutput: %s", algorithm, err, output)
			}

			// Parse the JSON output to ensure it's valid
			var fbom FBOM

			// Find the JSON part of the output (starts with { and ends with })
			outputStr := string(output)
			startIdx := strings.Index(outputStr, "{")
			if startIdx == -1 {
				t.Fatalf("No JSON found in output for algorithm %s\nOutput: %s", algorithm, output)
			}

			// Find the last } in the output
			endIdx := strings.LastIndex(outputStr, "}")
			if endIdx == -1 || endIdx < startIdx {
				t.Fatalf("Invalid JSON structure in output for algorithm %s\nOutput: %s", algorithm, output)
			}

			jsonLine := outputStr[startIdx : endIdx+1]

			if jsonLine == "" {
				t.Fatalf("No JSON output found for algorithm %s\nOutput: %s", algorithm, output)
			}

			err = json.Unmarshal([]byte(jsonLine), &fbom)
			if err != nil {
				t.Fatalf("Failed to parse JSON output for algorithm %s: %v\nJSON: %s", algorithm, err, jsonLine)
			}

			// Basic validation - ensure we got some functions
			if len(fbom.Functions) == 0 {
				t.Errorf("No functions found in FBOM for algorithm %s", algorithm)
			}

			// Check that main function exists (basic sanity check)
			mainFound := false
			for _, fn := range fbom.Functions {
				if fn.Name == "main" {
					mainFound = true
					break
				}
			}
			if !mainFound {
				t.Errorf("Main function not found in FBOM for algorithm %s", algorithm)
			}

			t.Logf("Algorithm %s successfully generated FBOM with %d functions", algorithm, len(fbom.Functions))
		})
	}
}

// TestInvalidAlgorithm tests that an invalid algorithm returns an error
func TestInvalidAlgorithm(t *testing.T) {
	binaryPath := buildBinary(t)
	defer os.Remove(binaryPath)

	examplePath := "../../examples/hello-world"

	// Test with an invalid algorithm
	cmd := exec.Command(binaryPath, "-package", ".", "-algo", "invalid")
	cmd.Dir = examplePath
	output, err := cmd.CombinedOutput()

	// We expect this to fail
	if err == nil {
		t.Fatalf("Expected binary to fail with invalid algorithm, but it succeeded\nOutput: %s", output)
	}

	// Check that the error message mentions the unsupported algorithm
	if !strings.Contains(string(output), "unsupported call graph algorithm") {
		t.Errorf("Expected error message about unsupported algorithm, got: %s", output)
	}
}

// TestEntryPointFunctionality tests the additional entry point functionality
func TestEntryPointFunctionality(t *testing.T) {
	binaryPath := buildBinary(t)
	defer os.Remove(binaryPath)

	examplePath := "../../examples/multi-entrypoint/cmd/app1"

	tests := []struct {
		name                  string
		entryPointsFlag       string
		expectedEntryPoints   []string
		unexpectedEntryPoints []string
	}{
		{
			name:                  "Default entry points only",
			entryPointsFlag:       "",
			expectedEntryPoints:   []string{"main", "init"},
			unexpectedEntryPoints: []string{"handleGetUsers", "handleCreateUser", "handleHealthCheck", "setupRoutes"},
		},
		{
			name:                  "Specific HTTP handlers as entry points",
			entryPointsFlag:       "handleGetUsers,handleCreateUser,handleHealthCheck",
			expectedEntryPoints:   []string{"main", "init", "handleGetUsers", "handleCreateUser", "handleHealthCheck"},
			unexpectedEntryPoints: []string{"setupRoutes", "handleUpdateUser", "handleDeleteUser"},
		},
		{
			name:                  "All HTTP handlers as entry points",
			entryPointsFlag:       "handle*",
			expectedEntryPoints:   []string{"main", "init", "handleGetUsers", "handleCreateUser", "handleHealthCheck", "handleUpdateUser", "handleDeleteUser", "handleGetUser"},
			unexpectedEntryPoints: []string{"setupRoutes"},
		},
		{
			name:                  "Wildcard pattern - handle prefix",
			entryPointsFlag:       "handle*",
			expectedEntryPoints:   []string{"main", "init", "handleGetUsers", "handleHealthCheck"},
			unexpectedEntryPoints: []string{"setupRoutes"},
		},
		{
			name:                  "Wildcard pattern - suffix matching",
			entryPointsFlag:       "*User",
			expectedEntryPoints:   []string{"main", "init", "handleCreateUser", "handleUpdateUser", "handleDeleteUser", "handleGetUser"},
			unexpectedEntryPoints: []string{"handleGetUsers", "handleHealthCheck", "setupRoutes"},
		},
		{
			name:                  "Multiple specific handlers",
			entryPointsFlag:       "setupRoutes,handleHealthCheck",
			expectedEntryPoints:   []string{"main", "init", "setupRoutes", "handleHealthCheck"},
			unexpectedEntryPoints: []string{"handleGetUsers", "handleCreateUser"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build command with entry points flag
			args := []string{"-package", "."}
			if tt.entryPointsFlag != "" {
				args = append(args, "-entry-points", tt.entryPointsFlag)
			}

			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = examplePath
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("Binary execution failed: %v\nOutput: %s", err, output)
			}

			// Parse the JSON output
			var fbom FBOM
			if err := json.Unmarshal(output, &fbom); err != nil {
				t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, output)
			}

			// Extract entry point names
			actualEntryPointNames := make([]string, len(fbom.EntryPoints))
			for i, ep := range fbom.EntryPoints {
				actualEntryPointNames[i] = ep.Name
			}

			// Verify expected entry points are present
			for _, expected := range tt.expectedEntryPoints {
				found := false
				for _, actual := range actualEntryPointNames {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected entry point '%s' not found. Found entry points: %v", expected, actualEntryPointNames)
				}
			}

			// Verify unexpected entry points are NOT present
			for _, unexpected := range tt.unexpectedEntryPoints {
				for _, actual := range actualEntryPointNames {
					if actual == unexpected {
						t.Errorf("Unexpected entry point '%s' found. Entry points: %v", unexpected, actualEntryPointNames)
					}
				}
			}

			// Verify entry point metadata
			for _, ep := range fbom.EntryPoints {
				if ep.Name == "" {
					t.Error("Entry point has empty name")
				}
				if ep.Type == "" {
					t.Error("Entry point has empty type")
				}
				if ep.Package == "" {
					t.Error("Entry point has empty package")
				}
				if ep.ReachableFunctions < 0 {
					t.Errorf("Entry point %s has negative reachable functions: %d", ep.Name, ep.ReachableFunctions)
				}
			}
		})
	}
}

// TestEntryPointPatternErrors tests error handling for invalid entry point patterns
func TestEntryPointPatternErrors(t *testing.T) {
	binaryPath := buildBinary(t)
	defer os.Remove(binaryPath)

	examplePath := "../../examples/multi-entrypoint/cmd/app1"

	tests := []struct {
		name            string
		entryPointsFlag string
		expectSuccess   bool
	}{
		{
			name:            "Valid patterns should succeed",
			entryPointsFlag: "GetUsers,Create*",
			expectSuccess:   true,
		},
		{
			name:            "Empty patterns should succeed",
			entryPointsFlag: "",
			expectSuccess:   true,
		},
		{
			name:            "Patterns with spaces should be trimmed and succeed",
			entryPointsFlag: " GetUsers , CreateUser ",
			expectSuccess:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"-package", "."}
			if tt.entryPointsFlag != "" {
				args = append(args, "-entry-points", tt.entryPointsFlag)
			}

			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = examplePath
			output, err := cmd.CombinedOutput()

			if tt.expectSuccess {
				if err != nil {
					t.Errorf("Expected success but got error: %v\nOutput: %s", err, output)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error but got success\nOutput: %s", output)
				}
			}
		})
	}
}
