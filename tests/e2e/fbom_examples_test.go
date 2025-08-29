package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang-fbom-generator/tests/shared"

	"gopkg.in/yaml.v2"
)

// TestFBOMExamples tests FBOM generation against all example codebases
func TestFBOMExamples(t *testing.T) {
	// Build the binary first
	binaryPath := shared.GetBinaryPath(t)

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

func runTestCase(t *testing.T, binaryPath, testCaseName string) {
	// Read expectations
	expectationPath := filepath.Join("testcases", testCaseName, "expected.yaml")
	expectationData, err := os.ReadFile(expectationPath)
	if err != nil {
		t.Fatalf("Failed to read expectations file: %v", err)
	}

	var expectations shared.TestExpectation
	err = yaml.Unmarshal(expectationData, &expectations)
	if err != nil {
		t.Fatalf("Failed to parse expectations: %v", err)
	}

	// Get the example project path
	examplePath := filepath.Join("../../examples", testCaseName)
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Fatalf("Example project not found: %s", examplePath)
	}

	// Read the go.mod file to determine the root module name
	goModPath := filepath.Join(examplePath, "go.mod")
	rootModuleName := ""
	if goModData, err := os.ReadFile(goModPath); err == nil {
		lines := strings.Split(string(goModData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				rootModuleName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
				break
			}
		}
	}

	// Run the binary on the example project
	cmd := exec.Command(binaryPath, "-package", ".")
	cmd.Dir = examplePath // Set working directory to the example project
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run binary: %v\nOutput: %s", err, output)
	}

	// Parse the JSON output
	var fbom shared.FBOM

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
	validateExpectations(t, &fbom, &expectations, rootModuleName)

	// Run assertions
	runAssertions(t, &fbom, expectations.Assertions)

	t.Logf("Test case '%s' passed all validations", expectations.TestName)
}

func validateExpectations(t *testing.T, fbom *shared.FBOM, expectations *shared.TestExpectation, rootModuleName string) {
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

				// Check version
				if expectedDep.Version != "" && actualDep.Version != expectedDep.Version {
					t.Errorf("Dependency %s: expected version '%s', got '%s'",
						expectedDep.Name, expectedDep.Version, actualDep.Version)
				}

				// Check PURL identifier
				if expectedDep.PurlIdentifier != "" && actualDep.PurlIdentifier != expectedDep.PurlIdentifier {
					t.Errorf("Dependency %s: expected PURL identifier '%s', got '%s'",
						expectedDep.Name, expectedDep.PurlIdentifier, actualDep.PurlIdentifier)
				}

				// Check used functions count
				if expectedDep.UsedFunctions > 0 && actualDep.UsedFunctions != expectedDep.UsedFunctions {
					t.Errorf("Dependency %s: expected UsedFunctions %d, got %d",
						expectedDep.Name, expectedDep.UsedFunctions, actualDep.UsedFunctions)
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

				// Check reflection access
				if expectedFunc.HasReflectionAccess != actualFunc.UsageInfo.HasReflectionAccess {
					t.Errorf("Function %s: expected has_reflection_access=%v, got %v",
						expectedFunc.Name, expectedFunc.HasReflectionAccess, actualFunc.UsageInfo.HasReflectionAccess)
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
		// A function is user-defined if:
		// 1. It's not from standard library
		// 2. It's not from an external dependency OR it's from the root module being analyzed
		isUserDefined := !isStandardLibraryPackage(fn.Package) &&
			(!isDependencyPackage(fn.Package) || isFromRootModule(fn.Package, rootModuleName))

		if isUserDefined {
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

	// Validate dependency clusters
	for _, expectedCluster := range expectations.Expectations.DependencyClusters {
		found := false
		for _, actualCluster := range fbom.DependencyClusters {
			if actualCluster.Name == expectedCluster.Name {
				found = true

				// Check minimum entry points
				if expectedCluster.MinEntryPoints > 0 && len(actualCluster.EntryPoints) < expectedCluster.MinEntryPoints {
					t.Errorf("Dependency cluster %s: expected at least %d entry points, got %d",
						expectedCluster.Name, expectedCluster.MinEntryPoints, len(actualCluster.EntryPoints))
				}

				// Check minimum blast radius
				if expectedCluster.MinBlastRadius > 0 && actualCluster.TotalBlastRadius < expectedCluster.MinBlastRadius {
					t.Errorf("Dependency cluster %s: expected at least %d blast radius, got %d",
						expectedCluster.Name, expectedCluster.MinBlastRadius, actualCluster.TotalBlastRadius)
				}

				// Check specific entry points
				for _, expectedEntry := range expectedCluster.EntryPointsContain {
					entryFound := false
					for _, actualEntry := range actualCluster.EntryPoints {
						if actualEntry.Function == expectedEntry.Function {
							entryFound = true

							// Check called_from_contains
							for _, expectedCaller := range expectedEntry.CalledFromContains {
								callerFound := false
								for _, actualCaller := range actualEntry.CalledFrom {
									if actualCaller == expectedCaller {
										callerFound = true
										break
									}
								}
								if !callerFound {
									t.Errorf("Dependency cluster %s, entry point %s: expected to be called from '%s', but not found in %v",
										expectedCluster.Name, expectedEntry.Function, expectedCaller, actualEntry.CalledFrom)
								}
							}
							break
						}
					}
					if !entryFound {
						t.Errorf("Dependency cluster %s: expected entry point '%s' not found",
							expectedCluster.Name, expectedEntry.Function)
					}
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected dependency cluster '%s' not found", expectedCluster.Name)
		}
	}
}

func runAssertions(t *testing.T, fbom *shared.FBOM, assertions []shared.Assertion) {
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

		case "dependency_version":
			found := false
			for _, dep := range fbom.Dependencies {
				if dep.Name == assertion.Name {
					found = true
					if dep.Version != assertion.ExpectedVersion {
						t.Errorf("Assertion failed: dependency '%s' should have version '%s', got '%s'",
							assertion.Name, assertion.ExpectedVersion, dep.Version)
					}
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: dependency '%s' should exist for version check", assertion.Name)
			}

		case "dependency_purl":
			found := false
			for _, dep := range fbom.Dependencies {
				if dep.Name == assertion.Name {
					found = true
					if dep.PurlIdentifier != assertion.ExpectedPurl {
						t.Errorf("Assertion failed: dependency '%s' should have PURL identifier '%s', got '%s'",
							assertion.Name, assertion.ExpectedPurl, dep.PurlIdentifier)
					}
					break
				}
			}
			if !found {
				t.Errorf("Assertion failed: dependency '%s' should exist for PURL check", assertion.Name)
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

		case "vendor_dependency_handling":
			// Ensure vendor packages are detected and handled correctly
			vendorDepsFound := 0
			for _, dep := range fbom.Dependencies {
				if strings.Contains(dep.Name, "vendor/") {
					vendorDepsFound++
				}
			}
			if vendorDepsFound == 0 {
				t.Errorf("Vendor assertion failed: No vendor dependencies found - vendor directory handling may be broken")
			} else {
				t.Logf("Vendor dependencies detected: %d packages from vendor directory", vendorDepsFound)
			}

		case "vendor_functions_excluded":
			// Ensure no functions from vendor packages are included as user functions
			vendorFunctionsFound := 0
			for _, fn := range fbom.Functions {
				if strings.Contains(fn.Package, "vendor/") {
					vendorFunctionsFound++
					t.Errorf("Vendor assertion failed: Found function '%s' from vendor package '%s' - vendor functions should not be included", fn.Name, fn.Package)
				}
			}
			if vendorFunctionsFound == 0 {
				t.Logf("Vendor functions correctly excluded: No functions from vendor packages found in FBOM")
			}

		case "vendor_mod_flag_usage":
			// This validates that the tool runs successfully with vendor directory present
			// The fact that we get valid output (including vendor dependencies) indicates
			// that the -mod=mod flag was used automatically
			if len(fbom.Dependencies) > 0 {
				t.Logf("Vendor mod flag usage: Tool successfully analyzed project with vendor directory (found %d dependencies)", len(fbom.Dependencies))
			} else {
				t.Errorf("Vendor mod flag assertion failed: No dependencies found - vendor directory may not be handled correctly")
			}

		default:
			t.Errorf("Unknown assertion type: %s", assertion.Type)
		}
	}
}

// Helper functions for package classification (copied from old integration test)
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

func isFromRootModule(pkg string, rootModuleName string) bool {
	// If we don't have a root module name, we can't determine this
	if rootModuleName == "" {
		return false
	}

	// Check if the package is the root module or a subpackage of the root module
	return pkg == rootModuleName || strings.HasPrefix(pkg, rootModuleName+"/")
}
