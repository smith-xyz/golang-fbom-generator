package output

import (
	"testing"
)

// Unit tests for external dependency data structures and logic
func TestExternalDependencyDataStructures(t *testing.T) {
	// Test the enhanced data structures work correctly

	// Create a sample function with external and stdlib calls
	testFunc := Function{
		Name:     "testFunction",
		FullName: "main.testFunction",
		Package:  "main",
		UsageInfo: UsageInfo{
			Calls: []string{"main.otherFunction"},
			ExternalCalls: []string{
				"github.com/gin-gonic/gin.Default",
				"github.com/gin-gonic/gin.Engine.GET",
				"golang.org/x/crypto/bcrypt.GenerateFromPassword",
			},
			StdlibCalls: []string{
				"fmt.Println",
				"encoding/json.Marshal",
			},
			CalledBy:            []string{"main.caller"},
			IsReachable:         true,
			ReachabilityType:    "direct",
			DistanceFromEntry:   1,
			InCriticalPath:      false,
			HasReflectionAccess: false,
			IsEntryPoint:        false,
			CVEReferences:       []string{},
		},
	}

	// Test that all call arrays are properly initialized
	if testFunc.UsageInfo.Calls == nil {
		t.Error("Calls array should not be nil")
	}
	if testFunc.UsageInfo.ExternalCalls == nil {
		t.Error("ExternalCalls array should not be nil")
	}
	if testFunc.UsageInfo.StdlibCalls == nil {
		t.Error("StdlibCalls array should not be nil")
	}

	// Test call separation
	if len(testFunc.UsageInfo.ExternalCalls) != 3 {
		t.Errorf("Expected 3 external calls, got %d", len(testFunc.UsageInfo.ExternalCalls))
	}
	if len(testFunc.UsageInfo.StdlibCalls) != 2 {
		t.Errorf("Expected 2 stdlib calls, got %d", len(testFunc.UsageInfo.StdlibCalls))
	}

	// Test enhanced dependency structure
	testDep := Dependency{
		Name:           "github.com/gin-gonic/gin",
		Version:        "v1.9.1",
		Type:           "go-module",
		SPDXId:         "SPDXRef-Package-github-com-gin-gonic-gin",
		PackageManager: "go",
		UsedFunctions:  2,
		TotalFunctions: 247,
		FBOMReference: &ExternalFBOMReference{
			FBOMLocation:   "./fboms/github-com-gin-gonic-gin.fbom.json",
			FBOMVersion:    "0.1.0",
			ResolutionType: "file",
			SPDXDocumentId: "SPDXRef-Document-gin",
		},
		CalledFunctions: []ExternalFunctionCall{
			{
				FunctionName:     "Default",
				FullFunctionName: "github.com/gin-gonic/gin.Default",
				CallSites:        []string{"main.testFunction"},
				CallCount:        1,
				CallContext:      "direct",
			},
			{
				FunctionName:     "GET",
				FullFunctionName: "github.com/gin-gonic/gin.Engine.GET",
				CallSites:        []string{"main.testFunction"},
				CallCount:        1,
				CallContext:      "direct",
			},
		},
	}

	// Test FBOM reference
	if testDep.FBOMReference == nil {
		t.Error("FBOMReference should not be nil")
	} else {
		if testDep.FBOMReference.ResolutionType != "file" {
			t.Errorf("Expected resolution type 'file', got %s", testDep.FBOMReference.ResolutionType)
		}
		if testDep.FBOMReference.SPDXDocumentId == "" {
			t.Error("SPDXDocumentId should not be empty")
		}
	}

	// Test called functions
	if len(testDep.CalledFunctions) != 2 {
		t.Errorf("Expected 2 called functions, got %d", len(testDep.CalledFunctions))
	}

	for _, calledFunc := range testDep.CalledFunctions {
		if calledFunc.CallContext == "" {
			t.Errorf("CallContext should not be empty for function %s", calledFunc.FunctionName)
		}
		if len(calledFunc.CallSites) == 0 {
			t.Errorf("CallSites should not be empty for function %s", calledFunc.FunctionName)
		}
		if calledFunc.CallCount == 0 {
			t.Errorf("CallCount should not be zero for function %s", calledFunc.FunctionName)
		}
	}
}

func TestExternalCallTrackingHelperFunctions(t *testing.T) {
	generator := NewFBOMGenerator(false)

	// Test extractPackageFromCall
	tests := []struct {
		call             string
		expectedPackage  string
		expectedFunction string
	}{
		{
			call:             "github.com/gin-gonic/gin.Default",
			expectedPackage:  "github.com/gin-gonic/gin",
			expectedFunction: "Default",
		},
		{
			call:             "golang.org/x/crypto/bcrypt.GenerateFromPassword",
			expectedPackage:  "golang.org/x/crypto/bcrypt",
			expectedFunction: "GenerateFromPassword",
		},
		{
			call:             "fmt.Println",
			expectedPackage:  "fmt",
			expectedFunction: "Println",
		},
		{
			call:             "encoding/json.Marshal",
			expectedPackage:  "encoding/json",
			expectedFunction: "Marshal",
		},
	}

	for _, test := range tests {
		actualPackage := generator.extractPackageFromCall(test.call)
		if actualPackage != test.expectedPackage {
			t.Errorf("extractPackageFromCall(%s): expected package %s, got %s",
				test.call, test.expectedPackage, actualPackage)
		}

		actualFunction := generator.extractFunctionFromCall(test.call)
		if actualFunction != test.expectedFunction {
			t.Errorf("extractFunctionFromCall(%s): expected function %s, got %s",
				test.call, test.expectedFunction, actualFunction)
		}
	}

	// Test FBOM location generation
	locationTests := []struct {
		packageName      string
		expectedLocation string
	}{
		{
			packageName:      "github.com/gin-gonic/gin",
			expectedLocation: "./fboms/github-com-gin-gonic-gin.fbom.json",
		},
		{
			packageName:      "golang.org/x/crypto",
			expectedLocation: "./fboms/golang-org-x-crypto.fbom.json",
		},
	}

	for _, test := range locationTests {
		actualLocation := generator.generateFBOMLocation(test.packageName)
		if actualLocation != test.expectedLocation {
			t.Errorf("generateFBOMLocation(%s): expected %s, got %s",
				test.packageName, test.expectedLocation, actualLocation)
		}
	}

	// Test resolution type determination
	resolutionTests := []struct {
		packageName            string
		expectedResolutionType string
	}{
		{
			packageName:            "github.com/gin-gonic/gin",
			expectedResolutionType: "file",
		},
		{
			packageName:            "golang.org/x/crypto",
			expectedResolutionType: "file",
		},
	}

	for _, test := range resolutionTests {
		actualResolution := generator.determineFBOMResolutionType(test.packageName)
		if actualResolution != test.expectedResolutionType {
			t.Errorf("determineFBOMResolutionType(%s): expected %s, got %s",
				test.packageName, test.expectedResolutionType, actualResolution)
		}
	}
}

func TestExternalDependencyExtraction(t *testing.T) {
	generator := NewFBOMGenerator(false)

	// Create test functions with external calls
	testFunctions := []Function{
		{
			Name:     "setupServer",
			FullName: "main.setupServer",
			UsageInfo: UsageInfo{
				ExternalCalls: []string{
					"github.com/gin-gonic/gin.Default",
					"github.com/gin-gonic/gin.GET",
				},
				StdlibCalls: []string{
					"fmt.Println",
				},
			},
		},
		{
			Name:     "handleAuth",
			FullName: "main.handleAuth",
			UsageInfo: UsageInfo{
				ExternalCalls: []string{
					"golang.org/x/crypto.GenerateFromPassword",
					"github.com/gin-gonic/gin.JSON",
				},
				StdlibCalls: []string{
					"fmt.Printf",
				},
			},
		},
	}

	// Test packages that should be treated as dependencies
	packages := []string{
		"fmt",                      // stdlib - should be excluded
		"encoding/json",            // stdlib - should be excluded
		"github.com/gin-gonic/gin", // dependency - should be included
		"golang.org/x/crypto",      // dependency - should be included
		"main",                     // user code - should be excluded
	}

	dependencies := generator.extractDependencies(packages, testFunctions, nil)

	// Should find 2 dependencies (gin and crypto)
	expectedDepCount := 2
	if len(dependencies) != expectedDepCount {
		t.Errorf("Expected %d dependencies, got %d", expectedDepCount, len(dependencies))
	}

	// Find gin dependency
	var ginDep *Dependency
	for i := range dependencies {
		if dependencies[i].Name == "github.com/gin-gonic/gin" {
			ginDep = &dependencies[i]
			break
		}
	}

	if ginDep == nil {
		t.Fatal("gin dependency not found")
	}

	// Test gin dependency has FBOM reference and called functions
	if ginDep.FBOMReference == nil {
		t.Error("gin dependency should have FBOM reference")
	}

	if len(ginDep.CalledFunctions) == 0 {
		t.Error("gin dependency should have called functions")
	} else {
		t.Logf("Found %d called functions for gin: %v", len(ginDep.CalledFunctions), ginDep.CalledFunctions)
	}

	// Should have 3 called functions: Default, GET, JSON
	expectedGinFunctions := map[string]bool{
		"Default": false,
		"GET":     false,
		"JSON":    false,
	}

	for _, calledFunc := range ginDep.CalledFunctions {
		if _, exists := expectedGinFunctions[calledFunc.FunctionName]; exists {
			expectedGinFunctions[calledFunc.FunctionName] = true

			// Test that call context is set
			if calledFunc.CallContext == "" {
				t.Errorf("CallContext should be set for %s", calledFunc.FunctionName)
			}

			// Test that call sites are tracked
			if len(calledFunc.CallSites) == 0 {
				t.Errorf("CallSites should not be empty for %s", calledFunc.FunctionName)
			}
		}
	}

	for funcName, found := range expectedGinFunctions {
		if !found {
			t.Errorf("Expected to find gin function %s", funcName)
		}
	}

	// Find crypto dependency
	var cryptoDep *Dependency
	for i := range dependencies {
		if dependencies[i].Name == "golang.org/x/crypto" {
			cryptoDep = &dependencies[i]
			break
		}
	}

	if cryptoDep == nil {
		t.Fatal("crypto dependency not found")
	}

	// Test crypto dependency
	if len(cryptoDep.CalledFunctions) == 0 {
		t.Error("crypto dependency should have called functions")
	}

	// Should have GenerateFromPassword
	found := false
	for _, calledFunc := range cryptoDep.CalledFunctions {
		if calledFunc.FunctionName == "GenerateFromPassword" {
			found = true
			if calledFunc.CallContext != "direct" {
				t.Errorf("Expected direct call context for GenerateFromPassword, got %s", calledFunc.CallContext)
			}
		}
	}

	if !found {
		t.Error("Expected to find GenerateFromPassword in crypto dependency")
	}
}
