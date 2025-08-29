package reflection

// NOTE: This test file was generated using AI assistance.
// While the tests have been validated and are functional,
// they should be reviewed and potentially enhanced by human developers.

import (
	"go/ast"
	"go/parser"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// Test data and helper functions
func createTestDirectory() (string, error) {
	tmpDir, err := os.MkdirTemp("", "test_pkg_*")
	if err != nil {
		return "", err
	}
	return tmpDir, nil
}

func TestNewDetector(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
	}{
		{
			name:    "verbose detector",
			verbose: true,
		},
		{
			name:    "non-verbose detector",
			verbose: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector(tt.verbose)
			if detector == nil {
				t.Fatal("NewDetector() returned nil")
			}
			if detector.verbose != tt.verbose {
				t.Errorf("Expected verbose %v, got %v", tt.verbose, detector.verbose)
			}
			if detector.fset == nil {
				t.Error("Expected fset to be initialized")
			}
		})
	}
}

func TestRiskLevelString(t *testing.T) {
	tests := []struct {
		risk     models.RiskLevel
		expected string
	}{
		{models.RiskNone, "None"},
		{models.RiskLow, "Low"},
		{models.RiskMedium, "Medium"},
		{models.RiskHigh, "High"},
		{models.RiskLevel(999), "Unknown"}, // test default case
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.risk.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestHasReflectImport(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "file with reflect import",
			content: `package main

import (
	"fmt"
	"reflect"
)

func main() {
	fmt.Println("Hello")
}`,
			expected: true,
		},
		{
			name: "file without reflect import",
			content: `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Hello")
}`,
			expected: false,
		},
		{
			name: "file with only reflect import",
			content: `package main

import "reflect"

func main() {}`,
			expected: true,
		},
		{
			name: "file with no imports",
			content: `package main

func main() {}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(detector.fset, "test.go", tt.content, parser.ParseComments)
			if err != nil {
				t.Fatalf("Failed to parse test file: %v", err)
			}

			result := detector.hasReflectImport(file)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdentifyReflectionCall(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name     string
		code     string
		expected string // expected method name, empty string if not reflection
	}{
		{
			name: "reflect.TypeOf call",
			code: `package main
import "reflect"
func test() {
	reflect.TypeOf(42)
}`,
			expected: "reflect.TypeOf",
		},
		{
			name: "reflect.ValueOf call",
			code: `package main
import "reflect"
func test() {
	reflect.ValueOf("hello")
}`,
			expected: "reflect.ValueOf",
		},
		{
			name: "value.Call method",
			code: `package main
import "reflect"
func test() {
	val := reflect.ValueOf(func(){})
	val.Call(nil)
}`,
			expected: "Value.Call",
		},
		{
			name: "non-reflection call",
			code: `package main
import "fmt"
func test() {
	fmt.Println("hello")
}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(detector.fset, "test.go", tt.code, parser.ParseComments)
			if err != nil {
				t.Fatalf("Failed to parse test code: %v", err)
			}

			var foundCall *models.ReflectionCall
			ast.Inspect(file, func(n ast.Node) bool {
				if callExpr, ok := n.(*ast.CallExpr); ok {
					call := detector.identifyReflectionCall(callExpr)
					if call != nil {
						foundCall = call
						return false // stop inspection
					}
				}
				return true
			})

			if tt.expected == "" {
				if foundCall != nil {
					t.Errorf("Expected no reflection call, but found %s", foundCall.Method)
				}
			} else {
				if foundCall == nil {
					t.Errorf("Expected reflection call %s, but found none", tt.expected)
				} else if foundCall.Method != tt.expected {
					t.Errorf("Expected method %s, got %s", tt.expected, foundCall.Method)
				}
			}
		})
	}
}

func TestGetMethodRisk(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		method   string
		expected models.RiskLevel
	}{
		// High risk methods
		{"reflect.Call", models.RiskHigh},
		{"Value.Call", models.RiskHigh},
		{"Value.CallSlice", models.RiskHigh},
		{"reflect.MakeFunc", models.RiskHigh},
		{"Value.Set", models.RiskHigh},
		{"Value.SetInt", models.RiskHigh},

		// Medium risk methods
		{"reflect.MethodByName", models.RiskMedium},
		{"Value.MethodByName", models.RiskMedium},
		{"reflect.FieldByName", models.RiskMedium},
		{"Value.FieldByName", models.RiskMedium},
		{"Value.Elem", models.RiskMedium},

		// Low risk methods (default)
		{"reflect.TypeOf", models.RiskLow},
		{"reflect.ValueOf", models.RiskLow},
		{"Value.Type", models.RiskLow},
		{"unknown.method", models.RiskLow},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := detector.getMethodRisk(tt.method)
			if result != tt.expected {
				t.Errorf("Expected risk %v for method %s, got %v", tt.expected, tt.method, result)
			}
		})
	}
}

func TestCalculateRiskLevel(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name     string
		calls    []models.ReflectionCall
		expected models.RiskLevel
	}{
		{
			name:     "no calls",
			calls:    []models.ReflectionCall{},
			expected: models.RiskNone,
		},
		{
			name: "single low risk call",
			calls: []models.ReflectionCall{
				{Method: "reflect.TypeOf"},
			},
			expected: models.RiskLow,
		},
		{
			name: "single high risk call",
			calls: []models.ReflectionCall{
				{Method: "Value.Call"},
			},
			expected: models.RiskHigh,
		},
		{
			name: "mixed risk calls - should return highest",
			calls: []models.ReflectionCall{
				{Method: "reflect.TypeOf"},     // Low
				{Method: "Value.MethodByName"}, // Medium
				{Method: "Value.Call"},         // High
			},
			expected: models.RiskHigh,
		},
		{
			name: "multiple medium risk calls",
			calls: []models.ReflectionCall{
				{Method: "reflect.MethodByName"},
				{Method: "Value.FieldByName"},
			},
			expected: models.RiskMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.calculateRiskLevel(tt.calls)
			if result != tt.expected {
				t.Errorf("Expected risk level %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetReceiverType(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "simple receiver",
			code:     "func (r Receiver) Method() {}",
			expected: "Receiver",
		},
		{
			name:     "pointer receiver",
			code:     "func (r *Receiver) Method() {}",
			expected: "*Receiver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(detector.fset, "test.go", "package main\n"+tt.code, parser.ParseComments)
			if err != nil {
				t.Fatalf("Failed to parse test code: %v", err)
			}

			var result string
			ast.Inspect(file, func(n ast.Node) bool {
				if funcDecl, ok := n.(*ast.FuncDecl); ok {
					if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
						result = detector.getReceiverType(funcDecl.Recv.List[0].Type)
						return false
					}
				}
				return true
			})

			if result != tt.expected {
				t.Errorf("Expected receiver type %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestAnalyzeDirectory(t *testing.T) {
	detector := NewDetector(true) // Enable verbose for coverage

	// Create test directory with Go files
	tmpDir, err := createTestDirectory()
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test file with reflection
	testFileContent := `package testpkg

import (
	"reflect"
)

func TestFunction() {
	reflect.TypeOf(42)
	val := reflect.ValueOf("hello")
	val.Call(nil)
}

func NonReflectiveFunction() {
	// No reflection here
}
`

	testFilePath := filepath.Join(tmpDir, "test.go")
	err = os.WriteFile(testFilePath, []byte(testFileContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create file without reflection
	nonReflectContent := `package testpkg

import "fmt"

func PrintHello() {
	fmt.Println("Hello")
}
`

	nonReflectPath := filepath.Join(tmpDir, "noreflect.go")
	err = os.WriteFile(nonReflectPath, []byte(nonReflectContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write non-reflect file: %v", err)
	}

	// Analyze directory
	usageMap, err := detector.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory() error = %v", err)
	}

	// Should find TestFunction but not NonReflectiveFunction or PrintHello
	found := false
	for funcName, usage := range usageMap {
		if strings.Contains(funcName, "TestFunction") {
			found = true
			if !usage.UsesReflection {
				t.Error("Expected TestFunction to use reflection")
			}
			if len(usage.ReflectionCalls) == 0 {
				t.Error("Expected TestFunction to have reflection calls")
			}
			if usage.ReflectionRisk == models.RiskNone {
				t.Error("Expected TestFunction to have non-zero risk")
			}
		}
	}

	if !found {
		t.Error("Expected to find TestFunction in usage map")
	}
}

func TestIsReflectValue(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name     string
		varName  string
		expected bool
	}{
		{
			name:     "variable named value",
			varName:  "value",
			expected: true,
		},
		{
			name:     "variable named val",
			varName:  "val",
			expected: true,
		},
		{
			name:     "variable named typ",
			varName:  "typ",
			expected: true,
		},
		{
			name:     "variable named fn",
			varName:  "fn",
			expected: true,
		},
		{
			name:     "variable named reflectValue",
			varName:  "reflectValue",
			expected: true,
		},
		{
			name:     "variable named foo",
			varName:  "foo",
			expected: false,
		},
		{
			name:     "variable named data",
			varName:  "data",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create an identifier AST node
			ident := &ast.Ident{Name: tt.varName}
			result := detector.isReflectValue(ident)
			if result != tt.expected {
				t.Errorf("isReflectValue(%s) = %v, want %v", tt.varName, result, tt.expected)
			}
		})
	}
}

func TestGetSSAStyleFunctionName(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name        string
		code        string
		packagePath string
		expected    string
	}{
		{
			name:        "regular function",
			code:        "func TestFunc() {}",
			packagePath: "github.com/example/pkg",
			expected:    "github.com/example/pkg.TestFunc",
		},
		{
			name:        "method with receiver",
			code:        "func (r Receiver) Method() {}",
			packagePath: "github.com/example/pkg",
			expected:    "(Receiver).Method",
		},
		{
			name:        "method with pointer receiver",
			code:        "func (r *Receiver) Method() {}",
			packagePath: "github.com/example/pkg",
			expected:    "(*Receiver).Method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(detector.fset, "test.go", "package main\n"+tt.code, parser.ParseComments)
			if err != nil {
				t.Fatalf("Failed to parse test code: %v", err)
			}

			var result string
			ast.Inspect(file, func(n ast.Node) bool {
				if funcDecl, ok := n.(*ast.FuncDecl); ok {
					result = detector.getSSAStyleFunctionName(funcDecl, tt.packagePath)
					return false
				}
				return true
			})

			if result != tt.expected {
				t.Errorf("Expected function name %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetCurrentModuleName(t *testing.T) {
	detector := NewDetector(false)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Create temporary directory with go.mod
	tmpDir, err := createTestDirectory()
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	err = os.Chdir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Create go.mod file
	goModContent := `module github.com/example/testmodule

go 1.19
`
	err = os.WriteFile("go.mod", []byte(goModContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Test getting module name
	moduleName, err := detector.getCurrentModuleName()
	if err != nil {
		t.Fatalf("getCurrentModuleName() error = %v", err)
	}

	expected := "github.com/example/testmodule"
	if moduleName != expected {
		t.Errorf("Expected module name %s, got %s", expected, moduleName)
	}

	// Test with missing go.mod
	err = os.Remove("go.mod")
	if err != nil {
		t.Fatalf("Failed to remove go.mod: %v", err)
	}

	_, err = detector.getCurrentModuleName()
	if err == nil {
		t.Error("Expected error when go.mod is missing")
	}
}

func TestIsStandardLibraryPackage(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		pkgPath  string
		expected bool
	}{
		// Standard library packages
		{"fmt", true},
		{"os", true},
		{"net/http", true},
		{"crypto/rand", true},

		// Internal packages
		{"internal/something", true},
		{"runtime", true},
		{"vendor/something", true},

		// External packages
		{"github.com/user/repo", false},
		{"gopkg.in/yaml.v2", false},
		{"example.com/package", false},

		// Local packages
		{"main", false},
		{"my-project", false},
		{"my.project", false},
	}

	for _, tt := range tests {
		t.Run(tt.pkgPath, func(t *testing.T) {
			result := detector.isStandardLibraryPackage(tt.pkgPath)
			if result != tt.expected {
				t.Errorf("isStandardLibraryPackage(%s) = %v, want %v", tt.pkgPath, result, tt.expected)
			}
		})
	}
}

func TestIsLocalPackage(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name       string
		pkgPath    string
		moduleName string
		expected   bool
	}{
		{
			name:       "exact match",
			pkgPath:    "github.com/example/mymodule",
			moduleName: "github.com/example/mymodule",
			expected:   true,
		},
		{
			name:       "subpackage",
			pkgPath:    "github.com/example/mymodule/subpkg",
			moduleName: "github.com/example/mymodule",
			expected:   true,
		},
		{
			name:       "different module",
			pkgPath:    "github.com/other/module",
			moduleName: "github.com/example/mymodule",
			expected:   false,
		},
		{
			name:       "main package",
			pkgPath:    "main",
			moduleName: "",
			expected:   true,
		},
		{
			name:       "local package without module",
			pkgPath:    "localpackage",
			moduleName: "",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.isLocalPackage(tt.pkgPath, tt.moduleName)
			if result != tt.expected {
				t.Errorf("isLocalPackage(%s, %s) = %v, want %v", tt.pkgPath, tt.moduleName, result, tt.expected)
			}
		})
	}
}

func TestGetPackageDirectory(t *testing.T) {
	detector := NewDetector(false)

	tests := []struct {
		name       string
		pkgPath    string
		moduleName string
		expected   string
	}{
		{
			name:       "root module",
			pkgPath:    "github.com/example/mymodule",
			moduleName: "github.com/example/mymodule",
			expected:   ".",
		},
		{
			name:       "subpackage",
			pkgPath:    "github.com/example/mymodule/sub/pkg",
			moduleName: "github.com/example/mymodule",
			expected:   "sub/pkg",
		},
		{
			name:       "no module name",
			pkgPath:    "anything",
			moduleName: "",
			expected:   ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.getPackageDirectory(tt.pkgPath, tt.moduleName)
			if result != tt.expected {
				t.Errorf("getPackageDirectory(%s, %s) = %s, want %s", tt.pkgPath, tt.moduleName, result, tt.expected)
			}
		})
	}
}

func TestGetSummary(t *testing.T) {
	usageMap := map[string]*models.Usage{
		"func1": {ReflectionRisk: models.RiskLow},
		"func2": {ReflectionRisk: models.RiskMedium},
		"func3": {ReflectionRisk: models.RiskHigh},
		"func4": {ReflectionRisk: models.RiskLow},
		"func5": {ReflectionRisk: models.RiskNone},
	}

	summary := GetSummary(usageMap)

	expected := map[models.RiskLevel]int{
		models.RiskNone:   1,
		models.RiskLow:    2,
		models.RiskMedium: 1,
		models.RiskHigh:   1,
	}

	for risk, expectedCount := range expected {
		if summary[risk] != expectedCount {
			t.Errorf("Expected %d functions with risk %v, got %d", expectedCount, risk, summary[risk])
		}
	}
}

// Integration test
func TestCompleteAnalysisWorkflow(t *testing.T) {
	detector := NewDetector(false)

	// Create test directory structure
	tmpDir, err := createTestDirectory()
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create comprehensive test file
	testContent := `package testpkg

import (
	"reflect"
	"fmt"
)

// HighRiskFunction uses dangerous reflection
func HighRiskFunction() {
	fn := reflect.ValueOf(func(){})
	fn.Call(nil)
}

// MediumRiskFunction uses name-based access
func MediumRiskFunction() {
	typ := reflect.TypeOf("")
	method := typ.MethodByName("String")
	fmt.Println(method)
}

// LowRiskFunction only inspects types
func LowRiskFunction() {
	typ := reflect.TypeOf(42)
	fmt.Println(typ.Name())
}

// NoReflectionFunction doesn't use reflection
func NoReflectionFunction() {
	fmt.Println("Hello, World!")
}

// Method with receiver
func (t TestType) ReflectiveMethod() {
	reflect.ValueOf(t).FieldByName("field")
}

type TestType struct {
	field string
}
`

	testFile := filepath.Join(tmpDir, "comprehensive_test.go")
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Analyze the directory
	usageMap, err := detector.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Verify results
	expectedFunctions := map[string]models.RiskLevel{
		"testpkg.HighRiskFunction":            models.RiskHigh,
		"testpkg.MediumRiskFunction":          models.RiskMedium,
		"testpkg.LowRiskFunction":             models.RiskLow,
		"testpkg.(TestType).ReflectiveMethod": models.RiskMedium,
	}

	// Check that we found the expected functions
	for expectedFunc, expectedRisk := range expectedFunctions {
		found := false
		for funcName, usage := range usageMap {
			if strings.Contains(funcName, strings.Split(expectedFunc, ".")[1]) {
				found = true
				if usage.ReflectionRisk != expectedRisk {
					t.Errorf("Function %s: expected risk %v, got %v", expectedFunc, expectedRisk, usage.ReflectionRisk)
				}
				if !usage.UsesReflection {
					t.Errorf("Function %s: expected to use reflection", expectedFunc)
				}
				if len(usage.ReflectionCalls) == 0 {
					t.Errorf("Function %s: expected to have reflection calls", expectedFunc)
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected function %s not found in results", expectedFunc)
		}
	}

	// Verify NoReflectionFunction is not in the results
	for funcName := range usageMap {
		if strings.Contains(funcName, "NoReflectionFunction") {
			t.Error("NoReflectionFunction should not be in results as it doesn't use reflection")
		}
	}

	// Test summary
	summary := GetSummary(usageMap)
	if summary[models.RiskHigh] < 1 {
		t.Error("Expected at least one high-risk function")
	}
	if summary[models.RiskMedium] < 1 {
		t.Error("Expected at least one medium-risk function")
	}
	if summary[models.RiskLow] < 1 {
		t.Error("Expected at least one low-risk function")
	}
}

// Benchmark tests
func BenchmarkIdentifyReflectionCall(b *testing.B) {
	detector := NewDetector(false)

	code := `package main
import "reflect"
func test() {
	reflect.ValueOf(42).Call(nil)
}`

	file, err := parser.ParseFile(detector.fset, "test.go", code, parser.ParseComments)
	if err != nil {
		b.Fatalf("Failed to parse test code: %v", err)
	}

	var callExpr *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			callExpr = call
			return false
		}
		return true
	})

	if callExpr == nil {
		b.Fatal("No call expression found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.identifyReflectionCall(callExpr)
	}
}

func BenchmarkCalculateRiskLevel(b *testing.B) {
	detector := NewDetector(false)

	calls := []models.ReflectionCall{
		{Method: "reflect.TypeOf"},
		{Method: "Value.MethodByName"},
		{Method: "Value.Call"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.calculateRiskLevel(calls)
	}
}

func BenchmarkHasReflectImport(b *testing.B) {
	detector := NewDetector(false)

	code := `package main

import (
	"fmt"
	"reflect"
	"os"
)

func main() {}`

	file, err := parser.ParseFile(detector.fset, "test.go", code, parser.ParseComments)
	if err != nil {
		b.Fatalf("Failed to parse test code: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.hasReflectImport(file)
	}
}
