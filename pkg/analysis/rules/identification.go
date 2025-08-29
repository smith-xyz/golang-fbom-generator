package rules

import (
	"fmt"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// GenerateFunctionID creates a consistent function identifier
func GenerateFunctionID(fn *ssa.Function) string {
	if fn.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Path(), fn.Name())
	}
	return fn.Name()
}

// GenerateSPDXId creates SPDX-compliant identifiers
func GenerateSPDXId(prefix string, fn *ssa.Function) string {
	return fmt.Sprintf("%s-%s", prefix, GenerateFunctionID(fn))
}

// FormatFunctionCall formats function calls
func FormatFunctionCall(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		packagePath := fn.Pkg.Pkg.Path()
		return fmt.Sprintf("%s.%s", packagePath, fn.Name())
	}
	return fn.Name()
}

// InferVisibility determines if a function is public or private
func InferVisibility(fn *ssa.Function) string {
	if IsFunctionExported(fn) {
		return "public"
	}
	return "private"
}

// InferFunctionType determines the type/category of a function
func InferFunctionType(fn *ssa.Function) string {
	name := fn.Name()
	switch {
	case name == "main":
		return "main"
	case name == "init":
		return "init"
	case fn.Parent() != nil:
		return "closure"
	case fn.Signature != nil && fn.Signature.Recv() != nil:
		return "method"
	default:
		return "regular"
	}
}

// IsFunctionExported checks if a function is exported (public in Go)
func IsFunctionExported(fn *ssa.Function) bool {
	return len(fn.Name()) > 0 && fn.Name()[0] >= 'A' && fn.Name()[0] <= 'Z'
}

// GetPackageName extracts package name from a function (utility)
func GetPackageName(fn *ssa.Function) string {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return ""
	}
	return fn.Pkg.Pkg.Path()
}

// GetFunctionName extracts function name from SSA function (utility)
func GetFunctionName(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	return fn.Name()
}

// IsPointer checks if a type is a pointer type
func IsPointer(t types.Type) bool {
	_, ok := t.(*types.Pointer)
	return ok
}

// extractPackageFromCall extracts package name from a formatted call like "github.com/pkg/a.functionName"
func ExtractPackageFromCall(call string) string {
	lastDot := strings.LastIndex(call, ".")
	if lastDot == -1 {
		return ""
	}
	return call[:lastDot]
}

// extractFunctionFromCall extracts function name from a formatted call like "github.com/pkg/a.functionName"
func ExtractFunctionFromCall(call string) string {
	lastDot := strings.LastIndex(call, ".")
	if lastDot == -1 {
		return call
	}
	return call[lastDot+1:]
}
