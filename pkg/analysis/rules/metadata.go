package rules

import (
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/smith-xyz/golang-fbom-generator/pkg/models"
)

// ExtractCallSiteInfo extracts file path and line number from call graph edge
func ExtractCallSiteInfo(edge *callgraph.Edge) (string, int) {
	if edge == nil || edge.Site == nil {
		return "", 0
	}

	// Get the position information from the call site instruction
	pos := edge.Site.Pos()
	if !pos.IsValid() {
		return "", 0
	}

	// Get the file set from the caller function to resolve position
	if edge.Caller != nil && edge.Caller.Func != nil &&
		edge.Caller.Func.Prog != nil && edge.Caller.Func.Prog.Fset != nil {
		position := edge.Caller.Func.Prog.Fset.Position(pos)
		return position.Filename, position.Line
	}

	return "", 0
}

// ExtractFilePath extracts the file path from an SSA function
func ExtractFilePath(fn *ssa.Function) string {
	if fn.Prog != nil && fn.Prog.Fset != nil && fn.Pos().IsValid() {
		pos := fn.Prog.Fset.Position(fn.Pos())
		return pos.Filename
	}
	return "unknown"
}

// ExtractStartLine extracts the starting line number of a function
func ExtractStartLine(fn *ssa.Function) int {
	if fn.Prog != nil && fn.Prog.Fset != nil && fn.Pos().IsValid() {
		pos := fn.Prog.Fset.Position(fn.Pos())
		return pos.Line
	}
	return 0
}

// ExtractEndLine extracts the ending line number of a function
func ExtractEndLine(fn *ssa.Function) int {
	if fn.Prog == nil || fn.Prog.Fset == nil {
		return ExtractStartLine(fn) + 1 // fallback to reasonable estimate
	}

	maxLine := ExtractStartLine(fn)

	// Scan through all blocks to find the last valid position
	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}

		// Check instructions in this block
		for _, instr := range block.Instrs {
			if instr == nil {
				continue
			}

			pos := instr.Pos()
			if pos.IsValid() {
				position := fn.Prog.Fset.Position(pos)
				if position.Line > maxLine {
					maxLine = position.Line
				}
			}
		}
	}

	// If we didn't find any instructions with positions, use a reasonable estimate
	if maxLine == ExtractStartLine(fn) {
		maxLine += 1
	}

	return maxLine
}

// ExtractFunctionSignature extracts the signature of a function
func ExtractFunctionSignature(fn *ssa.Function) string {
	if fn.Signature != nil {
		return fn.Signature.String()
	}
	return "unknown"
}

// ExtractParameters extracts parameters from a function
func ExtractParameters(fn *ssa.Function) []models.Parameter {
	var params []models.Parameter
	if fn.Signature != nil && fn.Signature.Params() != nil {
		for i := 0; i < fn.Signature.Params().Len(); i++ {
			param := fn.Signature.Params().At(i)
			params = append(params, models.Parameter{
				Name: param.Name(),
				Type: param.Type().String(),
			})
		}
	}
	return params
}

// ExtractReturnTypes extracts return types from a function
func ExtractReturnTypes(fn *ssa.Function) []string {
	var returns []string
	if fn.Signature != nil && fn.Signature.Results() != nil {
		for i := 0; i < fn.Signature.Results().Len(); i++ {
			result := fn.Signature.Results().At(i)
			returns = append(returns, result.Type().String())
		}
	}
	return returns
}

// isReflectionMethod checks if a function name indicates reflection usage
func IsReflectionMethod(functionName string) bool {
	// note this seems to have more than what was in the original implementation, also this might not belong here
	reflectionMethods := []string{
		"TypeOf", "ValueOf", "Call", "CallSlice", "Method", "MethodByName",
		"Field", "FieldByName", "Elem", "Interface", "Set", "SetInt",
		"SetString", "SetBool", "SetFloat", "SetComplex", "SetBytes",
	}

	for _, method := range reflectionMethods {
		if strings.Contains(functionName, method) {
			return true
		}
	}

	return false
}
