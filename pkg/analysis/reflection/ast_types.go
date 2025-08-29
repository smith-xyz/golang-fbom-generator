package reflection

// Method-level risk patterns - used for AST-based reflection analysis
var highRiskMethods = []string{
	"reflect.Call", "Value.Call", "Value.CallSlice",
	"reflect.MakeFunc", "Value.Set", "Value.SetBool",
	"Value.SetInt", "Value.SetFloat", "Value.SetString",
	"Value.SetBytes", "Value.SetPointer",
}

var mediumRiskMethods = []string{
	"reflect.MethodByName", "Value.MethodByName", "Type.MethodByName",
	"reflect.FieldByName", "Value.FieldByName", "Type.FieldByName",
	"Value.Elem", "Value.Index", "Value.MapIndex",
}
