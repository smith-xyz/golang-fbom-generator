package rules

import (
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
)

// Classifier provides clean package and function classification
type Classifier struct {
	policy *ClassificationPolicy
}

// NewClassifier creates a new classifier with the given configuration
func NewClassifier(contextConfig *config.ContextAwareConfig, baseConfig *config.Config) *Classifier {
	return &Classifier{
		policy: NewClassificationPolicy(contextConfig, baseConfig),
	}
}

// IsUserDefinedFunction determines if a function is user-defined (vs stdlib/dependency)
func (c *Classifier) IsUserDefinedFunction(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	return c.policy.IsUserDefinedPackage(fn.Pkg.Pkg.Path())
}

// IsStandardLibraryPackage checks if a package is part of Go's standard library
func (c *Classifier) IsStandardLibraryPackage(packagePath string) bool {
	return c.policy.IsStandardLibrary(packagePath)
}

// IsDependencyPackage checks if a package is an external dependency
func (c *Classifier) IsDependencyPackage(packagePath string) bool {
	return c.policy.IsDependency(packagePath)
}

// IsUserDefinedPackage checks if a package is user-defined
func (c *Classifier) IsUserDefinedPackage(packagePath string) bool {
	return c.policy.IsUserDefinedPackage(packagePath)
}

// IsDependencyOrStdlib checks if a package is either dependency or stdlib
func (c *Classifier) IsDependencyOrStdlib(packagePath string) bool {
	return c.policy.IsStandardLibrary(packagePath) || c.policy.IsDependency(packagePath)
}

// GetRootPackage returns the project root package if available
func (c *Classifier) GetRootPackage() string {
	return c.policy.GetRootPackage()
}

// SetAdditionalEntryPoints configures additional entry point patterns
func (c *Classifier) SetAdditionalEntryPoints(entryPoints []string) {
	c.policy.SetAdditionalEntryPoints(entryPoints)
}

// GetAdditionalEntryPoints returns the configured additional entry points
func (c *Classifier) GetAdditionalEntryPoints() []string {
	return c.policy.GetAdditionalEntryPoints()
}

// IsEntryPoint determines if a function is an entry point
func (c *Classifier) IsEntryPoint(fn *ssa.Function) bool {
	return c.policy.IsEntryPoint(fn)
}

// GetHighRiskPackages returns the list of high-risk packages from configuration
func (c *Classifier) GetHighRiskPackages() []string {
	return c.policy.GetHighRiskPackages()
}

// GetHighRiskFunctions returns the list of high-risk function patterns from configuration
func (c *Classifier) GetHighRiskFunctions() []string {
	return c.policy.GetHighRiskFunctions()
}

// IsHighRiskPackage checks if a package is considered high-risk
func (c *Classifier) IsHighRiskPackage(packagePath string) bool {
	return c.policy.IsHighRiskPackage(packagePath)
}

// IsHighRiskFunction checks if a function name matches high-risk patterns
func (c *Classifier) IsHighRiskFunction(functionName string) bool {
	return c.policy.IsHighRiskFunction(functionName)
}

// IsDeserializationFunction checks if a function is related to deserialization (configurable)
func (c *Classifier) IsDeserializationFunction(functionName string) bool {
	return c.policy.IsDeserializationFunction(functionName)
}

// IsNetworkFunction checks if a function is related to networking (configurable)
func (c *Classifier) IsNetworkFunction(functionName string) bool {
	return c.policy.IsNetworkFunction(functionName)
}

// IsUserDefinedFunctionByQualifiedName checks if a function belongs to user-defined code
func (c *Classifier) IsUserDefinedFunctionByQualifiedName(qualifiedName string) bool {
	pkg := c.ExtractPackageFromFunction(qualifiedName)
	return c.IsUserDefinedPackage(pkg)
}

// ExtractPackageFromFunction extracts package name from qualified function name
func (c *Classifier) ExtractPackageFromFunction(qualifiedName string) string {
	// Handle method receivers like "(main.MyStruct).Method" -> "main"
	if strings.HasPrefix(qualifiedName, "(") {
		if endParen := strings.Index(qualifiedName, ")"); endParen > 0 {
			receiverType := qualifiedName[1:endParen]
			if dot := strings.LastIndex(receiverType, "."); dot >= 0 {
				return receiverType[:dot]
			}
			return receiverType
		}
	}

	// Handle regular functions like "main.Function" -> "main"
	if dot := strings.LastIndex(qualifiedName, "."); dot >= 0 {
		return qualifiedName[:dot]
	}

	return qualifiedName
}
