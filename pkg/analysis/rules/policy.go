package rules

import (
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/config"
	"golang.org/x/tools/go/ssa"
)

// ClassificationPolicy encapsulates all configuration-driven classification decisions
type ClassificationPolicy struct {
	contextConfig         *config.ContextAwareConfig
	baseConfig            *config.Config
	additionalEntryPoints []string
}

// NewClassificationPolicy creates a policy with the given configuration
func NewClassificationPolicy(contextConfig *config.ContextAwareConfig, baseConfig *config.Config) *ClassificationPolicy {
	return &ClassificationPolicy{
		contextConfig:         contextConfig,
		baseConfig:            baseConfig,
		additionalEntryPoints: make([]string, 0),
	}
}

// SetAdditionalEntryPoints configures additional entry point patterns
func (p *ClassificationPolicy) SetAdditionalEntryPoints(entryPoints []string) {
	if entryPoints == nil {
		p.additionalEntryPoints = make([]string, 0)
	} else {
		p.additionalEntryPoints = entryPoints
	}
}

// GetAdditionalEntryPoints returns the configured additional entry points
func (p *ClassificationPolicy) GetAdditionalEntryPoints() []string {
	return p.additionalEntryPoints
}

// IsUserDefinedPackage determines if a package is user-defined using policy rules
func (p *ClassificationPolicy) IsUserDefinedPackage(packagePath string) bool {
	// Use context-aware config first (most accurate)
	if p.contextConfig != nil {
		return p.contextConfig.IsUserDefined(packagePath)
	}

	// Fall back to base config
	if p.baseConfig != nil {
		return p.baseConfig.IsUserDefined(packagePath)
	}

	// Final fallback: deterministic logic
	return IsUserDefinedPackageByPattern(packagePath)
}

// IsStandardLibrary determines if a package is stdlib using policy rules
func (p *ClassificationPolicy) IsStandardLibrary(packagePath string) bool {
	// Use context-aware config first
	if p.contextConfig != nil {
		return p.contextConfig.IsStandardLibrary(packagePath)
	}

	// Fall back to base config
	if p.baseConfig != nil {
		return p.baseConfig.IsStandardLibrary(packagePath)
	}

	// Final fallback: deterministic logic
	return IsStandardLibraryByPattern(packagePath)
}

// IsDependency determines if a package is a dependency using policy rules
func (p *ClassificationPolicy) IsDependency(packagePath string) bool {
	// Use context-aware config first
	if p.contextConfig != nil {
		return p.contextConfig.IsDependency(packagePath)
	}

	// Fall back to base config
	if p.baseConfig != nil {
		return p.baseConfig.IsDependency(packagePath)
	}

	// Final fallback: deterministic logic
	return IsDependencyByPattern(packagePath)
}

// GetRootPackage returns the project root package if available
func (p *ClassificationPolicy) GetRootPackage() string {
	if p.contextConfig != nil {
		return p.contextConfig.GetRootPackage()
	}
	return ""
}

// ==============================================================================
// DETERMINISTIC CLASSIFICATION FUNCTIONS (No Config Dependencies)
// ==============================================================================

// IsUserDefinedPackageByPattern uses deterministic pattern matching (no config)
func IsUserDefinedPackageByPattern(packagePath string) bool {
	// If it's not stdlib and not a known dependency pattern, assume it's user code
	return !IsStandardLibraryByPattern(packagePath) && !IsDependencyByPattern(packagePath)
}

// IsStandardLibraryByPattern uses deterministic stdlib detection (no config)
func IsStandardLibraryByPattern(packagePath string) bool {
	if !strings.Contains(packagePath, ".") {
		return true
	}

	// Known stdlib prefixes
	stdlibPrefixes := []string{
		"archive/", "bufio/", "builtin/", "bytes/", "compress/", "container/",
		"context/", "crypto/", "database/", "debug/", "encoding/", "errors/",
		"expvar/", "flag/", "fmt/", "go/", "hash/", "html/", "image/", "index/",
		"io/", "log/", "math/", "mime/", "net/", "os/", "path/", "plugin/",
		"reflect/", "regexp/", "runtime/", "sort/", "strconv/", "strings/",
		"sync/", "syscall/", "testing/", "text/", "time/", "unicode/", "unsafe/",
	}

	for _, prefix := range stdlibPrefixes {
		if strings.HasPrefix(packagePath+"/", prefix) {
			return true
		}
	}

	return false
}

func IsDependencyByPattern(packagePath string) bool {
	dependencyPrefixes := []string{
		"github.com/", "gitlab.com/", "bitbucket.org/", "golang.org/x/",
		"google.golang.org/", "gopkg.in/", "go.uber.org/", "k8s.io/",
		"sigs.k8s.io/", "cloud.google.com/", "gocloud.dev/",
	}

	for _, prefix := range dependencyPrefixes {
		if strings.HasPrefix(packagePath, prefix) {
			return true
		}
	}

	return false
}

// IsEntryPoint determines if a function is an entry point, considering both standard and additional entry points
func (p *ClassificationPolicy) IsEntryPoint(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}

	// Check standard entry points first
	if fn.Name() == "main" && fn.Pkg != nil && fn.Pkg.Pkg.Name() == "main" {
		return true
	}

	if fn.Name() == "init" {
		return true
	}

	// Check additional entry points
	for _, pattern := range p.additionalEntryPoints {
		if p.matchesEntryPointPattern(fn, pattern) {
			return true
		}
	}

	return false
}

// matchesEntryPointPattern checks if a function matches an entry point pattern
func (p *ClassificationPolicy) matchesEntryPointPattern(fn *ssa.Function, pattern string) bool {
	// Simple pattern matching - could be enhanced with regex or glob patterns
	functionName := fn.Name()

	// Exact match
	if functionName == pattern {
		return true
	}

	// Package.Function match
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		fullName := fn.Pkg.Pkg.Path() + "." + functionName
		if fullName == pattern {
			return true
		}
	}

	// Handle wildcard patterns - use the same logic as MatchesPattern in analysis_helpers
	if strings.Contains(pattern, "*") {
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			// Pattern like "*User*" - contains match
			middle := pattern[1 : len(pattern)-1]
			return strings.Contains(functionName, middle)
		} else if strings.HasPrefix(pattern, "*") {
			// Pattern like "*User" - suffix match
			suffix := pattern[1:]
			return strings.HasSuffix(functionName, suffix)
		} else if strings.HasSuffix(pattern, "*") {
			// Pattern like "handle*" - prefix match
			prefix := pattern[:len(pattern)-1]
			return strings.HasPrefix(functionName, prefix)
		}
	}

	return false
}

// GetHighRiskPackages returns the list of high-risk packages from configuration
func (p *ClassificationPolicy) GetHighRiskPackages() []string {
	if p.baseConfig != nil && p.baseConfig.RiskAssessment.HighRiskPackages != nil {
		return p.baseConfig.RiskAssessment.HighRiskPackages
	}

	// Default high-risk packages if no configuration
	return []string{
		"unsafe", "reflect", "os/exec", "net/http", "crypto", "encoding",
		"syscall", "runtime", "plugin", "database/sql",
	}
}

// GetHighRiskFunctions returns the list of high-risk function patterns from configuration
func (p *ClassificationPolicy) GetHighRiskFunctions() []string {
	if p.baseConfig != nil && p.baseConfig.RiskAssessment.HighRiskFunctions != nil {
		return p.baseConfig.RiskAssessment.HighRiskFunctions
	}

	// Default high-risk function patterns if no configuration
	return []string{
		"Exec", "Command", "Marshal", "Unmarshal", "Decode", "Parse",
		"Call", "CallSlice", "ValueOf", "TypeOf", "New", "Load",
	}
}

// IsHighRiskPackage checks if a package is considered high-risk
func (p *ClassificationPolicy) IsHighRiskPackage(packagePath string) bool {
	highRiskPackages := p.GetHighRiskPackages()
	for _, pkg := range highRiskPackages {
		if strings.Contains(packagePath, pkg) {
			return true
		}
	}
	return false
}

// IsHighRiskFunction checks if a function name matches high-risk patterns
func (p *ClassificationPolicy) IsHighRiskFunction(functionName string) bool {
	highRiskFunctions := p.GetHighRiskFunctions()
	for _, fn := range highRiskFunctions {
		if strings.Contains(functionName, fn) {
			return true
		}
	}
	return false
}

// IsDeserializationFunction checks if a function is related to deserialization (configurable)
func (p *ClassificationPolicy) IsDeserializationFunction(functionName string) bool {
	// Check if we have custom deserialization patterns in config
	if p.baseConfig != nil && p.baseConfig.RiskAssessment.DeserializationPatterns != nil {
		for _, pattern := range p.baseConfig.RiskAssessment.DeserializationPatterns {
			if strings.Contains(functionName, pattern) {
				return true
			}
		}
		return false
	}

	// Default deserialization patterns
	deserializationPatterns := []string{
		"Unmarshal", "Decode", "Parse", "Deserialize", "FromJSON", "FromXML",
	}
	for _, pattern := range deserializationPatterns {
		if strings.Contains(functionName, pattern) {
			return true
		}
	}
	return false
}

// IsNetworkFunction checks if a function is related to networking (configurable)
func (p *ClassificationPolicy) IsNetworkFunction(functionName string) bool {
	// Check if we have custom network patterns in config
	if p.baseConfig != nil && p.baseConfig.RiskAssessment.NetworkPatterns != nil {
		for _, pattern := range p.baseConfig.RiskAssessment.NetworkPatterns {
			if strings.Contains(functionName, pattern) {
				return true
			}
		}
		return false
	}

	// Default network patterns
	networkPatterns := []string{
		"Dial", "Listen", "Accept", "HTTP", "TCP", "UDP", "TLS",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(functionName, pattern) {
			return true
		}
	}
	return false
}
