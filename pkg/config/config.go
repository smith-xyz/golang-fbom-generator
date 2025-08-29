package config

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Embedded default configuration
// Use 'go generate ./pkg/config' to update from root config.toml
//
//go:generate cp ../../config.toml default_config.toml
//go:embed default_config.toml
var embeddedConfigData []byte

// Config holds the application configuration.
type Config struct {
	Packages       PackageConfig        `toml:"packages"`
	RiskAssessment RiskAssessmentConfig `toml:"risk_assessment"`
}

// PackageConfig holds package classification patterns.
type PackageConfig struct {
	StdlibPatterns     []string `toml:"stdlib_patterns"`
	StdlibPrefixes     []string `toml:"stdlib_prefixes"`
	DependencyPatterns []string `toml:"dependency_patterns"`
	VendorPatterns     []string `toml:"vendor_patterns"`
}

// RiskAssessmentConfig holds configuration for security risk assessment.
type RiskAssessmentConfig struct {
	HighRiskPackages        []string `toml:"high_risk_packages"`
	HighRiskFunctions       []string `toml:"high_risk_functions"`
	DeserializationPatterns []string `toml:"deserialization_patterns"`
	NetworkPatterns         []string `toml:"network_patterns"`
}

// DefaultConfig returns the default configuration with optional local overrides.
// It always starts with the embedded config, then optionally merges with local config.toml.
func DefaultConfig() (*Config, error) {
	// Start with embedded default configuration
	var config Config
	if err := toml.Unmarshal(embeddedConfigData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse embedded config: %w", err)
	}

	// Look for local config.toml to override defaults
	localConfigPaths := []string{
		"config.toml",       // Current directory (project root when running binary)
		"../config.toml",    // Parent directory (for tests in subdirs)
		"../../config.toml", // Two levels up (for tests in pkg/*/test)
	}

	for _, path := range localConfigPaths {
		if _, err := os.Stat(path); err == nil {
			// Found a local config file - merge it with defaults
			localConfig, err := LoadFromFile(path)
			if err != nil {
				// Log warning but continue with embedded config
				fmt.Fprintf(os.Stderr, "Warning: failed to load local config %s: %v\n", path, err)
				break
			}
			// For now, we'll do a simple override (local completely replaces embedded)
			// In the future, we could implement smarter merging
			return localConfig, nil
		}
	}

	// Return embedded config if no local override found
	return &config, nil
}

// LoadFromFile loads configuration from a TOML file.
func LoadFromFile(filepath string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", filepath, err)
	}
	return &config, nil
}

// IsStandardLibrary checks if a package is from the Go standard library.
func (c *Config) IsStandardLibrary(packagePath string) bool {
	// Check against standard library package patterns
	for _, pattern := range c.Packages.StdlibPatterns {
		if packagePath == pattern || strings.HasPrefix(packagePath, pattern+"/") {
			return true
		}
	}

	// Check against standard library prefixes
	for _, prefix := range c.Packages.StdlibPrefixes {
		if strings.HasPrefix(packagePath, prefix) {
			return true
		}
	}

	return false
}

// IsDependency checks if a package is a third-party dependency.
func (c *Config) IsDependency(packagePath string) bool {
	// Check vendor patterns first
	for _, pattern := range c.Packages.VendorPatterns {
		if strings.HasPrefix(packagePath, pattern) {
			return true
		}
	}

	// Check dependency hosting patterns
	for _, pattern := range c.Packages.DependencyPatterns {
		if strings.HasPrefix(packagePath, pattern) {
			return true
		}
	}

	return false
}

// IsUserDefined checks if a package is user-defined (not stdlib or dependency).
func (c *Config) IsUserDefined(packagePath string) bool {
	return !c.IsStandardLibrary(packagePath) && !c.IsDependency(packagePath)
}
