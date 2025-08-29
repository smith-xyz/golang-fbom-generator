package config

import "strings"

// ContextAwareConfig wraps the base Config with context about the current project
// to enable proper classification of local vs external packages
type ContextAwareConfig struct {
	*Config
	RootPackage string // The root package of the current project being analyzed
}

// NewContextAwareConfig creates a new context-aware config with the specified root package
func NewContextAwareConfig(rootPackage string) (*ContextAwareConfig, error) {
	baseConfig, err := DefaultConfig()
	if err != nil {
		return nil, err
	}

	return &ContextAwareConfig{
		Config:      baseConfig,
		RootPackage: rootPackage,
	}, nil
}

// IsUserDefined checks if a package is user-defined, taking into account the project context.
// A package is user-defined if:
// 1. It's not a standard library package, AND
// 2. It's either the root package or a subpackage of the root package, OR
// 3. It's not a known dependency pattern and not under the root package
func (c *ContextAwareConfig) IsUserDefined(packagePath string) bool {
	// Check if it's standard library first
	if c.IsStandardLibrary(packagePath) {
		return false
	}

	// If we have a root package defined, check if this package belongs to our project
	if c.RootPackage != "" {
		if c.isLocalProjectPackage(packagePath) {
			return true
		}
	}

	// If we have a root package set but this package is not local, it's external (dependency)
	if c.RootPackage != "" {
		return false
	}

	// Fall back to base config logic when no root package is set
	return c.Config.IsUserDefined(packagePath)
}

// IsDependency checks if a package is a third-party dependency, excluding local project packages.
// A package is a dependency if:
// 1. It matches dependency patterns (like github.com/, golang.org/x/, etc.), AND
// 2. It's NOT part of our local project (not root package or subpackage)
func (c *ContextAwareConfig) IsDependency(packagePath string) bool {
	// If this is a local project package, it's not a dependency
	if c.RootPackage != "" && c.isLocalProjectPackage(packagePath) {
		return false
	}

	// Use base dependency logic for external packages
	return c.Config.IsDependency(packagePath)
}

// isLocalProjectPackage determines if a package path belongs to the local project
func (c *ContextAwareConfig) isLocalProjectPackage(packagePath string) bool {
	if c.RootPackage == "" {
		return false
	}

	// Exact match with root package
	if packagePath == c.RootPackage {
		return true
	}

	// Subpackage of root package (must have / separator to avoid false positives)
	if strings.HasPrefix(packagePath, c.RootPackage+"/") {
		return true
	}

	return false
}

// GetRootPackage returns the root package for this context
func (c *ContextAwareConfig) GetRootPackage() string {
	return c.RootPackage
}

// SetRootPackage updates the root package for this context
func (c *ContextAwareConfig) SetRootPackage(rootPackage string) {
	c.RootPackage = rootPackage
}
