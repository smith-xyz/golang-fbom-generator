package standalone

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/smith-xyz/golang-fbom-generator/pkg/cache"
)

// PackageSpec represents a parsed package specification
type PackageSpec struct {
	Name     string
	Version  string
	IsStdlib bool
}

// ParsePackageSpec parses a package specification in the format "package[@version]"
func ParsePackageSpec(spec string) (*PackageSpec, error) {
	if spec == "" {
		return nil, fmt.Errorf("package specification cannot be empty")
	}

	// Check for invalid format (multiple @ symbols)
	parts := strings.Split(spec, "@")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid package specification format: %s", spec)
	}

	packageName := parts[0]
	var version string

	if len(parts) == 2 {
		version = parts[1]
	}

	// Determine if it's a stdlib package
	isStdlib := isStandardLibraryPackage(packageName)

	// For stdlib packages, use Go version as version if not specified
	if isStdlib && version == "" {
		goVersion := runtime.Version() // e.g., "go1.21.0"
		version = goVersion
	}

	// For external packages, resolve version if not specified
	if !isStdlib && version == "" {
		resolvedVersion, err := resolveLatestVersion(packageName)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve version for %s: %w", packageName, err)
		}
		version = resolvedVersion
	}

	return &PackageSpec{
		Name:     packageName,
		Version:  version,
		IsStdlib: isStdlib,
	}, nil
}

// GenerateFBOM generates an FBOM for a standalone package
func GenerateFBOM(spec *PackageSpec) error {
	// TODO: This is a placeholder implementation for Phase 2
	// TODO: In Phase 3, reuse existing infrastructure instead of duplicating:
	// TODO: 1. Use existing pkg/callgraph.Generator for package loading (already has packages.Load)
	// TODO: 2. Use existing pkg/output.FBOMGenerator for FBOM creation (already extracts versions)
	// TODO: 3. Use existing config package for stdlib detection (already implemented)
	// TODO: 4. Avoid duplicating go list logic - we already have getModuleVersions()
	// TODO: 5. The existing code already handles all the complexity we're recreating here

	// For now, create a mock FBOM to test the cache writing infrastructure
	mockFBOM := map[string]interface{}{
		"name":         spec.Name,
		"version":      spec.Version,
		"generated_at": "2024-01-01T00:00:00Z",
		"dependencies": []interface{}{}, // TODO: Replace with real dependency analysis
	}

	// Determine cache type
	cacheType := "external"
	version := spec.Version
	if spec.IsStdlib {
		cacheType = "stdlib"
	}

	// Write to cache
	err := cache.WriteFBOMToCache(mockFBOM, cacheType, spec.Name, version)
	if err != nil {
		return fmt.Errorf("failed to write FBOM to cache: %w", err)
	}

	return nil
}

// isStandardLibraryPackage determines if a package is part of the Go standard library
func isStandardLibraryPackage(packageName string) bool {
	// TODO: This is a simplified implementation for Phase 2
	// TODO: In Phase 3, integrate with the existing pkg/config package for proper stdlib detection
	// TODO: Use the config.Config.StdlibPatterns for comprehensive stdlib identification

	// Simple heuristic with known stdlib packages
	stdlibPackages := map[string]bool{
		"fmt":           true,
		"os":            true,
		"net/http":      true,
		"encoding/json": true,
		"strings":       true,
		"strconv":       true,
		"time":          true,
		"io":            true,
		"bytes":         true,
		"path/filepath": true,
	}

	// Check exact match first
	if stdlibPackages[packageName] {
		return true
	}

	// If it contains a domain (e.g., github.com), it's external
	if strings.Contains(packageName, ".") && strings.Contains(packageName, "/") {
		return false
	}

	// TODO: This heuristic is simplified - replace with proper config-based detection
	return !strings.Contains(packageName, "/") || strings.HasPrefix(packageName, "internal/")
}

// resolveLatestVersion resolves the latest version of an external package
func resolveLatestVersion(packageName string) (string, error) {
	// TODO: This basic implementation works for Phase 2, but could be enhanced in Phase 3:
	// TODO: 1. Add better error handling and retry logic
	// TODO: 2. Cache version resolution results to avoid repeated network calls
	// TODO: 3. Support private repositories and custom module proxies
	// TODO: 4. Add timeout handling for network operations

	// Use go list to get the latest version
	cmd := exec.Command("go", "list", "-m", "-versions", packageName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("package not found or unable to resolve: %s", packageName)
	}

	// Parse output to get the latest version
	lines := strings.TrimSpace(string(output))
	parts := strings.Fields(lines)
	if len(parts) < 2 {
		return "", fmt.Errorf("unable to parse version information for %s", packageName)
	}

	// The last version in the list is typically the latest
	versions := parts[1:]
	if len(versions) == 0 {
		return "latest", nil
	}

	return versions[len(versions)-1], nil
}
