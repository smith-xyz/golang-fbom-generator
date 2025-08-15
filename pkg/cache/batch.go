package cache

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DependencySpec represents a dependency to generate an FBOM for
type DependencySpec struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	IsStdlib bool   `json:"is_stdlib"`
}

// GenerationResult represents the result of generating a single FBOM
type GenerationResult struct {
	Dependency DependencySpec `json:"dependency"`
	Success    bool           `json:"success"`
	Error      string         `json:"error,omitempty"`
	FilePath   string         `json:"file_path,omitempty"`
}

// BuildDependencyTree analyzes a Go package and returns all its dependencies
func BuildDependencyTree(packagePath string) ([]DependencySpec, error) {
	// Convert to absolute path and validate
	absPath, err := filepath.Abs(packagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Check if the path exists and contains a go.mod file
	if _, err := os.Stat(filepath.Join(absPath, "go.mod")); os.IsNotExist(err) {
		return nil, fmt.Errorf("no go.mod file found in %s", absPath)
	}

	// Get all module dependencies using go list -m all
	cmd := exec.Command("go", "list", "-m", "all")
	cmd.Dir = absPath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run go list -m all: %w", err)
	}

	// Parse the output to extract dependencies
	var dependencies []DependencySpec
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Skip the first line which is the main module
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Parse module line: "module version"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue // Skip malformed lines
		}

		moduleName := parts[0]
		version := parts[1]

		// Determine if this is a stdlib package
		isStdlib := isStandardLibraryModule(moduleName)

		// For stdlib packages, use Go version instead of module version
		if isStdlib {
			version = getCurrentGoVersion()
		}

		dependencies = append(dependencies, DependencySpec{
			Name:     moduleName,
			Version:  version,
			IsStdlib: isStdlib,
		})
	}

	return dependencies, nil
}

// isStandardLibraryModule checks if a module is part of the Go standard library
func isStandardLibraryModule(moduleName string) bool {
	// Standard library modules don't have dots in their names at the top level
	// However, golang.org/x/* packages are extended standard library
	if strings.HasPrefix(moduleName, "golang.org/x/") {
		return false // These are external dependencies, not stdlib
	}

	// Most stdlib packages don't appear in go.mod, but some extended ones might
	// For practical purposes, if it appears in go.mod, it's likely external
	return false
}

// getCurrentGoVersion returns the current Go version in the format go1.21.0
func getCurrentGoVersion() string {
	return fmt.Sprintf("go%s", strings.TrimPrefix(runtime.Version(), "go"))
}

// GenerateAllFBOMs generates FBOMs for all specified dependencies in parallel
func GenerateAllFBOMs(dependencies []DependencySpec) ([]GenerationResult, error) {
	if len(dependencies) == 0 {
		return []GenerationResult{}, nil
	}

	// Ensure cache directories exist
	if err := EnsureCacheDirectoryExists(); err != nil {
		return nil, fmt.Errorf("failed to ensure cache directories: %w", err)
	}

	// Set up parallel processing
	const maxWorkers = 5 // Limit concurrent operations to avoid overwhelming system
	semaphore := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup
	results := make([]GenerationResult, len(dependencies))

	// Process each dependency in parallel
	for i, dep := range dependencies {
		wg.Add(1)
		go func(index int, dependency DependencySpec) {
			defer wg.Done()

			// Acquire semaphore to limit concurrency
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Generate FBOM for this dependency
			result := generateSingleFBOM(dependency)
			results[index] = result
		}(i, dep)
	}

	wg.Wait()
	return results, nil
}

// GenerateMissingFBOMs generates FBOMs only for dependencies that don't exist in cache
func GenerateMissingFBOMs(dependencies []DependencySpec) ([]GenerationResult, error) {
	// Filter to only missing dependencies
	var missingDeps []DependencySpec

	for _, dep := range dependencies {
		// Check if FBOM already exists and is valid
		linkResult := LinkToCachedFBOM(dep.Name, dep.Version, dep.IsStdlib)
		if !linkResult.CacheHit {
			missingDeps = append(missingDeps, dep)
		}
	}

	// Generate FBOMs only for missing dependencies
	return GenerateAllFBOMs(missingDeps)
}

// generateSingleFBOM generates an FBOM for a single dependency
func generateSingleFBOM(dep DependencySpec) GenerationResult {
	// For stdlib packages, generate a basic FBOM since they're not typically analyzed standalone
	if dep.IsStdlib {
		return generateStdlibFBOM(dep)
	}

	// For external packages, generate an enhanced FBOM
	// TODO: Phase 4.1 - Integrate with real FBOM generation infrastructure
	// TODO: Phase 4.2 - Use existing pkg/callgraph.Generator for package loading
	// TODO: Phase 4.3 - Use existing pkg/output.FBOMGenerator for FBOM creation
	// TODO: This would require creating a temporary package context for analysis

	return generateExternalFBOM(dep)
}

// generateStdlibFBOM generates a basic FBOM for stdlib packages
func generateStdlibFBOM(dep DependencySpec) GenerationResult {
	// Create basic FBOM content for stdlib packages
	// TODO: In Phase 4.2, enhance stdlib FBOM generation with real function analysis
	fbomContent := map[string]interface{}{
		"fbom_version": "0.1.0",
		"name":         dep.Name,
		"version":      dep.Version,
		"generated_at": getCurrentTimestamp(),
		"package_type": "stdlib",
		"functions":    []interface{}{},
		"dependencies": []interface{}{},
	}

	// Write FBOM to cache
	err := WriteFBOMToCache(fbomContent, "stdlib", dep.Name, dep.Version)
	if err != nil {
		return GenerationResult{
			Dependency: dep,
			Success:    false,
			Error:      err.Error(),
		}
	}

	// Determine the file path where it was written
	safeName := SanitizePackageName(dep.Name)
	filename := fmt.Sprintf("%s.fbom.json", safeName)
	filePath := filepath.Join("fboms", "stdlib", dep.Version, filename)

	// Convert to absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath // Fallback to relative path
	}

	return GenerationResult{
		Dependency: dep,
		Success:    true,
		FilePath:   absPath,
	}
}

// generateExternalFBOM generates an enhanced FBOM for external packages
func generateExternalFBOM(dep DependencySpec) GenerationResult {
	// Create enhanced FBOM content for external packages
	// TODO: Phase 4.1 - Replace with real FBOM generation using pkg/callgraph and pkg/output
	fbomContent := map[string]interface{}{
		"fbom_version": "0.1.0",
		"spdx_id":      "SPDXRef-FBOM-ROOT",
		"creation_info": map[string]interface{}{
			"created":         getCurrentTimestamp(),
			"created_by":      "golang-fbom-generator Function Bill of Materials Generator",
			"tool_name":       "golang-fbom-generator",
			"tool_version":    "v1.0.0-beta",
			"creators":        []string{"Tool: golang-fbom-generator"},
			"license_list_id": "MIT",
		},
		"package_info": map[string]interface{}{
			"name":        dep.Name,
			"spdx_id":     fmt.Sprintf("SPDXRef-Package-%s", strings.ReplaceAll(dep.Name, "/", "-")),
			"source_info": "Standalone Package Analysis",
		},
		"functions": []interface{}{}, // TODO: Add real function analysis
		"call_graph": map[string]interface{}{
			"total_functions":     0,
			"used_functions":      0,
			"unused_functions":    0,
			"total_edges":         0,
			"max_depth":           0,
			"avg_depth":           0.0,
			"call_edges":          []interface{}{},
			"reachable_functions": 0,
		},
		"entry_points": []interface{}{}, // TODO: Add real entry point detection
		"dependencies": []interface{}{}, // TODO: Add real dependency analysis
		"security_info": map[string]interface{}{
			"vulnerable_functions":        []interface{}{},
			"security_hotspots":           []interface{}{},
			"critical_paths":              []interface{}{},
			"unreachable_vulnerabilities": []interface{}{},
			"reflection_calls_count":      0,
			"total_cves_found":            0,
			"total_reachable_cves":        0,
		},
	}

	// Write FBOM to cache
	err := WriteFBOMToCache(fbomContent, "external", dep.Name, dep.Version)
	if err != nil {
		return GenerationResult{
			Dependency: dep,
			Success:    false,
			Error:      err.Error(),
		}
	}

	// Determine the file path where it was written
	safeName := SanitizePackageName(dep.Name)
	filename := fmt.Sprintf("%s@%s.fbom.json", safeName, dep.Version)
	filePath := filepath.Join("fboms", "external", filename)

	// Convert to absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath // Fallback to relative path
	}

	return GenerationResult{
		Dependency: dep,
		Success:    true,
		FilePath:   absPath,
	}
}

// getCurrentTimestamp returns the current timestamp in RFC3339 format
func getCurrentTimestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}
