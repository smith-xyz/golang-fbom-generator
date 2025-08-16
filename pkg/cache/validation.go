package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// CacheValidationResult represents the result of validating a cached FBOM
type CacheValidationResult struct {
	IsValid    bool   `json:"is_valid"`
	FilePath   string `json:"file_path"`
	Checksum   string `json:"checksum"`
	Error      string `json:"error,omitempty"`
	LastCheck  string `json:"last_check"`
	FBOMValid  bool   `json:"fbom_valid"`
	Accessible bool   `json:"accessible"`
}

// CacheLinkingResult represents the result of attempting to link to a cached FBOM
type CacheLinkingResult struct {
	Found            bool                   `json:"found"`
	CacheHit         bool                   `json:"cache_hit"`
	FilePath         string                 `json:"file_path"`
	Checksum         string                 `json:"checksum"`
	ResolutionType   string                 `json:"resolution_type"`
	ValidationResult *CacheValidationResult `json:"validation_result,omitempty"`
	Error            string                 `json:"error,omitempty"`
}

// CacheMissReport represents a cache miss for reporting
type CacheMissReport struct {
	PackageName      string `json:"package_name"`
	Version          string `json:"version"`
	IsStdlib         bool   `json:"is_stdlib"`
	SuggestedCommand string `json:"suggested_command"`
}

// ValidateCachedFBOM validates a cached FBOM file
func ValidateCachedFBOM(filePath string) *CacheValidationResult {
	result := &CacheValidationResult{
		FilePath:   filePath,
		LastCheck:  time.Now().UTC().Format(time.RFC3339),
		IsValid:    false,
		FBOMValid:  false,
		Accessible: false,
	}

	// Check if file exists and is accessible
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		result.Error = fmt.Sprintf("file not accessible: %v", err)
		return result
	}
	result.Accessible = true

	// Check if file size is reasonable (not empty, not too large)
	if fileInfo.Size() == 0 {
		result.Error = "file is empty"
		return result
	}
	if fileInfo.Size() > 100*1024*1024 { // 100MB limit
		result.Error = "file too large (>100MB)"
		return result
	}

	// Read and validate file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}

	// Calculate checksum
	hash := sha256.Sum256(content)
	result.Checksum = fmt.Sprintf("%x", hash)

	// Validate JSON structure
	var fbom map[string]interface{}
	if err := json.Unmarshal(content, &fbom); err != nil {
		result.Error = fmt.Sprintf("invalid JSON: %v", err)
		return result
	}

	// Basic FBOM structure validation
	if err := validateFBOMStructure(fbom); err != nil {
		result.Error = fmt.Sprintf("invalid FBOM structure: %v", err)
		return result
	}
	result.FBOMValid = true

	result.IsValid = true
	return result
}

// validateFBOMStructure validates basic FBOM structure
func validateFBOMStructure(fbom map[string]interface{}) error {
	// Check for required top-level fields
	requiredFields := []string{"fbom_version", "functions", "dependencies"}
	for _, field := range requiredFields {
		if _, exists := fbom[field]; !exists {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Validate FBOM version
	if version, ok := fbom["fbom_version"].(string); ok {
		if !strings.HasPrefix(version, "0.1") {
			return fmt.Errorf("unsupported FBOM version: %s", version)
		}
	} else {
		return fmt.Errorf("fbom_version must be a string")
	}

	return nil
}

// LinkToCachedFBOM attempts to link to a cached FBOM for a given package
func LinkToCachedFBOM(packageName, version string, isStdlib bool) *CacheLinkingResult {
	result := &CacheLinkingResult{
		Found:    false,
		CacheHit: false,
	}

	// Determine cache type and file path
	var filePath string
	var resolutionType string

	if isStdlib {
		filePath, result.Found = LookupStdlibFBOM(packageName, version)
		resolutionType = "cached_stdlib"
	} else {
		filePath, result.Found = LookupExternalFBOM(packageName, version)
		resolutionType = "cached_external"
	}

	result.FilePath = filePath
	result.ResolutionType = resolutionType

	if !result.Found {
		return result
	}

	// Validate the cached file
	validation := ValidateCachedFBOM(filePath)
	result.ValidationResult = validation

	if !validation.IsValid {
		result.Error = fmt.Sprintf("cached file invalid: %s", validation.Error)
		return result
	}

	// Cache hit - file exists and is valid
	result.CacheHit = true
	result.Checksum = validation.Checksum

	return result
}

// GenerateCacheMissReport generates a report of missing cached FBOMs with suggested commands
func GenerateCacheMissReport(misses []CacheMissReport) string {
	if len(misses) == 0 {
		return ""
	}

	var report strings.Builder
	report.WriteString(fmt.Sprintf("\n📋 Cache Miss Report: %d missing FBOMs\n", len(misses)))
	report.WriteString(strings.Repeat("=", 50) + "\n")

	stdlibMisses := 0
	externalMisses := 0

	for _, miss := range misses {
		if miss.IsStdlib {
			stdlibMisses++
		} else {
			externalMisses++
		}
		report.WriteString(fmt.Sprintf("📦 %s", miss.PackageName))
		if !miss.IsStdlib && miss.Version != "" {
			report.WriteString(fmt.Sprintf("@%s", miss.Version))
		}
		report.WriteString("\n")
		report.WriteString(fmt.Sprintf("   💡 %s\n", miss.SuggestedCommand))
	}

	report.WriteString(strings.Repeat("-", 50) + "\n")
	report.WriteString(fmt.Sprintf("📊 Summary: %d external, %d stdlib packages missing\n", externalMisses, stdlibMisses))

	if externalMisses > 0 {
		report.WriteString("💡 Generate all external: Run the suggested commands above\n")
	}
	if stdlibMisses > 0 {
		report.WriteString("💡 Generate all stdlib: Run the suggested commands above\n")
	}

	return report.String()
}

// CreateCacheMissReport creates a cache miss report entry
func CreateCacheMissReport(packageName, version string, isStdlib bool) CacheMissReport {
	var suggestedCommand string
	if isStdlib {
		suggestedCommand = fmt.Sprintf("golang-fbom-generator -package %s", packageName)
	} else if version != "" && version != "unknown" {
		suggestedCommand = fmt.Sprintf("golang-fbom-generator -package %s@%s", packageName, version)
	} else {
		suggestedCommand = fmt.Sprintf("golang-fbom-generator -package %s", packageName)
	}

	return CacheMissReport{
		PackageName:      packageName,
		Version:          version,
		IsStdlib:         isStdlib,
		SuggestedCommand: suggestedCommand,
	}
}

// EnsureCacheDirectoryExists creates the cache directory structure if it doesn't exist
func EnsureCacheDirectoryExists() error {
	structure := DetectCacheStructure()

	// Create base directory
	if err := os.MkdirAll(structure.BasePath, 0755); err != nil {
		return fmt.Errorf("failed to create base cache directory %s: %w", structure.BasePath, err)
	}

	// Create external directory
	if err := os.MkdirAll(structure.ExternalPath, 0755); err != nil {
		return fmt.Errorf("failed to create external cache directory %s: %w", structure.ExternalPath, err)
	}

	// Note: stdlib directories are created on-demand since they're version-specific

	return nil
}
