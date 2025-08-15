package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFBOMToCache writes an FBOM to the appropriate cache location
func WriteFBOMToCache(fbom interface{}, cacheType, packageName, version string) error {
	// TODO: Add input validation for Phase 3:
	// TODO: 1. Validate that fbom contains required FBOM fields
	// TODO: 2. Validate version format (semver for external, go version for stdlib)
	// TODO: 3. Add size limits for FBOM files to prevent disk space issues

	if packageName == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}

	var targetPath string
	switch cacheType {
	case "external":
		safeName := SanitizePackageName(packageName)
		filename := fmt.Sprintf("%s@%s.fbom.json", safeName, version)
		targetPath = filepath.Join(".", "fboms", "external", filename)
	case "stdlib":
		safeName := SanitizePackageName(packageName)
		filename := fmt.Sprintf("%s.fbom.json", safeName)
		targetPath = filepath.Join(".", "fboms", "stdlib", version, filename)
	default:
		return fmt.Errorf("unsupported cache type: %s", cacheType)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		// TODO: Add defensive permission handling for Phase 2 completion
		return fmt.Errorf("failed to create cache directory %s: %w", dir, err)
	}

	// Marshal FBOM to JSON
	data, err := json.MarshalIndent(fbom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal FBOM: %w", err)
	}

	// TODO: Add atomic write operations for Phase 3:
	// TODO: 1. Write to temporary file first, then rename to prevent corruption
	// TODO: 2. Add file locking to prevent concurrent write conflicts
	// TODO: 3. Add checksum validation for data integrity

	// Write to file
	if err := os.WriteFile(targetPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write FBOM to %s: %w", targetPath, err)
	}

	return nil
}
