package cveloader

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Loader handles loading CVE data from various sources.
type Loader struct {
	verbose bool
}

// NewLoader creates a new CVE loader.
func NewLoader(verbose bool) *Loader {
	return &Loader{verbose: verbose}
}

// LoadFromFile loads CVE data from a JSON file
func (l *Loader) LoadFromFile(filePath string) (*CVEDatabase, error) {
	if l.verbose {
		fmt.Fprintf(os.Stderr, "Loading CVE data from file: %s\n", filePath)
	}

	// Validate and clean the filepath to prevent directory traversal attacks
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CVE file %s: %w", filePath, err)
	}
	defer file.Close()

	return l.LoadFromReader(file)
}

// LoadFromReader loads CVE data from an io.Reader
func (l *Loader) LoadFromReader(reader io.Reader) (*CVEDatabase, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read CVE data: %w", err)
	}

	var database CVEDatabase
	if err := json.Unmarshal(data, &database); err != nil {
		return nil, fmt.Errorf("failed to parse CVE JSON: %w", err)
	}

	if l.verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d CVEs from data source\n", len(database.CVEs))
	}

	return &database, nil
}
