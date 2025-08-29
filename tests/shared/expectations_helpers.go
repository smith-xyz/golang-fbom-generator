// Package shared contains common test utilities used across different test packages
package shared

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// LoadExpectations loads test expectations from a YAML file
func LoadExpectations(expectationPath string) (*TestExpectation, error) {
	// Basic path validation to satisfy gosec
	if expectationPath == "" || strings.Contains(expectationPath, "..") {
		return nil, fmt.Errorf("invalid expectation path")
	}
	expectationData, err := os.ReadFile(expectationPath) // #nosec G304 - controlled path for test expectations
	if err != nil {
		return nil, err
	}

	var expectations TestExpectation
	err = yaml.Unmarshal(expectationData, &expectations)
	if err != nil {
		return nil, err
	}

	return &expectations, nil
}

// ParseFBOM parses FBOM JSON output into a map for testing
func ParseFBOM(output []byte) (map[string]interface{}, error) {
	var fbom map[string]interface{}
	err := json.Unmarshal(output, &fbom)
	if err != nil {
		return nil, err
	}
	return fbom, nil
}
