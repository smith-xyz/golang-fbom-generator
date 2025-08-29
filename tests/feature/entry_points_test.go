package feature

import (
	"os/exec"
	"testing"

	"golang-fbom-generator/tests/shared"
)

// TestEntryPointFunctionality tests entry point pattern matching and configuration
func TestEntryPointFunctionality(t *testing.T) {
	binaryPath := shared.GetBinaryPath(t)

	examplePath := "../../examples/multi-entrypoint/cmd/app1"

	tests := []struct {
		name                  string
		entryPointsFlag       string
		expectedEntryPoints   []string
		unexpectedEntryPoints []string
	}{
		{
			name:                  "Default entry points only",
			entryPointsFlag:       "",
			expectedEntryPoints:   []string{"main", "init"},
			unexpectedEntryPoints: []string{"handleGetUsers", "handleCreateUser", "handleHealthCheck", "setupRoutes"},
		},
		{
			name:                  "Specific HTTP handlers as entry points",
			entryPointsFlag:       "handleGetUsers,handleCreateUser,handleHealthCheck",
			expectedEntryPoints:   []string{"main", "init", "handleGetUsers", "handleCreateUser", "handleHealthCheck"},
			unexpectedEntryPoints: []string{"setupRoutes", "handleUpdateUser", "handleDeleteUser"},
		},
		{
			name:                  "All HTTP handlers as entry points",
			entryPointsFlag:       "handle*",
			expectedEntryPoints:   []string{"main", "init", "handleGetUsers", "handleCreateUser", "handleHealthCheck", "handleUpdateUser", "handleDeleteUser", "handleGetUser"},
			unexpectedEntryPoints: []string{"setupRoutes"},
		},
		{
			name:                  "Wildcard pattern - handle prefix",
			entryPointsFlag:       "handle*",
			expectedEntryPoints:   []string{"main", "init", "handleGetUsers", "handleHealthCheck"},
			unexpectedEntryPoints: []string{"setupRoutes"},
		},
		{
			name:                  "Wildcard pattern - suffix matching",
			entryPointsFlag:       "*User",
			expectedEntryPoints:   []string{"main", "init", "handleCreateUser", "handleUpdateUser", "handleDeleteUser", "handleGetUser"},
			unexpectedEntryPoints: []string{"handleGetUsers", "handleHealthCheck", "setupRoutes"},
		},
		{
			name:                  "Multiple specific handlers",
			entryPointsFlag:       "setupRoutes,handleHealthCheck",
			expectedEntryPoints:   []string{"main", "init", "setupRoutes", "handleHealthCheck"},
			unexpectedEntryPoints: []string{"handleGetUsers", "handleCreateUser"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build command with entry points flag
			args := []string{"-package", "."}
			if tt.entryPointsFlag != "" {
				args = append(args, "-entry-points", tt.entryPointsFlag)
			}

			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = examplePath

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to run command: %v\nOutput: %s", err, output)
			}

			// Parse FBOM output
			fbom, err := shared.ParseFBOM(output)
			if err != nil {
				t.Fatalf("Failed to parse FBOM: %v", err)
			}

			// Extract entry points from FBOM
			entryPoints, ok := fbom["entry_points"].([]interface{})
			if !ok {
				t.Fatal("Missing entry_points in FBOM")
			}

			// Convert to strings for easier comparison
			foundEntryPoints := make([]string, 0, len(entryPoints))
			for _, ep := range entryPoints {
				if epObj, ok := ep.(map[string]interface{}); ok {
					if name, ok := epObj["name"].(string); ok {
						foundEntryPoints = append(foundEntryPoints, name)
					}
				}
			}

			// Check for expected entry points
			for _, expected := range tt.expectedEntryPoints {
				found := false
				for _, actual := range foundEntryPoints {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected entry point '%s' not found. Found entry points: %v", expected, foundEntryPoints)
				}
			}

			// Check for unexpected entry points
			for _, unexpected := range tt.unexpectedEntryPoints {
				for _, actual := range foundEntryPoints {
					if actual == unexpected {
						t.Errorf("Unexpected entry point '%s' found in results", unexpected)
					}
				}
			}
		})
	}
}

// TestEntryPointPatternErrors tests error handling for invalid entry point patterns
func TestEntryPointPatternErrors(t *testing.T) {
	binaryPath := shared.GetBinaryPath(t)

	examplePath := "../../examples/hello-world"

	tests := []struct {
		name           string
		entryPoints    string
		expectError    bool
		expectedToPass bool
	}{
		{
			name:           "Valid patterns should succeed",
			entryPoints:    "main,handle*,setup*",
			expectError:    false,
			expectedToPass: true,
		},
		{
			name:           "Empty patterns should succeed",
			entryPoints:    "",
			expectError:    false,
			expectedToPass: true,
		},
		{
			name:           "Patterns with spaces should be trimmed and succeed",
			entryPoints:    " main , handle* , setup* ",
			expectError:    false,
			expectedToPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"-package", "."}
			if tt.entryPoints != "" {
				args = append(args, "-entry-points", tt.entryPoints)
			}

			cmd := exec.Command(binaryPath, args...)
			cmd.Dir = examplePath

			output, err := cmd.CombinedOutput()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but command succeeded")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v\nOutput: %s", err, output)
				}

				if tt.expectedToPass {
					// Try to parse the FBOM to ensure it's valid
					_, parseErr := shared.ParseFBOM(output)
					if parseErr != nil {
						t.Errorf("Failed to parse FBOM output: %v", parseErr)
					}
				}
			}
		})
	}
}
