package config

import (
	"testing"
)

func TestContextAwareConfig(t *testing.T) {
	tests := []struct {
		name            string
		rootPackage     string
		packagePath     string
		expectedUserDef bool
		expectedDep     bool
		description     string
	}{
		// Local GitHub project scenarios
		{
			name:            "Local GitHub project root",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/example/myproject",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "Root package should be user-defined",
		},
		{
			name:            "Local GitHub project subpackage",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/example/myproject/pkg/api",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "Subpackage should be user-defined",
		},
		{
			name:            "Local GitHub project cmd",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/example/myproject/cmd/cli",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "Command package should be user-defined",
		},
		{
			name:            "Local GitHub project internal",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/example/myproject/internal/helpers",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "Internal package under project should be user-defined",
		},

		// External GitHub dependencies
		{
			name:            "External GitHub dependency",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/gin-gonic/gin",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "External GitHub package should be dependency",
		},
		{
			name:            "External GitHub dependency subpackage",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/gin-gonic/gin/binding",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "External subpackage should be dependency",
		},

		// Other external dependencies
		{
			name:            "Golang.org dependency",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "golang.org/x/tools/cmd/goimports",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "Golang.org package should be dependency",
		},
		{
			name:            "K8s.io dependency",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "k8s.io/apimachinery/pkg/runtime",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "K8s.io package should be dependency",
		},

		// Standard library
		{
			name:            "Standard library package",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "fmt",
			expectedUserDef: false,
			expectedDep:     false,
			description:     "Standard library should not be user-defined or dependency",
		},
		{
			name:            "Standard library subpackage",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "net/http",
			expectedUserDef: false,
			expectedDep:     false,
			description:     "Standard library subpackage should not be user-defined or dependency",
		},

		// Non-GitHub local projects
		{
			name:            "Custom domain local project",
			rootPackage:     "mycompany.com/myproject",
			packagePath:     "mycompany.com/myproject",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "Custom domain root should be user-defined",
		},
		{
			name:            "Custom domain local subpackage",
			rootPackage:     "mycompany.com/myproject",
			packagePath:     "mycompany.com/myproject/internal/api",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "Custom domain subpackage should be user-defined",
		},

		// Edge cases
		{
			name:            "Similar but different GitHub project",
			rootPackage:     "github.com/example/myproject",
			packagePath:     "github.com/example/myproject-fork",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "Similar-named external project should be dependency",
		},
		{
			name:            "Parent path of local project",
			rootPackage:     "github.com/example/myproject/submodule",
			packagePath:     "github.com/example/myproject",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "Parent path should be dependency when submodule is root",
		},

		// K8s.io as local project
		{
			name:            "K8s.io as local project root",
			rootPackage:     "k8s.io/kubernetes",
			packagePath:     "k8s.io/kubernetes",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "K8s.io project as local root should be user-defined",
		},
		{
			name:            "K8s.io as local project subpackage",
			rootPackage:     "k8s.io/kubernetes",
			packagePath:     "k8s.io/kubernetes/pkg/scheduler",
			expectedUserDef: true,
			expectedDep:     false,
			description:     "K8s.io project subpackage should be user-defined",
		},
		{
			name:            "K8s.io external when different local project",
			rootPackage:     "k8s.io/kubernetes",
			packagePath:     "k8s.io/apimachinery/pkg/runtime",
			expectedUserDef: false,
			expectedDep:     true,
			description:     "Different k8s.io project should be dependency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewContextAwareConfig(tt.rootPackage)
			if err != nil {
				t.Fatalf("Failed to create context-aware config: %v", err)
			}

			actualUserDef := config.IsUserDefined(tt.packagePath)
			actualDep := config.IsDependency(tt.packagePath)

			t.Logf("Testing: %s", tt.description)
			t.Logf("Root: %s, Package: %s", tt.rootPackage, tt.packagePath)
			t.Logf("Result - UserDefined: %v, Dependency: %v", actualUserDef, actualDep)
			t.Logf("Expected - UserDefined: %v, Dependency: %v", tt.expectedUserDef, tt.expectedDep)

			if actualUserDef != tt.expectedUserDef {
				t.Errorf("IsUserDefined(%q) = %v, want %v", tt.packagePath, actualUserDef, tt.expectedUserDef)
			}

			if actualDep != tt.expectedDep {
				t.Errorf("IsDependency(%q) = %v, want %v", tt.packagePath, actualDep, tt.expectedDep)
			}
		})
	}
}

func TestContextAwareConfigRealWorldScenarios(t *testing.T) {
	scenarios := []struct {
		name        string
		rootPackage string
		testCases   []struct {
			packagePath     string
			expectedUserDef bool
			expectedDep     bool
			description     string
		}
	}{
		{
			name:        "HyperShift project",
			rootPackage: "github.com/openshift/hypershift",
			testCases: []struct {
				packagePath     string
				expectedUserDef bool
				expectedDep     bool
				description     string
			}{
				{
					packagePath:     "github.com/openshift/hypershift",
					expectedUserDef: true,
					expectedDep:     false,
					description:     "HyperShift root should be user-defined",
				},
				{
					packagePath:     "github.com/openshift/hypershift/cmd/install",
					expectedUserDef: true,
					expectedDep:     false,
					description:     "HyperShift command should be user-defined",
				},
				{
					packagePath:     "github.com/openshift/hypershift/pkg/api",
					expectedUserDef: true,
					expectedDep:     false,
					description:     "HyperShift package should be user-defined",
				},
				{
					packagePath:     "github.com/gin-gonic/gin",
					expectedUserDef: false,
					expectedDep:     true,
					description:     "External dependency should remain dependency",
				},
			},
		},
		{
			name:        "Multi-component project",
			rootPackage: "github.com/example/multi-component-project",
			testCases: []struct {
				packagePath     string
				expectedUserDef bool
				expectedDep     bool
				description     string
			}{
				{
					packagePath:     "github.com/example/multi-component-project",
					expectedUserDef: true,
					expectedDep:     false,
					description:     "Multi-component root should be user-defined",
				},
				{
					packagePath:     "github.com/example/multi-component-project/pkg/api",
					expectedUserDef: true,
					expectedDep:     false,
					description:     "Multi-component API package should be user-defined",
				},
				{
					packagePath:     "github.com/example/multi-component-project/cmd/cli",
					expectedUserDef: true,
					expectedDep:     false,
					description:     "Multi-component CLI should be user-defined",
				},
				{
					packagePath:     "github.com/spf13/cobra",
					expectedUserDef: false,
					expectedDep:     true,
					description:     "Cobra dependency should remain dependency",
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			config, err := NewContextAwareConfig(scenario.rootPackage)
			if err != nil {
				t.Fatalf("Failed to create context-aware config: %v", err)
			}

			for _, tc := range scenario.testCases {
				t.Run(tc.description, func(t *testing.T) {
					actualUserDef := config.IsUserDefined(tc.packagePath)
					actualDep := config.IsDependency(tc.packagePath)

					if actualUserDef != tc.expectedUserDef {
						t.Errorf("IsUserDefined(%q) = %v, want %v", tc.packagePath, actualUserDef, tc.expectedUserDef)
					}

					if actualDep != tc.expectedDep {
						t.Errorf("IsDependency(%q) = %v, want %v", tc.packagePath, actualDep, tc.expectedDep)
					}

					t.Logf("✓ %s: %s correctly classified (UserDefined=%v, Dependency=%v)",
						scenario.name, tc.packagePath, actualUserDef, actualDep)
				})
			}
		})
	}
}

func TestContextAwareConfigEdgeCases(t *testing.T) {
	t.Run("Empty root package", func(t *testing.T) {
		config, err := NewContextAwareConfig("")
		if err != nil {
			t.Fatalf("Failed to create context-aware config: %v", err)
		}

		// Should fall back to base behavior when no root package is set
		testCases := []struct {
			packagePath     string
			expectedUserDef bool
			expectedDep     bool
		}{
			{"github.com/user/repo", false, true},  // Should be dependency (base behavior)
			{"mycompany.com/project", true, false}, // Should be user-defined (base behavior)
			{"fmt", false, false},                  // Should be stdlib (base behavior)
		}

		for _, tc := range testCases {
			actualUserDef := config.IsUserDefined(tc.packagePath)
			actualDep := config.IsDependency(tc.packagePath)

			if actualUserDef != tc.expectedUserDef {
				t.Errorf("IsUserDefined(%q) with empty root = %v, want %v", tc.packagePath, actualUserDef, tc.expectedUserDef)
			}
			if actualDep != tc.expectedDep {
				t.Errorf("IsDependency(%q) with empty root = %v, want %v", tc.packagePath, actualDep, tc.expectedDep)
			}
		}
	})

	t.Run("Root package setter/getter", func(t *testing.T) {
		config, err := NewContextAwareConfig("initial/package")
		if err != nil {
			t.Fatalf("Failed to create context-aware config: %v", err)
		}

		if config.GetRootPackage() != "initial/package" {
			t.Errorf("GetRootPackage() = %q, want %q", config.GetRootPackage(), "initial/package")
		}

		config.SetRootPackage("new/package")
		if config.GetRootPackage() != "new/package" {
			t.Errorf("GetRootPackage() after SetRootPackage() = %q, want %q", config.GetRootPackage(), "new/package")
		}

		// Test that the new root package affects classification
		if !config.IsUserDefined("new/package/subpkg") {
			t.Error("Expected subpackage of new root to be user-defined")
		}
		if config.IsUserDefined("initial/package/subpkg") {
			t.Error("Expected subpackage of old root to not be user-defined after change")
		}
	})
}
