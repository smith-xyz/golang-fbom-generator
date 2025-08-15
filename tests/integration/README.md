# Integration Tests

This directory contains integration tests that execute the simplified golang-fbom-generator binary directly and validate the output against expected results for **local package analysis**.

## Running Tests

```bash
cd tests/integration && go test -v
```

## Test Structure

Each test case has:
- A directory under `testcases/` containing the Go code to analyze
- An `expected.yaml` file defining expected results
- The integration test runner validates the actual binary output against expectations

## Expected YAML Format

```yaml
# Test metadata
test_name: "Basic external dependency tracking"
description: "Test that gin and yaml dependencies are properly tracked"

# Expected results
expectations:
  dependencies:
    - name: "github.com/gin-gonic/gin"
      called_functions:
        - function_name: "Default"
          call_context: "direct"
        - function_name: "GET" 
          call_context: "direct"
        - function_name: "POST"
          call_context: "direct"
        - function_name: "Run"
          call_context: "direct"
        - function_name: "JSON"
          call_context: "callback"
    - name: "gopkg.in/yaml.v2"
      called_functions:
        - function_name: "Unmarshal"
          call_context: "direct"
          call_sites_contain: "loadConfig"

  dependency_clusters:
    - name: "github.com/gin-gonic/gin"
      min_entry_points: 5
      min_blast_radius: 50
      entry_points_contain:
        - function: "Default"
        - function: "GET"
    - name: "gopkg.in/yaml.v2"
      min_entry_points: 1
      min_blast_radius: 100
      entry_points_contain:
        - function: "Unmarshal"
          called_from_contains: ["loadConfig"]

  functions:
    - name: "loadConfig"
      has_external_calls: true
      stdlib_calls_contain: ["fmt.Printf"]
    
  security_info:
    min_reflection_calls: 0
    min_external_dependencies: 2

# Optional: specific assertions to check
assertions:
  - type: "dependency_exists"
    name: "github.com/gin-gonic/gin"
  - type: "function_called"
    dependency: "github.com/gin-gonic/gin"
    function: "Default"
  - type: "call_context"
    dependency: "github.com/gin-gonic/gin" 
    function: "JSON"
    expected_context: "callback"
```

## Dependency Clustering Tests

The integration tests include comprehensive validation of the dependency clustering feature:

### TestDependencyClusteringIntegration
- Validates the `dependency_clusters` section structure
- Checks entry point identification and `called_from` relationships
- Verifies blast radius calculations
- Tests cluster function grouping

### Expected Clustering Properties
- **min_entry_points**: Minimum number of entry points expected for a dependency
- **min_blast_radius**: Minimum total count of reachable functions within the dependency
- **entry_points_contain**: Specific entry points that must be present
- **called_from_contains**: User functions that should be calling specific dependency functions

This ensures the clustering provides accurate attack surface analysis for security assessment.

## Running Tests

```bash
go test ./tests/integration/...
```
