# golang-fbom-generator

A security-focused Function Bill of Materials (FBOM) generator for Go applications that provides comprehensive static analysis to identify potential vulnerabilities and security risks. This is an experimental project aiming mostly for a standard to follow for collecting a complete tree of functions for a codebase (here applied to golang projects).

## Overview

The golang-fbom-generator analyzes **local Go projects** to create detailed security reports that include:

- **Function Inventory**: All user-defined functions with their call relationships
- **Dependency Analysis**: External libraries and their usage patterns
- **Dependency Clustering**: Groups reachable functions by dependency with blast radius analysis
- **Entry Point Mapping**: Application entry points and reachability analysis
- **Security Assessment**: CVE mapping, vulnerability reachability analysis, and risk scoring
- **Advanced Reflection Analysis**: Multi-layered reflection detection with user-focused vulnerability mapping
- **Attack Chain Visualization**: Clear paths from user code to vulnerable functions through reflection
- **Call Graph Analysis**: Function call relationships using proven Go toolchain algorithms
- **Flexible Output**: Console output (default) or automatic file generation with `-o` flag

## Quick Start

### Installation

```bash
go install github.com/smith-xyz/golang-fbom-generator@latest
```

### Basic Usage

```bash
# Analyze current directory (outputs to stdout)
golang-fbom-generator -package .

# Analyze and save to file
golang-fbom-generator -package . -o

# Analyze with live CVE scanning
golang-fbom-generator -package . -live-cve-scan -o

# Analyze a subdirectory
golang-fbom-generator -package ./examples/hello-world

# Analyze with CVE data and save to file
golang-fbom-generator -package . -cve cve-data.json -o

# Deeper analysis with custom attack path configuration
golang-fbom-generator -package . -live-cve-scan -max-depth 5 -max-edges 10 -o

# Verbose output
golang-fbom-generator -package . -v

# Auto-discover all main functions for multi-component projects
golang-fbom-generator --auto-discover -v -o
```

### Command Line Options

- `-package`: **Local Go package path only** - supports relative paths (`.`, `./subdir`)
- `-cve`: Path to CVE data file (JSON) - optional
- `-live-cve-scan`: Perform live CVE scanning using Go's vulnerability database
- `-o`: Write output to `<package-name>.fbom.json` file instead of stdout
- `-v`: Verbose output
- `-entry-points`: Comma-separated list of additional entry point patterns
- `-algo`: Call graph algorithm to use: `rta`, `cha`, `static`, `vta` (default: "rta")
- `-auto-discover`: Auto-discover all main functions for unified multi-component analysis
- `-max-depth`: Maximum traversal depth for dependency attack paths (default: 3)
- `-max-edges`: Maximum edges to traverse per node in attack paths (default: 5)
- `-version`: Show version information

**Important**: This tool only analyzes **local packages**. External dependencies and standard library packages are not supported for direct analysis, but their usage is tracked when called from your local code.

### Output Options

The tool supports two output modes:

#### Console Output (Default)

By default, FBOM JSON is written to stdout, maintaining backwards compatibility:

```bash
golang-fbom-generator -package . > my-project.fbom.json
```

#### File Output

Use the `-o` flag to automatically save output to a file named after your package:

```bash
golang-fbom-generator -package . -o
# Creates: <package-name>.fbom.json
```

The filename is automatically generated based on:

1. **Go module name** (preferred): Extracted from `go.mod`
2. **Directory name** (fallback): Current directory name if no module found

Examples:

- Module `github.com/example/my-app` → `my-app.fbom.json`
- Directory `./examples/hello-world` → `hello-world.fbom.json`

## Output Format

The tool generates JSON documents following the **Function Bill of Materials (FBOM) Specification v0.1.0**.

### Key Output Sections

- **Functions**: User-defined functions with metadata and call information
- **Dependencies**: External dependencies and their usage patterns
- **Dependency Clusters**: Grouped dependency functions with blast radius analysis for attack surface assessment
- **Entry Points**: Application entry points (main, handlers, etc.)
- **Call Graph**: Function call relationships and statistics
- **Security Info**: CVE analysis and vulnerability reachability
- **Reflection Analysis**: Advanced reflection detection with user-focused vulnerability mapping and attack chains

### Example Output Structure

```json
{
  "fbom_version": "0.1.0",
  "functions": [...],
  "dependencies": [...],
  "dependency_clusters": [...],
  "entry_points": [...],
  "call_graph": {...},
  "reflection_analysis": {...},
  "security_info": {...}
}
```

### Dependency Clustering & CVE Reachability

The FBOM includes a `dependency_clusters` section that provides attack surface analysis by grouping all reachable functions within each dependency. This is enhanced with **hierarchical attack path visualization** and **configurable depth analysis**:

```json
{
  "dependency_clusters": [
    {
      "name": "gopkg.in/yaml.v2",
      "entry_points": [
        {
          "function": "Unmarshal",
          "called_from": ["loadConfig"]
        }
      ],
      "attack_paths": [
        {
          "entry_function": "Unmarshal",
          "path_depth": 3,
          "risk_level": "high",
          "vulnerability_ids": ["GO-2024-2611"],
          "path": [
            {
              "function": "Unmarshal",
              "package": "gopkg.in/yaml.v2",
              "call_type": "direct",
              "risk_indicators": ["DESERIALIZATION"]
            }
          ]
        }
      ],
      "blast_radius_summary": {
        "direct_functions": 5,
        "transitive_functions": 134,
        "high_risk_paths": 2,
        "packages_reached": 8,
        "max_path_depth": 5
      }
    }
  ]
}
```

This enables comprehensive security assessment:

- **Entry Points**: Functions in the dependency called directly by your code
- **Attack Paths**: Hierarchical visualization of call chains with vulnerability mapping
- **Vulnerability IDs**: CVEs mapped to specific attack paths for precise impact assessment
- **Risk Indicators**: Call type classification (direct/transitive/reflection) and risk patterns
- **Blast Radius Summary**: High-level statistics about the attack surface complexity
- **Configurable Analysis**: Use `-max-depth` and `-max-edges` to control analysis depth and complexity

## Documentation

- **[FBOM Specification](FBOM_SPECIFICATION.md)**: Complete specification for the FBOM format
- **[Contributing Guide](CONTRIBUTING.md)**: Guidelines for contributors
- **[Integration Tests](tests/integration/README.md)**: Information about the test suite

## Local Package Analysis

The tool analyzes **local Go packages only** for simplicity and reliability:

### Supported Package Types

- **✅ Local Packages**: Current directory (`.`) and relative paths (`./examples/hello-world`)
- **❌ External Dependencies**: Not directly analyzable (e.g., `github.com/gin-gonic/gin`)
- **❌ Standard Library**: Not directly analyzable (e.g., `fmt`, `net/http`)

### Dependency Tracking

While external packages cannot be directly analyzed, the tool **tracks their usage**:

- **Detects external function calls** from your local code
- **Maps dependencies** and their versions from `go.mod`
- **Identifies call patterns** and usage contexts
- **Tracks reflection usage** that may call external code

### Error Messages

If you try to analyze non-local packages, you'll see helpful errors:

```bash
# Trying to analyze external package
golang-fbom-generator -package github.com/gin-gonic/gin
# Error: external packages are not supported: github.com/gin-gonic/gin

# Trying to analyze standard library
golang-fbom-generator -package fmt
# Error: standard library packages are not supported: fmt
```

This simplified approach focuses on analyzing **your code** while tracking **external dependencies** it uses.

## Configuration

The tool uses a `config.toml` file to define:

- Standard library package patterns
- Dependency identification patterns
- Vendor directory patterns
- **Risk assessment configuration** - Configurable high-risk packages and functions

### Risk Assessment Configuration

You can customize which packages and functions are considered high-risk for security analysis by modifying the `[risk_assessment]` section in `config.toml`:

```toml
[risk_assessment]
# High-risk packages for security analysis
high_risk_packages = [
    "os/exec",
    "syscall",
    "unsafe",
    "plugin",
    "crypto",
    "encoding/json",
    "encoding/xml",
    "google.golang.org/protobuf/encoding/protojson"
]

# High-risk functions for security analysis
high_risk_functions = [
    "Unmarshal",
    "Marshal",
    "Decode",
    "Encode",
    "Execute",
    "Run",
    "Open",
    "Create",
    "Remove",
    "Chmod",
    "Chown"
]
```

This configuration affects reflection analysis risk scoring and attack path assessment. You can customize these lists based on your specific threat model and security requirements.

See [config.toml](config.toml) for the complete default configuration.

## Examples

### Analyzing a Simple Application

```bash
# Analyze the hello-world example
cd examples/hello-world
golang-fbom-generator -package .
```

### Analyzing Different Project Types

```bash
# Simple program with basic functions
golang-fbom-generator -package ./examples/hello-world

# Web server with external dependencies
golang-fbom-generator -package ./examples/test-project

# Complex application with multiple features
golang-fbom-generator -package ./examples/fbom-demo
```

### Analyzing with Security Data

```bash
# Run with live CVE scanning for real-time vulnerability analysis
golang-fbom-generator -package . -live-cve-scan -o

# Run with CVE database file for vulnerability analysis (output to file)
golang-fbom-generator -package . -cve examples/sample_cves.json -o

# Customize attack path analysis depth and complexity
golang-fbom-generator -package . -live-cve-scan -max-depth 5 -max-edges 10 -o

# Or output to stdout and redirect
golang-fbom-generator -package . -cve examples/sample_cves.json > fbom.json

# Example output showing reachable CVEs
jq '.security_info' my-project.fbom.json
# {
#   "total_cves_found": 15,
#   "total_reachable_cves": 5,
#   "vulnerable_functions": [
#     {
#       "function_id": "Unmarshal",
#       "full_name": "Unmarshal",
#       "cves": ["GO-2024-2611"],
#       "reachability_paths": ["USER_CODE -> Unmarshal", "USER_CODE -> init"],
#       "risk_score": 7.8,
#       "impact": "medium"
#     }
#   ]
# }

# Analyze reflection-based vulnerabilities
jq '.reflection_analysis.summary' my-project.fbom.json
# {
#   "total_user_reflection_functions": 5,
#   "highest_risk_level": "high",
#   "mitigation_priority": "high",
#   "recommendations": ["Review high-risk reflection usage"]
# }

# Check for reflection-based CVE exposure
jq '.reflection_analysis.attack_chains[] | select(.cves_exposed | length > 0)' my-project.fbom.json
```

### Integration with CI/CD

```bash
# Generate FBOM and check for critical vulnerabilities
golang-fbom-generator -package . -cve cve-data.json -o

# Check for reachable CVEs (fail build if > 0)
REACHABLE_CVES=$(jq '.security_info.total_reachable_cves' my-project.fbom.json)
if [ "$REACHABLE_CVES" -gt 0 ]; then
  echo "❌ Found $REACHABLE_CVES reachable CVEs - failing build"
  exit 1
fi

# Check for high-risk reflection usage
HIGH_RISK_REFLECTION=$(jq '.reflection_analysis.user_reflection_functions[] | select(.risk_score >= 8) | length' my-project.fbom.json)
if [ "$HIGH_RISK_REFLECTION" -gt 0 ]; then
  echo "⚠️  Found $HIGH_RISK_REFLECTION high-risk reflection functions - requires review"
  jq '.reflection_analysis.summary.recommendations[]' my-project.fbom.json
fi

# Check for reflection-exposed CVEs
REFLECTION_CVES=$(jq '.reflection_analysis.attack_chains[] | select(.cves_exposed | length > 0) | length' my-project.fbom.json)
if [ "$REFLECTION_CVES" -gt 0 ]; then
  echo "❌ Found $REFLECTION_CVES CVEs reachable via reflection - failing build"
  exit 1
fi

# Analyze dependency blast radius
jq '.dependency_clusters[] | {name: .name, blast_radius: .total_blast_radius}' fbom.json

# Check dependency usage patterns
jq '.dependencies[] | {name: .name, used_functions: .used_functions}' fbom.json
```

## Security Analysis Features

### Vulnerability Detection

- **CVE Mapping**: Maps known CVEs to function calls with precise function name matching
- **Cluster-Based Reachability**: Uses dependency clustering for fast, reliable vulnerability reachability analysis
- **Real-Time Risk Assessment**: Identifies which CVEs are actually reachable from your code entry points
- **Severity Assessment**: Categorizes vulnerabilities by severity with risk scores (Critical, High, Medium, Low)
- **Blast Radius Analysis**: Shows the total attack surface of each dependency cluster

### Call Analysis

- **Entry Point Identification**: Finds main functions, HTTP handlers, CLI commands
- **Call Depth Calculation**: Measures distance from entry points
- **Reflection Detection**: Advanced detection of reflection usage with risk assessment

### Advanced Reflection Analysis

The tool provides comprehensive reflection detection and vulnerability analysis:

#### Reflection Detection

- **Multi-layer Reflection Chains**: Detects complex reflection patterns across multiple function calls and modules
- **Reflection Usage Detection**: Identifies functions using `reflect.ValueOf()`, `Value.Method()`, `Value.Call()`, `MethodByName()`, etc.
- **Risk Assessment**: Categorizes reflection usage by complexity (direct, layered, dynamic) and risk level (Low, Medium, High)
- **Dynamic Call Patterns**: Detects sophisticated scenarios like interface-based dynamic method invocation

#### User-Focused Analysis

- **User Function Mapping**: Identifies which of _your_ functions use reflection and their risk profiles
- **Vulnerability Exposure**: Shows what vulnerable functions your reflection calls can reach
- **Attack Chain Visualization**: Creates clear step-by-step paths from your code to vulnerable functions
- **Entry Point Inference**: Automatically identifies likely entry points (HTTP handlers, processors, etc.)

#### Security Impact Assessment

- **CVE Reachability via Reflection**: Detects vulnerabilities only reachable through dynamic reflection calls
- **Complexity Classification**: Assesses attack chain complexity (direct, layered, dynamic)
- **Risk Scoring**: Provides 0-10 risk scores for each reflection function based on methods used and targets reached
- **Mitigation Advice**: Generates specific recommendations for reducing reflection-based attack surface

#### Output Structure

```json
{
  "reflection_analysis": {
    "summary": {
      "total_user_reflection_functions": 5,
      "total_vulnerable_targets": 12,
      "highest_risk_level": "high",
      "mitigation_priority": "high",
      "recommendations": [
        "Review processAdvancedReflectionRequest for high-risk reflection usage",
        "Consider input validation before dynamic calls"
      ]
    },
    "user_reflection_functions": [
      {
        "function_name": "processAdvancedReflectionRequest",
        "package": "main",
        "reflection_methods": ["reflect.Call", "reflect.MethodByName"],
        "risk_score": 8,
        "complexity": "dynamic",
        "entry_point": "HTTP endpoint"
      }
    ],
    "attack_chains": [
      {
        "source_function": "processAdvancedReflectionRequest",
        "target_function": "protojson.Unmarshal",
        "layer_count": 4,
        "complexity": "layered",
        "cves_exposed": ["GO-2024-2611"]
      }
    ]
  }
}
```

### Dependency Tracking

- **External Dependencies**: Catalogs third-party libraries and their usage
- **Function Call Mapping**: Tracks which external functions are called and from where
- **Call Context Analysis**: Identifies direct calls vs. callbacks vs. indirect calls

### Call Graph Algorithms

The tool supports multiple call graph generation algorithms, each with different precision and performance characteristics:

#### RTA (Rapid Type Analysis) - Default

```bash
golang-fbom-generator -package . -algo rta
```

- **Best for**: Most use cases, good balance of precision and performance
- **Characteristics**: Efficient, handles interface calls well, default choice

#### CHA (Class Hierarchy Analysis)

```bash
golang-fbom-generator -package . -algo cha
```

- **Best for**: Quick analysis, conservative estimates
- **Characteristics**: Fastest, may include unreachable edges, good for initial analysis

#### Static Analysis

```bash
golang-fbom-generator -package . -algo static
```

- **Best for**: Basic call relationships without dynamic dispatch
- **Characteristics**: Simple, only direct calls, limited interface support

#### VTA (Variable Type Analysis)

```bash
golang-fbom-generator -package . -algo vta
```

- **Best for**: Highest precision analysis
- **Characteristics**: Most precise, slower execution, best for security-critical analysis

## Development & Contributing

### Building from Source

```bash
git clone https://github.com/smith-xyz/golang-fbom-generator
cd golang-fbom-generator
go build .
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific test suites
go test ./pkg/...                    # Unit tests
go test ./tests/integration/...      # Integration tests
go test ./tests/bugs/...            # Bug regression tests
go test ./tests/feature/...         # Feature tests
go test ./tests/e2e/...             # End-to-end tests

# Run with verbose output
go test -v ./tests/integration/
```

#### Test Organization

The test suite is organized into focused categories:

- **`pkg/`**: Unit tests for individual packages and components
- **`tests/bugs/`**: Regression tests for specific bug fixes
- **`tests/feature/`**: Feature-level integration tests
- **`tests/integration/`**: Full integration tests with real Go code analysis
- **`tests/e2e/`**: End-to-end tests with example projects
- **`tests/shared/`**: Common test utilities and helpers

### Quality Assurance

```bash
# Run all quality checks
make quality

# Individual quality checks
make fmt-check      # Code formatting
make vet           # Go vet analysis
make lint          # Linting
make sec           # Security scanning (gosec)

# Fix issues automatically
make lint-fix      # Fix linting issues
make fmt           # Format code

# Complete verification
make verify        # All tests + quality checks
```

#### Security Standards

The codebase follows security best practices:

- **Static Security Scanning**: Automated gosec security analysis
- **Secure File Permissions**: Test files use restrictive permissions (0600)
- **Path Validation**: Input validation for file operations
- **Dependency Security**: Regular CVE scanning of dependencies

## Example Projects

The repository includes example projects for testing and demonstration:

- **[hello-world](examples/hello-world/)**: Simple program with basic function calls
- **[test-project](examples/test-project/)**: Web server with external dependencies and reflection
- **[fbom-demo](examples/fbom-demo/)**: Complex application demonstrating various security scenarios

## CVE Analysis & Reachability

### Enhanced CVE Mapping

The tool provides sophisticated CVE analysis capabilities:

```bash
# Run CVE analysis on fbom-demo
cd examples/fbom-demo
golang-fbom-generator -package . -cve ../sample_cves.json -o

# Expected output:
# - Total CVEs Found: 15
# - Total Reachable CVEs: 5
# - Detailed vulnerable function analysis with risk scores
```

### Reachability Algorithm

The CVE reachability analysis uses an efficient **cluster-based approach**:

1. **Function Matching**: Maps CVE vulnerable functions to call graph functions
2. **Cluster Lookup**: Checks if vulnerable functions exist in any dependency cluster
3. **Entry Point Verification**: Confirms the cluster has entry points from user code
4. **Risk Assessment**: Calculates risk scores and impact levels

This approach is significantly faster than traditional path-finding algorithms while providing reliable results.

### CVE Data Format

CVE data should be provided in JSON format with function names matching the call graph output:

```json
{
  "cves": [
    {
      "id": "CVE-2023-12345",
      "vulnerable_package": "github.com/gin-gonic/gin",
      "vulnerable_functions": ["Abort", "AbortWithStatus", "Render"],
      "cvss_score": 7.8,
      "description": "Security vulnerability description"
    }
  ]
}
```

## Use Cases

### Security Auditing

- Identify all external dependencies and their usage
- Map CVEs to actual code usage with precise reachability analysis
- Assess attack surface through entry point analysis and dependency clustering

### Compliance and Documentation

- Generate software bills of materials for regulatory requirements
- Document function-level dependencies for security reviews
- Track code reachability for impact analysis

### CI/CD Integration

- Automated security scanning in build pipelines
- Fail builds on critical vulnerability reachability
- Track dependency changes over time

## Schema Validation

FBOM output can be validated against the JSON Schema:

```bash
# Validate FBOM output
jsonschema -i fbom.json schemas/fbom-v0.1.0.json
```

## Performance

The tool is designed for efficiency:

- **Static Analysis**: No code execution required
- **Incremental Processing**: Analyzes only user-defined code
- **Streaming Output**: Memory-efficient for large codebases

## Limitations

- **Local Packages Only**: Only analyzes local Go packages (not external dependencies or stdlib directly)
- **Static Analysis Only**: Cannot detect runtime-only vulnerabilities
- **Go-Specific**: Only analyzes Go source code
- **Call Graph Precision**: May miss some dynamic calls via reflection or interfaces
- **CVE Data Dependency**: CVE reachability analysis requires accurate, up-to-date CVE data with correct function names
- **Function Name Matching**: CVE function names must match call graph function name format for accurate reachability analysis

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Support

- Report issues on [GitHub Issues](https://github.com/smith-xyz/golang-fbom-generator/issues)
- Review the [FBOM Specification](FBOM_SPECIFICATION.md) for format questions
- Check [existing examples](examples/) for usage patterns
