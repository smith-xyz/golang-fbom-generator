# golang-fbom-generator

A security-focused Function Bill of Materials (FBOM) generator for Go applications that provides comprehensive static analysis to identify potential vulnerabilities and security risks.

## Overview

The golang-fbom-generator analyzes **local Go projects** to create detailed security reports that include:

- **Function Inventory**: All user-defined functions with their call relationships
- **Dependency Analysis**: External libraries and their usage patterns  
- **Dependency Clustering**: Groups reachable functions by dependency with blast radius analysis
- **Entry Point Mapping**: Application entry points and reachability analysis
- **Security Assessment**: CVE mapping and vulnerability reachability (when CVE data provided)
- **Call Graph Analysis**: Function call relationships using proven Go toolchain algorithms

## Quick Start

### Installation

```bash
go install github.com/smith-xyz/golang-fbom-generator@latest
```

### Basic Usage

```bash
# Analyze current directory (local project)
golang-fbom-generator -package .

# Analyze a subdirectory
golang-fbom-generator -package ./examples/hello-world

# Analyze with CVE data
golang-fbom-generator -package . -cve cve-data.json

# Verbose output
golang-fbom-generator -package . -v

# Auto-discover all main functions for multi-component projects
golang-fbom-generator --auto-discover -v
```

### Command Line Options

- `-package`: **Local Go package path only** - supports relative paths (`.`, `./subdir`) 
- `-cve`: Path to CVE data file (JSON) - optional
- `-v`: Verbose output
- `-entry-points`: Comma-separated list of additional entry point patterns
- `-algo`: Call graph algorithm to use: `rta`, `cha`, `static`, `vta` (default: "rta")
- `-auto-discover`: Auto-discover all main functions for unified multi-component analysis
- `-library`: Library mode - treat current package as user-defined regardless of import path
- `-version`: Show version information

**Important**: This tool only analyzes **local packages**. External dependencies and standard library packages are not supported for direct analysis, but their usage is tracked when called from your local code.

### Library Mode

For analyzing Go libraries themselves, use the `-library` flag:

```bash
# Analyze a Go library (treats the package functions as user-defined)
golang-fbom-generator -package . -library
```

This mode is useful for:
- Creating FBOMs for libraries to be published alongside the library
- Analyzing the internal structure of libraries
- Understanding library-specific attack surfaces

## Output Format

The tool generates JSON documents following the **Function Bill of Materials (FBOM) Specification v0.1.0**.

### Key Output Sections

- **Functions**: User-defined functions with metadata and call information
- **Dependencies**: External dependencies and their usage patterns
- **Dependency Clusters**: Grouped dependency functions with blast radius analysis for attack surface assessment
- **Entry Points**: Application entry points (main, handlers, etc.)
- **Call Graph**: Function call relationships and statistics
- **Security Info**: CVE analysis and vulnerability reachability

### Example Output Structure

```json
{
  "fbom_version": "0.1.0",
  "functions": [...],
  "dependencies": [...], 
  "dependency_clusters": [...],
  "entry_points": [...],
  "call_graph": {...},
  "security_info": {...}
}
```

### Dependency Clustering & CVE Reachability

The FBOM includes a `dependency_clusters` section that provides attack surface analysis by grouping all reachable functions within each dependency. This is also used for **fast CVE reachability analysis**:

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
      "cluster_functions": ["newDecoder", "decode", "parseNode", "..."],
      "total_blast_radius": 134
    }
  ]
}
```

This enables rapid security assessment:
- **Entry Points**: Functions in the dependency called directly by your code
- **Cluster Functions**: All reachable functions within that dependency  
- **Blast Radius**: Total count of functions that could be affected by a vulnerability in this dependency
- **CVE Reachability**: If a vulnerable function exists in `cluster_functions` and the cluster has `entry_points`, the CVE is reachable from your code

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

See [config.toml](config.toml) for the default configuration.

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
# Run with CVE database for vulnerability analysis
golang-fbom-generator -package . -cve examples/sample_cves.json

# Example output showing reachable CVEs
jq '.security_info' fbom.json
# {
#   "total_cves_found": 15,
#   "total_reachable_cves": 5,
#   "vulnerable_functions": [
#     {
#       "function_id": "github.com/gin-gonic/gin.Abort",
#       "cves": ["CVE-2023-12345"],
#       "is_reachable": true,
#       "risk_score": 7.8,
#       "impact": "high"
#     }
#   ]
# }
```

### Integration with CI/CD

```bash
# Generate FBOM and check for critical vulnerabilities
golang-fbom-generator -package . -cve cve-data.json > fbom.json

# Check for reachable CVEs (fail build if > 0)
REACHABLE_CVES=$(jq '.security_info.total_reachable_cves' fbom.json)
if [ "$REACHABLE_CVES" -gt 0 ]; then
  echo "❌ Found $REACHABLE_CVES reachable CVEs - failing build"
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
- **Reflection Detection**: Identifies use of reflection APIs that complicate static analysis

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

## Development

### Building from Source

```bash
git clone https://github.com/smith-xyz/golang-fbom-generator
cd golang-fbom-generator
go build .
```

### Running Tests

```bash
# Run unit tests
go test ./...

# Run integration tests
cd tests/integration
go test -v
```

### Linting and Verification

```bash
# Fix linting issues
make lint-fix

# Verify all checks pass
make verify
```

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
golang-fbom-generator -package . -cve ../sample_cves.json

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
