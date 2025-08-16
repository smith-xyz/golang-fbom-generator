# golang-fbom-generator

A security-focused Function Bill of Materials (FBOM) generator for Go applications that provides comprehensive static analysis to identify potential vulnerabilities and security risks.

## Overview

The golang-fbom-generator analyzes Go codebases to create detailed security reports that include:

- **Function Inventory**: All user-defined functions with their call relationships
- **Dependency Analysis**: External libraries and their usage patterns  
- **Entry Point Mapping**: Application entry points and reachability analysis
- **Security Assessment**: CVE mapping and vulnerability reachability
- **Call Graph Analysis**: Function call relationships and depth analysis

## Quick Start

### Installation

```bash
go install github.com/smith-xyz/golang-fbom-generator@latest
```

### Basic Usage

```bash
# Analyze current directory
golang-fbom-generator -package .

# Analyze with CVE data
golang-fbom-generator -package . -cve cve-data.json

# Verbose output
golang-fbom-generator -package . -v

# Generate FBOM for external dependency
golang-fbom-generator -package github.com/gin-gonic/gin@v1.9.1

# Generate FBOM for standard library package
golang-fbom-generator -package fmt
```

### Command Line Options

- `-package`: Go package path to analyze - supports local (`.`), external (`github.com/gin-gonic/gin@v1.9.1`), or stdlib (`fmt`) packages
- `-cve`: Path to CVE data file (JSON) - optional
- `-v`: Verbose output
- `-entry-points`: Comma-separated list of additional entry point patterns
- `-algo`: Call graph algorithm to use: `rta`, `cha`, `static`, `vta` (default: "rta")
- `-version`: Show version information

**Note**: The `-package` flag can analyze any type of package - local, external, or standard library.

## Output Format

The tool generates JSON documents following the **Function Bill of Materials (FBOM) Specification v0.1.0**.

### Key Output Sections

- **Functions**: User-defined functions with metadata and call information
- **Dependencies**: External dependencies and their usage patterns
- **Entry Points**: Application entry points (main, handlers, etc.)
- **Call Graph**: Function call relationships and statistics
- **Security Info**: CVE analysis and vulnerability reachability

### Example Output Structure

```json
{
  "fbom_version": "0.1.0",
  "functions": [...],
  "dependencies": [...], 
  "entry_points": [...],
  "call_graph": {...},
  "security_info": {...}
}
```

## Documentation

- **[FBOM Specification](FBOM_SPECIFICATION.md)**: Complete specification for the FBOM format
- **[Contributing Guide](CONTRIBUTING.md)**: Guidelines for contributors
- **[Integration Tests](tests/integration/README.md)**: Information about the test suite

## FBOM Cache

The tool supports generating and caching FBOMs for individual packages:

### Cache Structure

```
./fboms/
├── external/
│   └── github-com-gin-gonic-gin@v1.9.1.fbom.json
└── stdlib/
    ├── go1.21.0/
    │   └── fmt.fbom.json
    └── go1.22.0/
        └── net-http.fbom.json
```

### Generating Dependency FBOMs

```bash
# Generate FBOM for external package with specific version
golang-fbom-generator -package github.com/gin-gonic/gin@v1.9.1

# Generate FBOM for external package (latest version auto-resolved)
golang-fbom-generator -package github.com/sirupsen/logrus

# Generate FBOM for standard library package
golang-fbom-generator -package net/http
```

Generated FBOMs are saved to the local `./fboms/` directory for reuse and reference.

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

### Analyzing with Security Data

```bash
# Run with CVE database
golang-fbom-generator -package . -cve examples/sample_cves.json
```

### Integration with CI/CD

```bash
# Generate FBOM and check for critical vulnerabilities
golang-fbom-generator -package . -cve cve-data.json > fbom.json
jq '.security_info.critical_cves' fbom.json
```

## Security Analysis Features

### Vulnerability Detection

- **CVE Mapping**: Maps known CVEs to function calls
- **Reachability Analysis**: Determines if vulnerabilities are reachable from entry points
- **Severity Assessment**: Categorizes vulnerabilities by severity (Critical, High, Medium, Low)

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

## Use Cases

### Security Auditing

- Identify all external dependencies and their usage
- Map CVEs to actual code usage
- Assess attack surface through entry point analysis

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

- **Static Analysis Only**: Cannot detect runtime-only vulnerabilities
- **Go-Specific**: Only analyzes Go source code
- **Call Graph Precision**: May miss some dynamic calls via reflection or interfaces

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Support

- Report issues on [GitHub Issues](https://github.com/smith-xyz/golang-fbom-generator/issues)
- Review the [FBOM Specification](FBOM_SPECIFICATION.md) for format questions
- Check [existing examples](examples/) for usage patterns
