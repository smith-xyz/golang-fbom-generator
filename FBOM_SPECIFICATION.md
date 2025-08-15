# Function Bill of Materials (FBOM) Specification

## Overview

The Function Bill of Materials (FBOM) is a structured JSON document that provides comprehensive security analysis of Go applications. It catalogs all user-defined functions, their dependencies, call relationships, and security-relevant metadata to support vulnerability assessment and risk analysis.

## Version

**Current Specification Version:** 0.1.0  
**Compatible FBOM Generator Versions:** v1.0.0-beta+

## Document Structure

### Root Object

```json
{
  "fbom_version": "string",
  "spdx_id": "string", 
  "creation_info": { ... },
  "package_info": { ... },
  "functions": [ ... ],
  "dependencies": [ ... ],
  "entry_points": [ ... ],
  "call_graph": { ... },
  "security_info": { ... }
}
```

## Configuration and Entry Point Specification

### Entry Point Configuration

Entry points can be specified using the `-entry-points` flag when running the FBOM generator:

```bash
# Specify specific functions as entry points
golang-fbom-generator -package ./myapp -entry-points "HandleHTTP,ProcessRequest"

# Use wildcard patterns
golang-fbom-generator -package ./myapp -entry-points "handle*,*Handler"

# Multiple patterns
golang-fbom-generator -package ./myapp -entry-points "Get*,Post*,*Service"
```

#### Pattern Matching

The entry points flag supports basic wildcard patterns:

- **Exact match**: `"HandleHTTP"` - matches only functions named exactly "HandleHTTP"
- **Prefix wildcard**: `"handle*"` - matches functions starting with "handle"
- **Suffix wildcard**: `"*Handler"` - matches functions ending with "Handler"  
- **Contains wildcard**: `"*User*"` - matches functions containing "User"

#### Default Entry Points

By default, the following functions are always considered entry points:

- **`main`**: Application main function
- **`init`**: Package initialization functions

Additional entry points specified via the `-entry-points` flag are added to these defaults.

## Field Definitions

### 1. Document Metadata

#### `fbom_version` (string, required)
- **Description**: Version of the FBOM specification used
- **Format**: Semantic versioning (e.g., "0.1.0")
- **Example**: `"0.1.0"`

#### `spdx_id` (string, required)  
- **Description**: SPDX identifier for the root document
- **Format**: SPDX Document Reference format
- **Example**: `"SPDXRef-FBOM-ROOT"`

#### `creation_info` (object, required)
Document creation metadata following SPDX conventions.

```json
{
  "created": "string",           // Unix timestamp
  "created_by": "string",        // Tool description
  "tool_name": "string",         // Generator tool name
  "tool_version": "string",      // Generator version
  "creators": ["string"],        // List of creators
  "license_list_id": "string"    // License identifier
}
```

#### `package_info` (object, required)
Information about the analyzed Go package.

```json
{
  "name": "string",              // Package name
  "spdx_id": "string",          // SPDX package identifier  
  "source_info": "string"       // Source description
}
```

### 2. Functions Array

#### `functions` (array, required)
Array of user-defined function objects. Only includes functions from the target application (excludes stdlib and external dependencies).

```json
{
  "spdx_id": "string",              // Unique SPDX identifier
  "name": "string",                 // Function name
  "full_name": "string",            // Fully qualified name (package.function)
  "package": "string",              // Go package name
  "file_path": "string",            // Source file path
  "start_line": "number",           // Starting line number
  "end_line": "number",             // Ending line number  
  "signature": "string",            // Function signature
  "visibility": "string",           // "public" or "private"
  "function_type": "string",        // Function classification
  "is_exported": "boolean",         // Whether function is exported
  "parameters": [ ... ],            // Parameter definitions
  "return_types": ["string"],       // Return type names
  "usage_info": { ... }             // Call and usage metadata
}
```

#### Function Type Classifications

- **`"main"`**: Main entry point function
- **`"init"`**: Package initialization function  
- **`"regular"`**: Standard function
- **`"method"`**: Method with receiver
- **`"closure"`**: Anonymous function/closure

#### Usage Info Object

```json
{
  "calls": ["string"],              // Internal function calls (to user functions)
  "called_by": ["string"],          // Functions that call this function
  "external_calls": ["string"],     // Calls to external dependencies
  "stdlib_calls": ["string"],       // Calls to Go standard library
  "has_reflection_access": "boolean", // Uses reflection APIs
  "is_reachable": "boolean",        // Reachable from entry points
  "call_depth": "number",           // Distance from nearest entry point
  "is_entry_point": "boolean"       // Is an application entry point
}
```

### 3. Dependencies Array

#### `dependencies` (array, required)
External dependencies (third-party packages) used by the application.

**Version Detection**: Dependency versions are extracted from the project's `go.mod` file using the `go list -m all` command, ensuring accurate version information that matches the actual resolved dependencies.

```json
{
  "name": "string",                 // Dependency package name
  "version": "string",              // Package version (extracted from go.mod)
  "type": "string",                 // Package type (e.g., "go-module")
  "spdx_id": "string",             // SPDX identifier for this dependency
  "package_manager": "string",      // Package manager (e.g., "go-modules")
  "purl_identifier": "string",      // Package URL (PURL) identifier
  "used_functions": "number",       // Number of functions used from this dependency
  "called_functions": [ ... ],      // Functions called from this dependency
  "fbom_reference": { ... }         // Reference to dependency's FBOM (if available)
}
```

#### Called Functions Object

```json
{
  "function_name": "string",        // Name of the called function
  "full_function_name": "string",   // Fully qualified function name
  "call_context": "string",         // Call context classification
  "call_sites": ["string"]          // Functions that make this call
}
```

#### Call Context Classifications

- **`"direct"`**: Function called directly by user code
- **`"callback"`**: Function called as a callback/handler
- **`"indirect"`**: Function called through interface or reflection

#### Package URL (PURL) Identifier

The `purl_identifier` field contains a Package URL that uniquely identifies the dependency according to the [PURL specification](https://github.com/package-url/purl-spec).

**Format**: `pkg:type/namespace/name@version?qualifiers#subpath`

**Examples**:
- `pkg:golang/github.com/gin-gonic/gin@v1.9.1`
- `pkg:golang/gopkg.in/yaml.v2@v2.4.0`

#### FBOM Reference Object

```json
{
  "fbom_location": "string",        // URL, file path, or registry reference
  "fbom_version": "string",         // Version of the external FBOM
  "resolution_type": "string",      // How dependency FBOM was resolved
  "checksum_sha256": "string",      // SHA256 checksum (optional)
  "last_verified": "string",        // Last verification timestamp (optional)
  "spdx_document_id": "string"      // SPDX identifier for dependency FBOM
}
```

#### FBOM Cache Linking

The generator automatically links to cached FBOMs when available, providing enhanced metadata and validation:

**Cache Hit Behavior:**
- `fbom_location`: Absolute path to cached FBOM file
- `resolution_type`: `"cached_external"` or `"cached_stdlib"`
- `checksum_sha256`: SHA256 hash of cached file content
- `last_verified`: Timestamp when cache validation occurred

**Cache Miss Behavior:**
- `fbom_location`: Placeholder path where FBOM could be generated
- `resolution_type`: `"file"` (indicates placeholder)
- Missing optional fields (`checksum_sha256`, `last_verified`)

**Cache Structure:**
```
./fboms/
├── external/
│   └── github-com-gin-gonic-gin@v1.9.1.fbom.json
└── stdlib/
    └── go1.21.0/
        └── fmt.fbom.json
```

**Cache Miss Reporting:**
In verbose mode (`-v`), the generator reports missing FBOMs with suggested generation commands:

```
📋 Cache Miss Report: 2 missing FBOMs
==================================================
📦 github.com/gin-gonic/gin@v1.9.1
   💡 golang-fbom-generator -generate-fbom github.com/gin-gonic/gin@v1.9.1
📦 fmt
   💡 golang-fbom-generator -generate-fbom fmt
```

### 4. Entry Points Array

#### `entry_points` (array, required)
Application entry points that can be invoked externally.

```json
{
  "spdx_id": "string",              // SPDX identifier for entry point
  "name": "string",                 // Entry point name
  "type": "string",                 // Entry point type
  "package": "string",              // Package containing entry point
  "accessible_from": ["string"],   // Accessibility levels
  "security_level": "string",       // Security classification
  "reachable_functions": "number"   // Number of functions reachable from this entry point
}
```

#### Entry Point Types

- **`"main"`**: Main function entry point
- **`"init"`**: Package initialization function
- **`"internal"`**: User-defined internal entry point (specified via `-entry-points` flag)

#### Accessibility Levels

- **`"external"`**: Accessible from outside the application
- **`"internal"`**: Accessible only within the application

#### Security Levels

- **`"public"`**: Publicly accessible entry point
- **`"internal"`**: Internal access only

### 5. Call Graph Object

#### `call_graph` (object, required)
Representation of function call relationships.

```json
{
  "call_edges": [ ... ],            // Individual call relationships
  "statistics": { ... }             // Call graph metrics
}
```

#### Call Edge Object

```json
{
  "caller": "string",               // Calling function identifier
  "callee": "string",               // Called function identifier  
  "call_type": "string",            // Type of call relationship
  "file_path": "string",            // File containing the call
  "line_number": "number"           // Line number of the call
}
```

#### Call Types

- **`"internal"`**: Call between user functions
- **`"external"`**: Call to external dependency
- **`"stdlib"`**: Call to Go standard library
- **`"reflection"`**: Call made via reflection

#### Call Graph Statistics

```json
{
  "total_nodes": "number",          // Total functions in graph
  "total_edges": "number",          // Total call relationships
  "max_depth": "number",            // Maximum call depth
  "average_depth": "number",        // Average call depth
  "cyclic_dependencies": "number",  // Number of circular call patterns
  "unreachable_functions": "number" // Functions not reachable from entry points
}
```

### 6. Security Info Object

#### `security_info` (object, required)
Security analysis summary and metrics.

```json
{
  "total_cves_found": "number",             // Total CVEs identified
  "critical_cves": "number",                // Critical severity CVEs
  "high_cves": "number",                    // High severity CVEs  
  "medium_cves": "number",                  // Medium severity CVEs
  "low_cves": "number",                     // Low severity CVEs
  "reflection_calls_count": "number",       // Functions using reflection
  "total_external_dependencies": "number", // Count of external dependencies
  "reachable_vulnerabilities": "number",   // CVEs reachable from entry points
  "analysis_timestamp": "string"           // When analysis was performed
}
```

## Example Document

```json
{
  "fbom_version": "0.1.0",
  "spdx_id": "SPDXRef-FBOM-ROOT",
  "creation_info": {
    "created": "1703001600",
    "created_by": "golang-fbom-generator Function Bill of Materials Generator",
    "tool_name": "golang-fbom-generator", 
    "tool_version": "v1.0.0-beta",
    "creators": ["Tool: golang-fbom-generator"],
    "license_list_id": "MIT"
  },
  "package_info": {
    "name": "my-app",
    "spdx_id": "SPDXRef-Package-my-app",
    "source_info": "Local Go Package Analysis"
  },
  "functions": [
    {
      "spdx_id": "SPDXRef-Function-main",
      "name": "main",
      "full_name": "main.main",
      "package": "main",
      "file_path": "/app/main.go",
      "start_line": 10,
      "end_line": 15,
      "signature": "func()",
      "visibility": "public",
      "function_type": "main",
      "is_exported": false,
      "parameters": [],
      "return_types": [],
      "usage_info": {
        "calls": ["processRequest"],
        "called_by": [],
        "external_calls": ["github.com/gin-gonic/gin.Default"],
        "stdlib_calls": ["fmt.Println"],
        "has_reflection_access": false,
        "is_reachable": true,
        "call_depth": 0,
        "is_entry_point": true
      }
    }
  ],
  "dependencies": [
    {
      "name": "github.com/gin-gonic/gin",
      "version": "v1.9.1",
      "type": "go-module",
      "spdx_id": "SPDXRef-Dependency-gin",
      "package_manager": "go-modules",
      "purl_identifier": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
      "used_functions": 3,
      "called_functions": [
        {
          "function_name": "Default",
          "full_function_name": "github.com/gin-gonic/gin.Default", 
          "call_context": "direct",
          "call_sites": ["main"]
        }
      ],
      "fbom_reference": {
        "fbom_location": "https://registry.fbom.dev/gin-gonic/gin/v1.9.1",
        "fbom_version": "0.1.0",
        "resolution_type": "registry",
        "checksum_sha256": "abc123...",
        "last_verified": "2024-01-01T12:00:00Z",
        "spdx_document_id": "SPDXRef-Dependency-gin"
      }
    }
  ],
  "entry_points": [
    {
      "spdx_id": "SPDXRef-EntryPoint-main",
      "name": "main",
      "type": "main", 
      "package": "main",
      "accessible_from": ["external"],
      "security_level": "public",
      "reachable_functions": 15
    },
    {
      "spdx_id": "SPDXRef-EntryPoint-init",
      "name": "init",
      "type": "init", 
      "package": "main",
      "accessible_from": ["internal"],
      "security_level": "internal",
      "reachable_functions": 2
    }
  ],
  "call_graph": {
    "call_edges": [
      {
        "caller": "main.main",
        "callee": "main.processRequest",
        "call_type": "internal",
        "file_path": "/app/main.go", 
        "line_number": 12
      }
    ],
    "statistics": {
      "total_nodes": 5,
      "total_edges": 8,
      "max_depth": 3,
      "average_depth": 1.8,
      "cyclic_dependencies": 0,
      "unreachable_functions": 1
    }
  },
  "security_info": {
    "total_cves_found": 2,
    "critical_cves": 0,
    "high_cves": 1,
    "medium_cves": 1, 
    "low_cves": 0,
    "reflection_calls_count": 1,
    "total_external_dependencies": 3,
    "reachable_vulnerabilities": 2,
    "analysis_timestamp": "2024-01-01T12:00:00Z"
  }
}
```

## Implementation Guidelines

### 1. Data Consistency

- All `spdx_id` fields must be unique within the document
- Function references in `calls`, `called_by`, etc. must use `full_name` format
- File paths should be absolute when possible, relative to project root otherwise

### 2. Security Analysis Scope

- **Include**: Only user-defined functions from the target application
- **Exclude**: Go standard library functions, external dependency internals
- **Track**: All calls to external dependencies and stdlib functions

### 3. Call Graph Accuracy

- **Reachability**: Based on static analysis from defined entry points
- **Call Depth**: Minimum distance from any entry point
- **External Calls**: Direct calls only (not transitive through user functions)

### 4. Filtering Rules

Functions are included in the FBOM if they meet ALL criteria:
1. Defined in the target application (not stdlib or dependencies)
2. Reachable through static analysis from entry points  
3. Part of the compiled binary (not dead code eliminated)

### 5. Performance Considerations

- Large applications may generate substantial FBOM documents
- Consider pagination or summarization for very large call graphs
- Implement streaming for memory-efficient processing of large codebases

## Validation Schema

A JSON Schema for FBOM validation is available at: `schemas/fbom-v0.1.0.json`

## Versioning

This specification follows semantic versioning:
- **Major**: Breaking changes to document structure
- **Minor**: Backward-compatible additions  
- **Patch**: Clarifications and non-functional changes

## Security Considerations

FBOM documents may contain sensitive information:
- **Source code structure**: File paths and function signatures
- **Dependency usage**: External libraries and their usage patterns
- **Application architecture**: Call relationships and entry points

Implement appropriate access controls when storing or sharing FBOM documents.

## Extensions

Custom tools may extend FBOM documents with additional fields using vendor-specific prefixes:

```json
{
  "x-vendor-custom-field": "value",
  "x-security-scanner-results": { ... }
}
```

Standard extensions should be proposed through the specification governance process.

## References

- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom)
- [Go Module Reference](https://golang.org/ref/mod)
- [Static Analysis in Go](https://pkg.go.dev/golang.org/x/tools/go/analysis)
