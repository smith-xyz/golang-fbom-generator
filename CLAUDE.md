# CLAUDE.md - Project Context for golang-fbom-generator

This file provides comprehensive context for AI assistants (Claude) working on the golang-fbom-generator project.

## Project Overview

**golang-fbom-generator** is an experimental security-focused Function Bill of Materials (FBOM) generator for Go applications. It performs comprehensive static analysis to identify potential vulnerabilities and security risks, with the goal of establishing a standard for collecting a complete tree of functions for codebases.

### Core Purpose
- **Primary Goal**: Create detailed security reports for Go applications through static analysis
- **Secondary Goal**: Establish a standard for function-level bill of materials (FBOM) specification
- **Focus**: Security vulnerability detection, dependency analysis, and attack surface assessment

## Architecture Overview

### High-Level Components

```
golang-fbom-generator/
├── main.go                    # CLI entry point
├── pkg/                       # Core implementation packages
│   ├── analysis/             # Analysis engines
│   ├── config/              # Configuration management
│   ├── cveloader/           # CVE database handling
│   ├── generator/           # FBOM generation logic
│   ├── models/              # Data structures
│   ├── output/              # FBOM output generation
│   ├── utils/               # Utility functions
│   ├── version/             # Version management
│   └── vulncheck/           # Vulnerability checking
├── tests/                    # Comprehensive test suite
│   ├── bugs/                # Bug regression tests
│   ├── e2e/                 # End-to-end tests
│   ├── feature/             # Feature integration tests
│   ├── integration/         # Integration tests
│   └── shared/              # Common test utilities
└── examples/                 # Example projects for testing
```

### Analysis Pipeline

The tool follows a structured analysis pipeline:

1. **Call Graph Generation** (`pkg/analysis/callgraph/`)
   - Uses Go's SSA (Static Single Assignment) analysis
   - Supports multiple algorithms: RTA, CHA, Static, VTA
   - Builds function call relationships

2. **Function Analysis** (`pkg/analysis/function/`)
   - Identifies user-defined vs external functions
   - Calculates reachability and distance from entry points
   - Builds comprehensive function inventory

3. **Dependency Analysis** (`pkg/analysis/dependency/`)
   - Maps external dependencies and their usage
   - Creates dependency clusters for attack surface analysis
   - Generates blast radius assessments

4. **Reflection Analysis** (`pkg/analysis/reflection/`)
   - Detects reflection usage patterns
   - Assesses security risks of dynamic calls
   - Maps reflection-based vulnerability exposure

5. **CVE Analysis** (`pkg/analysis/cve/`)
   - Maps CVEs to reachable functions
   - Performs vulnerability reachability analysis
   - Generates risk assessments

6. **FBOM Generation** (`pkg/output/`)
   - Combines all analysis results
   - Generates JSON output following FBOM specification
   - Provides console or file output options

## Key Technical Concepts

### Context-Aware Configuration
- **Critical**: The FBOM generator is sensitive to the current working directory
- **Pattern**: Always create `NewFBOMGenerator()` AFTER changing to the target directory
- **Reason**: Module detection and package classification depend on go.mod context

### Test Organization Philosophy
- **Unit Tests** (`pkg/`): Individual package/component testing
- **Bug Tests** (`tests/bugs/`): Regression tests for specific fixes
- **Feature Tests** (`tests/feature/`): Feature-level integration testing
- **Integration Tests** (`tests/integration/`): Full pipeline testing with real Go code
- **E2E Tests** (`tests/e2e/`): End-to-end validation with example projects

### Security Standards
- **File Permissions**: Test files use 0600 permissions for security compliance
- **Path Validation**: Input validation for file operations to prevent injection
- **Static Analysis**: Automated gosec security scanning
- **Dependency Security**: CVE scanning and vulnerability tracking

## Development Patterns & Best Practices

### Test-Driven Development (TDD) Approach

**MANDATORY**: All bug fixes and new features should follow TDD methodology:

#### TDD Cycle for Bug Fixes
```bash
# 1. RED: Write a failing test that reproduces the bug
cd tests/bugs/
# Create bug_XX_description_test.go with failing test

# 2. GREEN: Write minimal code to make the test pass
# Fix the bug in the appropriate pkg/ module

# 3. REFACTOR: Clean up the implementation
# Ensure the fix is clean and maintainable

# 4. VERIFY: Run all tests to ensure no regressions
make verify
```

#### TDD Cycle for New Features
```bash
# 1. RED: Write tests for the feature before implementation
cd tests/feature/  # or appropriate test directory
# Create feature_test.go with desired behavior

# 2. GREEN: Implement the feature to make tests pass
# Add implementation in pkg/ modules

# 3. REFACTOR: Improve design and code quality
# Clean up implementation, extract common patterns

# 4. INTEGRATE: Add integration and e2e tests
cd tests/integration/
# Add integration tests for the complete feature

# 5. VERIFY: Complete test suite validation
make verify
```

### Code Quality Standards
```bash
make quality    # Runs all quality checks (formatting, linting, security)
make verify     # Complete verification (tests + quality)
make lint-fix   # Automatic issue resolution
```

### Testing Patterns
```bash
go test ./pkg/...                    # Unit tests
go test ./tests/integration/...      # Integration tests
go test ./tests/bugs/...            # Bug regression tests
go test ./tests/feature/...         # Feature tests
go test ./tests/e2e/...             # End-to-end tests
```

### TDD-Specific Guidelines for This Project

#### Bug Fix TDD Pattern
```bash
# Example: Fixing a reflection detection bug
# 1. RED: Create failing test in tests/bugs/
cat > tests/bugs/bug_XX_reflection_detection_test.go << 'EOF'
func TestBug_XX_ReflectionDetection(t *testing.T) {
    // Code that should work but currently fails
    code := `package main
    import "reflect"
    func problematicFunction() {
        // Specific case that's broken
    }`
    
    // Expected behavior that currently fails
    // Test the specific bug condition
}
EOF

# 2. Verify test fails
go test ./tests/bugs/ -run TestBug_XX_ReflectionDetection

# 3. GREEN: Fix the bug in pkg/analysis/reflection/
# Make minimal changes to pass the test

# 4. REFACTOR: Clean up the fix
# Ensure solution is maintainable and doesn't break other tests

# 5. VERIFY: All tests pass
make verify
```

#### Feature Development TDD Pattern  
```bash
# Example: Adding new CVE severity analysis
# 1. RED: Write feature test first
cat > tests/feature/cve_severity_analysis_test.go << 'EOF'
func TestCVESeverityAnalysis(t *testing.T) {
    // Define expected behavior before implementation
    // Test the complete feature workflow
}
EOF

# 2. RED: Write unit tests for components
cat > pkg/analysis/cve/severity_test.go << 'EOF'
func TestSeverityCalculation(t *testing.T) {
    // Test individual component behavior
}
EOF

# 3. GREEN: Implement feature to pass tests
# Add implementation in pkg/analysis/cve/

# 4. INTEGRATE: Add integration tests
# Test feature in complete pipeline

# 5. REFACTOR: Clean up and optimize
# Extract common patterns, improve maintainability
```

#### Context Detection TDD Pattern
```bash
# Critical for this project: Always test context-sensitive features
func TestFeature_ContextAware(t *testing.T) {
    // 1. Create temporary module environment
    tmpDir, cleanup := shared.BuildCallGraphFromCodeWithDir(testCode)
    defer cleanup()
    
    // 2. Change to test context BEFORE creating generator
    originalDir, _ := os.Getwd()
    defer os.Chdir(originalDir)
    os.Chdir(tmpDir)
    
    // 3. NOW create the generator (context-sensitive)
    generator := output.NewFBOMGenerator(true, config)
    
    // 4. Test the feature behavior
    // This pattern prevents context detection bugs
}
```

### Common Development Tasks

#### Adding New Analysis Features (TDD Approach)
1. **RED**: Write feature tests defining expected behavior
2. **RED**: Write unit tests for individual components  
3. **GREEN**: Create analyzer in appropriate `pkg/analysis/` subdirectory
4. **GREEN**: Add corresponding models in `pkg/models/`
5. **GREEN**: Integrate into main pipeline in `pkg/output/fbom_generator.go`
6. **REFACTOR**: Clean up implementation and extract patterns
7. **INTEGRATE**: Add integration and e2e tests
8. **VERIFY**: Update FBOM specification if needed

#### Adding CVE Sources
1. Extend `pkg/cveloader/` for new data sources
2. Update `pkg/vulncheck/` for integration
3. Add mapping logic in `pkg/analysis/cve/`
4. Test with sample CVE data

#### Fixing Context Detection Issues
- **Remember**: Always call `NewFBOMGenerator()` after `os.Chdir()`
- **Pattern**: Build temporary environment first, then create generator
- **Common Issue**: Generator created in wrong directory leads to incorrect package classification

## Important Files & Their Roles

### Core Configuration
- `config.toml` - Analysis configuration and risk assessment rules
- `pkg/config/context_aware_config.go` - Module and package detection logic

### Key Analysis Files
- `pkg/output/fbom_generator.go` - Main FBOM generation orchestrator
- `pkg/analysis/rules/` - Classification and policy rules
- `pkg/analysis/shared/analyzer.go` - Shared analysis utilities

### Test Infrastructure
- `tests/shared/` - Common test utilities and helpers
- `tests/integration/fbom_generator_integration_test.go` - Main integration tests
- Test helper pattern: Create temp module, change directory, then create generator

### Quality Assurance
- `Makefile` - Comprehensive build and quality targets
- `.github/workflows/` - CI/CD pipelines
- Security scanning integrated via gosec

## Recent Major Improvements

### Test Infrastructure Refactoring
- Migrated from monolithic test files to organized test suites
- Fixed context detection timing issues in integration tests
- Improved test reliability and maintainability
- Added comprehensive bug regression test coverage

### Security Enhancements
- Fixed all gosec security issues (file permissions, path validation)
- Added security scanning to quality pipeline
- Implemented secure coding practices throughout

### Code Quality Improvements
- Resolved all TODO items in codebase
- Enhanced CVE database integration
- Improved function metadata extraction
- Better error handling and logging

## Common Pitfalls & Solutions

### Context Detection Issues
**Problem**: Functions classified incorrectly as external vs user-defined
**Solution**: Ensure generator is created in correct module context

### Test Reliability
**Problem**: Brittle tests that depend on debug output or specific formatting
**Solution**: Test actual FBOM structure and functionality, not implementation details

### CVE Integration
**Problem**: Hardcoded CVE mappings or incomplete database integration
**Solution**: Use proper database lookups with function name matching

### Module Boundary Handling
**Problem**: Analysis fails across module boundaries
**Solution**: Ensure proper go.mod context and module path resolution

### TDD Benefits for This Project

#### Why TDD is Mandatory Here
1. **Complex Static Analysis**: Go call graph and SSA analysis is intricate - tests help verify correctness
2. **Context Sensitivity**: Generator behavior depends on module context - TDD prevents regression
3. **Security Focus**: Vulnerability detection requires precise behavior - tests ensure accuracy
4. **Integration Complexity**: Multiple analysis engines must work together - tests catch interface issues
5. **Regression Prevention**: Previous bug fixes show importance of test-first approach

#### TDD Enforcement Guidelines
- **No Code Without Tests**: All new functionality must have tests written first
- **Bug Reports → Tests**: Every bug report should result in a failing test before fixing
- **Quality Gate**: `make verify` must pass before any code merge
- **Test Coverage**: Aim for meaningful test coverage, not just percentage targets
- **Documentation**: Tests serve as living documentation of expected behavior

#### TDD Success Patterns from This Project
- **Context Detection Fix**: TDD revealed timing issues with generator creation
- **Reflection Analysis**: Step-by-step TDD helped build complex reflection detection
- **CVE Integration**: Test-first approach prevented hardcoded mapping bugs
- **Security Fixes**: TDD caught edge cases in path validation and file permissions

### Mandatory TDD Workflow Steps

**CRITICAL**: All new features and bug fixes MUST follow this exact workflow:

#### Phase 1: Unit Test Development (RED-GREEN-REFACTOR)

```bash
# 1. Craft a clear unit test for the output you expect from the program
#    Please create stubs for any undefined items we are expecting to use.

# 2. Run the test to verify it fails.
go test ./pkg/... -run YourNewTest

# 3. Ask for review: "Please review these tests to ensure they make sense"
#    (Human verification of test design before implementation)

# 4. Implement the code changes.
#    Write minimal code to make the test pass

# 5. Build the binary to make sure there are no build errors.
go build .

# 6. Run the failed test created and see that it passes.
go test ./pkg/... -run YourNewTest

# 7. Add additional unit tests to cover edge cases or other unique cases.
#    Expand test coverage for comprehensive validation

# 8. Run all unit tests and ensure they pass. 
#    Do not create skips - if roadblock, ask for review.
#    Sometimes we need to move the test to integration tests.
go test ./pkg/...

# 9. Ask for review: "Ready for integration phase review"
#    (Human verification before moving to integration)
```

#### Phase 2: Integration & Final Validation

```bash
# 1. Replicate the test in the integration tests to ensure 
#    the program is working as expected.
cd tests/integration/
# Create comprehensive integration test

# 2. If you run into a failing scenario and determine the cause 
#    is in the logic of the program, create a unit test to verify 
#    that before proceeding with a fix.

# 3. Run all integration tests and ensure they pass.
go test ./tests/integration/...

# 4. Run linting to ensure the code is clean.
make quality

# 5. Update all .md files to reflect the changes if necessary.
#    Update README.md, CLAUDE.md, FBOM_SPECIFICATION.md as needed

# 6. Cleanup any output files that were created so that they 
#    are not checked into version control.
git status  # Check for untracked files
# Remove any .fbom.json or temporary files

# 7. Ask for final review: "Ready for final sign-off and commit"
#    This is a good chance for real e2e testing, spot checking outputs, etc.

# 8. If all is good, provide a commit message using conventional commits
#    Example: "feat: add CVE severity analysis with risk scoring"
#             "fix: resolve context detection timing in generator creation"
```

#### TDD Enforcement Checkpoints

- **Checkpoint 1**: Tests must fail before implementation (RED phase verification)
- **Checkpoint 2**: Human review of test design before coding
- **Checkpoint 3**: Unit tests pass before integration (GREEN phase verification)  
- **Checkpoint 4**: Integration tests validate end-to-end behavior
- **Checkpoint 5**: Quality gates pass (linting, security, formatting)
- **Checkpoint 6**: Human review before commit (final validation)

#### TDD Quality Gates

```bash
# Must pass at each checkpoint:
make verify          # All tests + quality checks
make quality         # Formatting, linting, security
go test ./...        # Complete test suite
git status           # No untracked files
```

## Future Development Guidelines

### Adding New Features (TDD-First)
1. **RED**: Write failing tests defining desired behavior
2. **GREEN**: Implement minimal code to pass tests
3. **REFACTOR**: Clean up and follow existing package structure patterns
4. **INTEGRATE**: Add integration and e2e tests
5. **VERIFY**: Ensure security compliance (gosec passing)
6. **DOCUMENT**: Update FBOM specification and documentation (README, this file)

### Maintaining Quality
1. Always run `make quality` before commits
2. Add regression tests for bug fixes
3. Keep test organization clean and focused
4. Update this CLAUDE.md when making architectural changes

### Security Considerations
1. Validate all file paths and inputs
2. Use restrictive file permissions (0600 for sensitive files)
3. Regular dependency security scanning
4. Follow secure coding practices

## CLI Usage Patterns

### Basic Analysis
```bash
golang-fbom-generator -package .                    # Analyze current directory
golang-fbom-generator -package . -o                 # Save to file
golang-fbom-generator -package . -v                 # Verbose output
```

### Security Analysis
```bash
golang-fbom-generator -package . -live-cve-scan -o  # Live CVE scanning
golang-fbom-generator -package . -cve data.json     # CVE file analysis
golang-fbom-generator --auto-discover -v -o         # Multi-component analysis
```

### Advanced Options
```bash
golang-fbom-generator -package . -algo vta          # High-precision analysis
golang-fbom-generator -package . -max-depth 5       # Deep attack path analysis
golang-fbom-generator -package . -library           # Library mode analysis
```

## Integration Points

### CI/CD Integration
- Use `make verify` for complete validation
- Check FBOM output for security thresholds
- Automated CVE reachability analysis

### External Tools
- JSON Schema validation for FBOM output
- Integration with vulnerability databases
- Security pipeline integration

This project represents a significant effort in Go security analysis tooling and aims to establish standards for function-level bill of materials generation. The architecture is designed for extensibility while maintaining security and reliability standards.

---
*This file should be updated whenever significant architectural changes are made to the project.*
