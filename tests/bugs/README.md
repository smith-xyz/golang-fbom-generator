# Bug Tests

This directory contains regression tests for specific bugs that have been identified and fixed in the FBOM generator.

## Purpose

- **Bug Reproduction**: Each test reproduces a specific bug scenario
- **Regression Prevention**: Ensures fixed bugs don't reappear during refactoring
- **Documentation**: Serves as documentation of known issues and their fixes

## Current Bug Tests

The following bug tests are currently implemented:

1. **Bug 1** - `TestBug1_PackageInfoName`: Package info name incorrectly set to package name instead of module name
2. **Bug 2** - `TestBug2_CallGraphTotalFunctions`: Call graph total function count incorrect when adding uncalled functions
3. **Bug 3** - `TestBug3_CallTypeTransitive`: Call type incorrectly marking transitive functions as direct
4. **Bug 4** - `TestBug4_CallEdgeFilePathAndLineNumber`: Call graph file path and line number not being set correctly
5. **Bug 5** - `TestBug5_ReachableFunctionsCount`: ReachableFunctions defaulting to 1 instead of calculating actual count
6. **Bug 6** - `TestBug6_UnusedFunctionInclusion`: Unused standalone functions not being added to FBOM
7. **Bug 7** - `TestBug7_AnonymousFunctionCallGraph`: Anonymous functions not being added to call graph
8. **Bug 8** - `TestBug8_CallRelationshipPopulation`: Functions showing calls=null instead of listing called functions
9. **Bug 9** - `TestBug9_StructMethodDistance`: Struct methods showing incorrect distance calculations
10. **Bug 10** - `TestBug10_InterfaceMethodDistances`: Interface methods showing incorrect distance calculations
11. **Bug 11** - `TestBug11_CallGraphProcessing`: Call graph edges not being properly processed and matched to functions
12. **Bug 12** - `TestBug12_FbomDemoCallGraphProcessing`: Complex call patterns missing from FBOM in realistic scenarios

## Naming Convention

Tests should be named `TestBug{N}_{DescriptiveName}` where:
- `{N}` is a sequential bug number
- `{DescriptiveName}` briefly describes the bug

## Test Structure

Each bug test should:
1. Include a comment explaining what the bug was
2. Use real Go code that triggered the bug
3. Test through the complete FBOM generation pipeline
4. Assert the expected correct behavior

### Using Test Helpers

Use the `test_helpers` package for consistent test setup:

```go
import "golang-fbom-generator/tests/bugs/test_helpers"

// For context-aware testing (most bug tests need this)
callGraph, ssaProgram, tmpDir, err := test_helpers.BuildCallGraphFromCodeWithDir(testCode)
defer os.RemoveAll(tmpDir)

// Change to temporary directory so context-aware config works correctly
originalDir, _ := os.Getwd()
defer os.Chdir(originalDir)
os.Chdir(tmpDir)

// Now create generator - it will detect the temporary module
generator := output.NewFBOMGenerator(false, output.DefaultAnalysisConfig())
```

See `test_helpers/README.md` for complete documentation and examples.

## Running Tests

```bash
# Run all bug tests
make test-bugs

# Run specific bug test
cd tests/bugs && go test -v -run TestBug1_PackageInfoName
```
