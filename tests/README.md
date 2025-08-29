# Test Structure

This directory contains the refactored test structure for golang-fbom-generator, organized by test type and purpose.

## Directory Structure

```
tests/
├── e2e/                # End-to-end tests against example codebases
├── feature/            # Feature-specific functionality tests  
├── integration/        # Component integration tests
└── shared/             # Shared test utilities and types
```

## Test Categories

### 🔄 E2E Tests (`tests/e2e/`)
**Purpose**: End-to-end testing against real example codebases
- `fbom_examples_test.go` - Tests FBOM generation against all example projects
- `live_cve_test.go` - Tests live CVE scanning functionality
- `multi_component_test.go` - Tests multi-component project auto-discovery

**Run with**: `make test-e2e`

### ⚙️ Feature Tests (`tests/feature/`)
**Purpose**: Testing specific features and functionality
- `entry_points_test.go` - Entry point pattern matching and configuration
- `algorithm_selection_test.go` - Call graph algorithm testing (rta, cha, static, vta)
- `dependency_clustering_test.go` - Dependency clustering and attack surface analysis

**Run with**: `make test-feature`

### 🔗 Integration Tests (`tests/integration/`)
**Purpose**: Testing component integration and cross-module functionality
- Currently being refactored to test proper component integration
- Will focus on testing how different analyzers work together

**Run with**: `make test-integration`

### 📚 Shared (`tests/shared/`)
**Purpose**: Common utilities and types used across all test packages
- `types.go` - Common test data structures (FBOM, expectations, etc.)
- `helpers.go` - Shared helper functions (GetBinaryPath, ParseFBOM, etc.)

## Running Tests

**Prerequisites**: All tests require the binary to be built first:
```bash
make build
```

### Individual Test Categories
```bash
make test-e2e          # End-to-end tests
make test-feature      # Feature tests  
make test-integration  # Integration tests
```

### All Tests
```bash
make test-all          # Unit + E2E + Feature + Integration
```

### Unit Tests (unchanged)
```bash
make test              # Unit tests in pkg/
```

## Adding New Tests

### E2E Test
1. Add test case to `tests/e2e/testcases/`
2. Create corresponding example project in `examples/`
3. E2E test will automatically pick it up

### Feature Test  
1. Add test to appropriate file in `tests/feature/`
2. Or create new file for new feature category

### Integration Test
1. Add component integration test to `tests/integration/`
2. Focus on testing how analyzers work together
