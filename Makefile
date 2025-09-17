# golang-fbom-generator Makefile
# Function Bill of Materials (FBOM) Generator for Go Applications

# Project configuration
PROJECT_NAME := golang-fbom-generator
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0-beta")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_TIME_RFC3339 := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_USER := $(shell whoami)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

# Go configuration
GO := go
GOCMD := $(GO)
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Build configuration
BINARY_NAME := golang-fbom-generator
BINARY_PATH := ./$(BINARY_NAME)
MAIN_FILE := main.go

# Directories
SRC_DIR := .
PKG_DIR := ./pkg/...
TEST_DIR := ./tests
INTEGRATION_TEST_DIR := ./tests/integration
EXAMPLES_DIR := ./examples

# Build flags
LDFLAGS := -ldflags "\
	-X 'github.com/smith-xyz/golang-fbom-generator/pkg/version.Version=$(VERSION)' \
	-X 'github.com/smith-xyz/golang-fbom-generator/pkg/version.GitCommit=$(COMMIT)' \
	-X 'github.com/smith-xyz/golang-fbom-generator/pkg/version.GitBranch=$(GIT_BRANCH)' \
	-X 'github.com/smith-xyz/golang-fbom-generator/pkg/version.BuildTime=$(BUILD_TIME_RFC3339)' \
	-X 'github.com/smith-xyz/golang-fbom-generator/pkg/version.BuildUser=$(BUILD_USER)'"

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

##@ General

.PHONY: help
help: ## Display this help message
	@echo "$(BLUE)golang-fbom-generator - Go Function Bill of Materials (FBOM) Generator$(NC)"
	@echo "$(BLUE)Function Bill of Materials (FBOM) Generator$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(CYAN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(PURPLE)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: version
version: ## Show version information
	@echo "$(BLUE)golang-fbom-generator Version Information:$(NC)"
	@echo "  Version: $(VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Commit: $(COMMIT)"
	@echo "  Go Version: $(shell $(GO) version)"

##@ Build

.PHONY: build
build: ## Build the golang-fbom-generator binary
	@echo "$(BLUE)Building golang-fbom-generator...$(NC)"
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_PATH) $(MAIN_FILE)
	@echo "$(GREEN)✅ Build completed: $(BINARY_PATH)$(NC)"

.PHONY: ci
ci: clean deps lint test test-integration build ## Run full build pipeline (clean, deps, lint, test, test-integration, build)
	@echo "$(GREEN)🎉 Full build pipeline completed successfully!$(NC)"

.PHONY: build-cross
build-cross: ## Build for multiple platforms
	@echo "$(BLUE)Cross-compiling for multiple platforms...$(NC)"
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 $(MAIN_FILE)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 $(MAIN_FILE)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe $(MAIN_FILE)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 $(MAIN_FILE)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 $(MAIN_FILE)
	@echo "$(GREEN)✅ Cross-compilation completed in dist/$(NC)"

##@ Dependencies

.PHONY: deps
deps: ## Download and verify dependencies
	@echo "$(BLUE)Managing dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) verify
	$(GOMOD) tidy
	@echo "$(GREEN)✅ Dependencies updated$(NC)"

.PHONY: deps-update
deps-update: ## Update all dependencies to latest versions
	@echo "$(BLUE)Updating dependencies...$(NC)"
	$(GOGET) -u ./...
	$(GOMOD) tidy
	@echo "$(GREEN)✅ Dependencies updated to latest versions$(NC)"

.PHONY: deps-vendor
deps-vendor: ## Create vendor directory
	@echo "$(BLUE)Creating vendor directory...$(NC)"
	$(GOMOD) vendor
	@echo "$(GREEN)✅ Vendor directory created$(NC)"

##@ Testing

.PHONY: test
test: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	$(GOTEST) -race -coverprofile=coverage.out ./pkg/...
	@echo "$(GREEN)✅ Unit tests completed$(NC)"

.PHONY: test-coverage
test-coverage: test ## Run tests and generate coverage report
	@echo "$(BLUE)Generating coverage report...$(NC)"
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✅ Coverage report generated: coverage.html$(NC)"

.PHONY: test-e2e
test-e2e: build ## Run end-to-end tests against example codebases
	@echo "$(BLUE)Running E2E tests...$(NC)"
	cd tests/e2e && $(GOTEST)
	@echo "$(GREEN)✅ E2E tests completed$(NC)"

.PHONY: test-feature
test-feature: build ## Run feature-specific tests
	@echo "$(BLUE)Running feature tests...$(NC)"
	cd tests/feature && $(GOTEST)
	@echo "$(GREEN)✅ Feature tests completed$(NC)"

.PHONY: test-integration
test-integration: build ## Run component integration tests
	@echo "$(BLUE)Running integration tests...$(NC)"
	cd tests/integration && $(GOTEST)
	@echo "$(GREEN)✅ Integration tests completed$(NC)"

.PHONY: test-bugs
test-bugs: ## Run bug regression tests
	@echo "$(BLUE)Running bug regression tests...$(NC)"
	cd tests/bugs && $(GOTEST)
	@echo "$(GREEN)✅ Bug regression tests completed$(NC)"

.PHONY: test-all
test-all: test test-e2e test-feature test-integration test-bugs ## Run all tests (unit + e2e + feature + integration + bugs)
	@echo "$(GREEN)🎉 All tests completed successfully!$(NC)"

##@ Quality Assurance

.PHONY: lint
lint: ## Run linter
	@echo "$(BLUE)Running linter...$(NC)"
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
		echo "$(GREEN)✅ Linting completed$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  golangci-lint not found, skipping linting$(NC)"; \
		echo "$(YELLOW)   Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest$(NC)"; \
	fi

.PHONY: fmt
fmt: ## Format Go code
	@echo "$(BLUE)Formatting Go code...$(NC)"
	$(GOFMT) -s -w .
	@echo "$(GREEN)✅ Code formatted$(NC)"

.PHONY: fmt-check
fmt-check: ## Check if code is formatted
	@echo "$(BLUE)Checking code formatting...$(NC)"
	@if [ -n "$$($(GOFMT) -l .)" ]; then \
		echo "$(RED)❌ Code is not formatted. Run 'make fmt' to fix.$(NC)"; \
		$(GOFMT) -l .; \
		exit 1; \
	else \
		echo "$(GREEN)✅ Code is properly formatted$(NC)"; \
	fi

.PHONY: vet
vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(NC)"
	$(GO) vet ./...
	@echo "$(GREEN)✅ Go vet completed$(NC)"

.PHONY: sec
sec: ## Run security scanner (gosec)
	@echo "$(BLUE)Running security scanner...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -quiet -exclude-dir=examples -exclude-dir=tests/shared ./...; \
		echo "$(GREEN)✅ Security scan completed$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  gosec not found, skipping security scan$(NC)"; \
		echo "$(YELLOW)   Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest$(NC)"; \
	fi

.PHONY: quality
quality: fmt-check vet lint sec test-all ## Run all quality assurance checks including comprehensive tests
	@echo "$(GREEN)✅ All quality checks completed$(NC)"

##@ Cleanup

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	$(GOCLEAN)
	rm -f $(BINARY_PATH)
	rm -f coverage.out coverage.html
	rm -f *.fbom.json
	rm -rf dist/
	@echo "$(GREEN)✅ Clean completed$(NC)"

.PHONY: clean-deps
clean-deps: ## Clean dependency cache
	@echo "$(BLUE)Cleaning dependency cache...$(NC)"
	$(GOCLEAN) -modcache
	@echo "$(GREEN)✅ Dependency cache cleaned$(NC)"

.PHONY: clean-all
clean-all: clean clean-deps ## Clean everything including dependency cache
	@echo "$(GREEN)✅ Complete cleanup finished$(NC)"

.PHONY: watch
watch: ## Watch for changes and run tests (requires entr)
	@echo "$(BLUE)Watching for changes...$(NC)"
	@if command -v entr >/dev/null 2>&1; then \
		find . -name "*.go" | entr -c make dev-test; \
	else \
		echo "$(RED)❌ entr not found. Install with: brew install entr (macOS) or apt-get install entr (Ubuntu)$(NC)"; \
	fi

# Include local development overrides if present
-include Makefile.local 