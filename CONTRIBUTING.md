# Contributing to golang-fbom-generator

Thank you for your interest in contributing to golang-fbom-generator! Since we're currently in beta, your contributions are especially valuable in helping us reach a stable release.

## 🚧 Beta Status

golang-fbom-generator is currently in beta. This means:
- The API and CLI may change between releases
- We're actively seeking feedback and bug reports
- Breaking changes may be introduced to improve the user experience
- Your input helps shape the stable release

## How to Contribute

### Reporting Issues
- Use our [issue templates](.github/ISSUE_TEMPLATE/) for bug reports and feature requests
- Provide detailed information about your environment and use case
- Include sample code or repositories when possible

### Beta Feedback
- Try golang-fbom-generator on your real-world projects
- Share your experience using the [Beta Feedback template](.github/ISSUE_TEMPLATE/beta_feedback.md)
- Let us know what works well and what could be improved

### Code Contributions

#### Getting Started
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/golang-fbom-generator.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Add tests for new functionality
6. Run tests: `make test`
7. Run linting: `make lint`
8. Commit your changes with a [conventional commit message](https://conventionalcommits.org/)
9. Push to your fork and create a pull request

#### Development Setup
```bash
# Install dependencies
go mod download

# Run tests
make test

# Run linting
make lint

# Build locally
make build

# Run with your changes
./golang-fbom-generator --help
```

#### Code Style
- Follow standard Go conventions
- Use `go fmt` to format your code
- Write meaningful commit messages
- Add tests for new functionality
- Update documentation as needed

### Documentation
- Help improve our documentation
- Add examples and use cases
- Fix typos and unclear explanations
- Translate documentation (if applicable)

## Development Guidelines

### Testing
- Write unit tests for new functions
- Add integration tests for new features
- Ensure all tests pass before submitting PRs
- Test on different Go versions when possible

### Performance
- Consider performance impact of changes
- Add benchmarks for performance-critical code
- Profile memory usage for large codebases

### Backward Compatibility
- While in beta, breaking changes are acceptable but should be:
  - Well documented in CHANGELOG.md
  - Discussed in issues/PRs before implementation
  - Communicated to users through release notes

## Release Process (Beta)

Since we're in beta:
1. Changes are merged to `main` branch
2. Beta releases are tagged as `v1.0.0-beta.X`
3. Release notes highlight breaking changes
4. Community feedback is incorporated for next release

## Questions?

- Open an issue for questions about contributing
- Use the [Beta Feedback template](.github/ISSUE_TEMPLATE/beta_feedback.md) for general feedback
- Check existing issues and PRs before creating new ones

## Code of Conduct

Please be respectful and constructive in all interactions. We're building this together!

---

Thank you for helping make golang-fbom-generator better! 🚀