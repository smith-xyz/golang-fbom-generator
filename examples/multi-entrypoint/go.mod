module multi-entrypoint

go 1.21

// This is a multi-entrypoint Go project that demonstrates:
// - Multiple main functions in different cmd subdirectories
// - Shared internal library code
// - Proper Go project structure for building multiple executables

// Build commands:
// go build -o bin/webserver ./cmd/app1
// go build -o bin/cli-tool ./cmd/app2
