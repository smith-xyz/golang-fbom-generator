# Multi-Entrypoint Example Project

This project demonstrates a proper Go project structure with multiple entry points (multiple main functions that can be built into separate executables).

## Project Structure

```
multi-entrypoint/
├── cmd/
│   ├── app1/
│   │   └── main.go          # Web server application
│   └── app2/
│       └── main.go          # CLI tool application
├── internal/
│   └── common/
│       └── library.go       # Shared library code
├── go.mod
└── README.md
```

## Applications

### App1 - Web Server

A REST API web server that provides user management endpoints.

**Build and run:**
```bash
go build -o bin/webserver ./cmd/app1
./bin/webserver
```

**Endpoints:**
- `GET /health` - Health check
- `GET /users` - List all users
- `POST /users` - Create a new user
- `GET /users/{id}` - Get user by ID
- `PUT /users/{id}` - Update user by ID
- `DELETE /users/{id}` - Delete user by ID

### App2 - CLI Tool

A command-line interface for managing users and performing administrative tasks.

**Build and run:**
```bash
go build -o bin/cli-tool ./cmd/app2
./bin/cli-tool -command list
./bin/cli-tool -command create -name "John Doe" -email "john@example.com"
./bin/cli-tool -command get -id 1
```

**Commands:**
- `list` - List all users
- `create` - Create a new user
- `get` - Get a user by ID
- `update` - Update a user
- `delete` - Delete a user
- `health` - Perform health check

## Shared Library

The `internal/common` package contains shared functionality used by both applications:

- **User management:** Data structures and database operations
- **Logging:** Structured logging with different levels
- **Configuration:** Environment-based configuration management
- **Health checks:** System health monitoring
- **Database simulation:** Mock database operations

## Entry Points Analysis

This project is perfect for testing entry point analysis because:

1. **Multiple main functions:** Each cmd subdirectory has its own main function
2. **Shared dependencies:** Both applications use the common library
3. **Different execution paths:** Web server vs CLI tool have different call graphs
4. **Realistic structure:** Follows Go project layout conventions

When analyzing with golang-fbom-generator, you can:
- Analyze the entire project to see all entry points
- Analyze specific applications (cmd/app1 or cmd/app2)
- Use entry point patterns to focus on specific functions

## Environment Variables

- `DATABASE_URL` - Database connection string (default: sqlite:///tmp/app.db)
- `PORT` - Web server port (default: 8080)
- `DEBUG` - Enable debug logging (default: empty/false)
