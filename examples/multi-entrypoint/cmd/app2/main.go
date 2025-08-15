package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"multi-entrypoint/internal/common"
)

// App2 is a CLI tool for managing users and performing administrative tasks
func main() {
	fmt.Println("Starting App2 - CLI Tool")

	// Define command line flags
	var (
		command    = flag.String("command", "", "Command to execute: list, create, get, update, delete, health")
		userID     = flag.Int("id", 0, "User ID for get, update, delete operations")
		userName   = flag.String("name", "", "User name for create, update operations")
		userEmail  = flag.String("email", "", "User email for create, update operations")
		userRole   = flag.String("role", "user", "User role for create, update operations")
		outputJSON = flag.Bool("json", false, "Output in JSON format")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Initialize the application using shared library
	config, logger, err := common.InitializeApplication("app2-cli")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Set debug mode if verbose
	if *verbose {
		os.Setenv("DEBUG", "1")
	}

	// Validate command
	if *command == "" {
		printUsage()
		os.Exit(1)
	}

	// Set up database connection
	db := common.NewDatabaseConnection(config.DatabaseURL, logger)
	if err := db.Connect(); err != nil {
		logger.Error("Failed to connect to database", err)
		os.Exit(1)
	}
	defer db.Close()

	// Execute the requested command
	if err := executeCommand(*command, db, logger, *userID, *userName, *userEmail, *userRole, *outputJSON); err != nil {
		logger.Error("Command execution failed", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// printUsage prints usage information for the CLI tool
func printUsage() {
	fmt.Println("Usage: app2 -command <command> [options]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  list     - List all users")
	fmt.Println("  create   - Create a new user (requires -name, -email)")
	fmt.Println("  get      - Get a user by ID (requires -id)")
	fmt.Println("  update   - Update a user (requires -id, -name, -email)")
	fmt.Println("  delete   - Delete a user (requires -id)")
	fmt.Println("  health   - Perform health check")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -id int       User ID")
	fmt.Println("  -name string  User name")
	fmt.Println("  -email string User email")
	fmt.Println("  -role string  User role (default: user)")
	fmt.Println("  -json         Output in JSON format")
	fmt.Println("  -verbose      Enable verbose logging")
}

// executeCommand executes the requested command
func executeCommand(command string, db *common.DatabaseConnection, logger *common.Logger,
	userID int, userName, userEmail, userRole string, outputJSON bool) error {

	switch command {
	case "list":
		return cmdListUsers(db, logger, outputJSON)
	case "create":
		return cmdCreateUser(db, logger, userName, userEmail, userRole, outputJSON)
	case "get":
		return cmdGetUser(db, logger, userID, outputJSON)
	case "update":
		return cmdUpdateUser(db, logger, userID, userName, userEmail, userRole, outputJSON)
	case "delete":
		return cmdDeleteUser(db, logger, userID)
	case "health":
		return cmdHealthCheck(db, logger, outputJSON)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

// Command implementations

func cmdListUsers(db *common.DatabaseConnection, logger *common.Logger, outputJSON bool) error {
	logger.Info("Listing all users")

	users, err := db.ListUsers()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if outputJSON {
		return json.NewEncoder(os.Stdout).Encode(users)
	}

	fmt.Printf("Found %d users:\n", len(users))
	for _, user := range users {
		fmt.Printf("  ID: %d, Name: %s, Email: %s, Role: %s, Created: %s\n",
			user.ID, user.Name, user.Email, user.Role, user.Created.Format("2006-01-02"))
	}

	return nil
}

func cmdCreateUser(db *common.DatabaseConnection, logger *common.Logger,
	name, email, role string, outputJSON bool) error {

	if name == "" || email == "" {
		return fmt.Errorf("name and email are required for create command")
	}

	logger.Info(fmt.Sprintf("Creating user: %s (%s)", name, email))

	user, err := db.CreateUser(name, email, role)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	if outputJSON {
		return json.NewEncoder(os.Stdout).Encode(user)
	}

	fmt.Printf("User created successfully:\n")
	fmt.Printf("  ID: %d\n", user.ID)
	fmt.Printf("  Name: %s\n", user.Name)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Role: %s\n", user.Role)
	fmt.Printf("  Created: %s\n", user.Created.Format("2006-01-02 15:04:05"))

	return nil
}

func cmdGetUser(db *common.DatabaseConnection, logger *common.Logger, userID int, outputJSON bool) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required for get command")
	}

	logger.Info(fmt.Sprintf("Getting user with ID: %d", userID))

	user, err := db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if outputJSON {
		return json.NewEncoder(os.Stdout).Encode(user)
	}

	fmt.Printf("User details:\n")
	fmt.Printf("  ID: %d\n", user.ID)
	fmt.Printf("  Name: %s\n", user.Name)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Role: %s\n", user.Role)
	fmt.Printf("  Created: %s\n", user.Created.Format("2006-01-02 15:04:05"))

	return nil
}

func cmdUpdateUser(db *common.DatabaseConnection, logger *common.Logger,
	userID int, name, email, role string, outputJSON bool) error {

	if userID == 0 {
		return fmt.Errorf("user ID is required for update command")
	}
	if name == "" || email == "" {
		return fmt.Errorf("name and email are required for update command")
	}

	logger.Info(fmt.Sprintf("Updating user %d", userID))

	user, err := db.UpdateUser(userID, name, email, role)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if outputJSON {
		return json.NewEncoder(os.Stdout).Encode(user)
	}

	fmt.Printf("User updated successfully:\n")
	fmt.Printf("  ID: %d\n", user.ID)
	fmt.Printf("  Name: %s\n", user.Name)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Role: %s\n", user.Role)

	return nil
}

func cmdDeleteUser(db *common.DatabaseConnection, logger *common.Logger, userID int) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required for delete command")
	}

	logger.Info(fmt.Sprintf("Deleting user %d", userID))

	if err := db.DeleteUser(userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	fmt.Printf("User %d deleted successfully\n", userID)
	return nil
}

func cmdHealthCheck(db *common.DatabaseConnection, logger *common.Logger, outputJSON bool) error {
	logger.Info("Performing health check")

	if err := common.HealthCheck(db); err != nil {
		if outputJSON {
			result := map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}

		fmt.Printf("Health check failed: %v\n", err)
		return err
	}

	if outputJSON {
		result := map[string]string{
			"status":  "healthy",
			"service": "app2-cli",
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Println("Health check passed - all systems operational")
	return nil
}

// Additional utility functions for CLI operations

func validateUserID(idStr string) (int, error) {
	if idStr == "" {
		return 0, fmt.Errorf("user ID cannot be empty")
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, fmt.Errorf("invalid user ID: %s", idStr)
	}

	if id <= 0 {
		return 0, fmt.Errorf("user ID must be greater than 0")
	}

	return id, nil
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	// Simple email validation
	if len(email) < 3 || !contains(email, "@") || !contains(email, ".") {
		return fmt.Errorf("invalid email format: %s", email)
	}

	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)/2-len(substr)/2:len(s)/2+len(substr)/2+len(substr)%2] == substr
}
