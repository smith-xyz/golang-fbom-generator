package common

import (
	"fmt"
	"log"
	"os"
	"time"
)

// User represents a user in the system
type User struct {
	ID      int       `json:"id"`
	Name    string    `json:"name"`
	Email   string    `json:"email"`
	Role    string    `json:"role"`
	Created time.Time `json:"created"`
}

// Logger provides logging functionality shared across applications
type Logger struct {
	prefix string
}

// NewLogger creates a new logger with the given prefix
func NewLogger(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	log.Printf("[%s] INFO: %s", l.prefix, msg)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error) {
	log.Printf("[%s] ERROR: %s - %v", l.prefix, msg, err)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("[%s] DEBUG: %s", l.prefix, msg)
	}
}

// DatabaseConnection simulates a database connection
type DatabaseConnection struct {
	connectionString string
	logger           *Logger
}

// NewDatabaseConnection creates a new database connection
func NewDatabaseConnection(connStr string, logger *Logger) *DatabaseConnection {
	return &DatabaseConnection{
		connectionString: connStr,
		logger:           logger,
	}
}

// Connect simulates connecting to the database
func (db *DatabaseConnection) Connect() error {
	db.logger.Info(fmt.Sprintf("Connecting to database: %s", db.connectionString))
	// Simulate connection time
	time.Sleep(100 * time.Millisecond)
	db.logger.Info("Database connection established")
	return nil
}

// Close simulates closing the database connection
func (db *DatabaseConnection) Close() error {
	db.logger.Info("Closing database connection")
	return nil
}

// GetUser retrieves a user by ID
func (db *DatabaseConnection) GetUser(id int) (*User, error) {
	db.logger.Debug(fmt.Sprintf("Fetching user with ID: %d", id))

	// Simulate database query
	user := &User{
		ID:      id,
		Name:    fmt.Sprintf("User%d", id),
		Email:   fmt.Sprintf("user%d@example.com", id),
		Role:    "user",
		Created: time.Now().AddDate(0, 0, -30), // 30 days ago
	}

	return user, nil
}

// CreateUser creates a new user
func (db *DatabaseConnection) CreateUser(name, email, role string) (*User, error) {
	db.logger.Info(fmt.Sprintf("Creating new user: %s (%s)", name, email))

	user := &User{
		ID:      generateUserID(),
		Name:    name,
		Email:   email,
		Role:    role,
		Created: time.Now(),
	}

	db.logger.Info(fmt.Sprintf("User created with ID: %d", user.ID))
	return user, nil
}

// ListUsers retrieves all users
func (db *DatabaseConnection) ListUsers() ([]*User, error) {
	db.logger.Debug("Fetching all users")

	// Simulate returning some users
	users := []*User{
		{ID: 1, Name: "Alice", Email: "alice@example.com", Role: "admin", Created: time.Now().AddDate(0, 0, -60)},
		{ID: 2, Name: "Bob", Email: "bob@example.com", Role: "user", Created: time.Now().AddDate(0, 0, -45)},
		{ID: 3, Name: "Charlie", Email: "charlie@example.com", Role: "user", Created: time.Now().AddDate(0, 0, -30)},
	}

	return users, nil
}

// UpdateUser updates an existing user
func (db *DatabaseConnection) UpdateUser(id int, name, email, role string) (*User, error) {
	db.logger.Info(fmt.Sprintf("Updating user %d", id))

	user := &User{
		ID:      id,
		Name:    name,
		Email:   email,
		Role:    role,
		Created: time.Now().AddDate(0, 0, -15), // Assume created 15 days ago
	}

	return user, nil
}

// DeleteUser deletes a user by ID
func (db *DatabaseConnection) DeleteUser(id int) error {
	db.logger.Info(fmt.Sprintf("Deleting user %d", id))
	// Simulate deletion
	return nil
}

// Configuration holds application configuration
type Configuration struct {
	DatabaseURL string `json:"database_url"`
	Port        int    `json:"port"`
	Debug       bool   `json:"debug"`
	AppName     string `json:"app_name"`
}

// LoadConfiguration loads configuration from environment or defaults
func LoadConfiguration(appName string) *Configuration {
	config := &Configuration{
		DatabaseURL: getEnv("DATABASE_URL", "sqlite:///tmp/app.db"),
		Port:        getEnvInt("PORT", 8080),
		Debug:       getEnv("DEBUG", "") != "",
		AppName:     appName,
	}

	return config
}

// ValidateConfiguration validates the configuration
func ValidateConfiguration(config *Configuration) error {
	if config.DatabaseURL == "" {
		return fmt.Errorf("database URL is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if config.AppName == "" {
		return fmt.Errorf("app name is required")
	}
	return nil
}

// Utility functions

// generateUserID simulates generating a new user ID
func generateUserID() int {
	return int(time.Now().Unix() % 10000)
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt gets an environment variable as an integer with a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := fmt.Sscanf(value, "%d", &defaultValue); err == nil && intValue == 1 {
			return defaultValue
		}
	}
	return defaultValue
}

// HealthCheck performs a health check on the system
func HealthCheck(db *DatabaseConnection) error {
	// Check database connectivity
	if db != nil {
		// Simulate a simple health check
		_, err := db.GetUser(1)
		if err != nil {
			return fmt.Errorf("database health check failed: %w", err)
		}
	}

	// Check other system components
	return nil
}

// InitializeApplication performs common initialization tasks
func InitializeApplication(appName string) (*Configuration, *Logger, error) {
	logger := NewLogger(appName)
	logger.Info("Initializing application")

	config := LoadConfiguration(appName)
	if err := ValidateConfiguration(config); err != nil {
		return nil, nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	logger.Info("Application initialized successfully")
	return config, logger, nil
}
