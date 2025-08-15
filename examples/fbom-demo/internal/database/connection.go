package database

import (
	"errors"
	"io"
	"time"
)

// Connection interface for database operations
type Connection interface {
	// User operations
	CreateUser(username, email, passwordHash string) (int64, error)
	GetUserByID(userID int64) (*User, error)
	GetUserByUsername(username string) (*UserRecord, error)
	GetAllUsers() ([]*User, error)
	UpdateUser(userID int64, updates map[string]interface{}) error
	DeleteUser(userID int64) error

	// API Key operations
	StoreAPIKey(userID int64, apiKey string) error
	GetUserByAPIKey(apiKey string) (int64, error)

	// Data operations
	ExportUserData(format string) ([]byte, error)
	ImportUserData(file io.Reader, filename string) error

	// System operations
	CreateFullBackup() (string, error)
	CleanupOldData() error
	Close() error
}

// User represents a user in the system
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

// UserRecord represents internal user data with sensitive fields
type UserRecord struct {
	ID                 int64
	Username           string
	Email              string
	PasswordHash       string
	LegacyPasswordHash string
	IsAdmin            bool
	CreatedAt          time.Time
	LastLogin          *time.Time
}

// MockConnection implements Connection interface for demo purposes
type MockConnection struct {
	users   map[int64]*UserRecord
	nextID  int64
	apiKeys map[string]int64
}

func Connect(config *DatabaseConfig) (Connection, error) {
	// Return mock connection for demo
	return &MockConnection{
		users:   make(map[int64]*UserRecord),
		nextID:  1,
		apiKeys: make(map[string]int64),
	}, nil
}

// Mock implementation of database operations
func (m *MockConnection) CreateUser(username, email, passwordHash string) (int64, error) {
	userID := m.nextID
	m.nextID++

	m.users[userID] = &UserRecord{
		ID:           userID,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		IsAdmin:      false,
		CreatedAt:    time.Now(),
	}

	return userID, nil
}

func (m *MockConnection) GetUserByID(userID int64) (*User, error) {
	record, exists := m.users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	return &User{
		ID:        record.ID,
		Username:  record.Username,
		Email:     record.Email,
		IsAdmin:   record.IsAdmin,
		CreatedAt: record.CreatedAt,
	}, nil
}

func (m *MockConnection) GetUserByUsername(username string) (*UserRecord, error) {
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (m *MockConnection) GetAllUsers() ([]*User, error) {
	users := make([]*User, 0, len(m.users))
	for _, record := range m.users {
		users = append(users, &User{
			ID:        record.ID,
			Username:  record.Username,
			Email:     record.Email,
			IsAdmin:   record.IsAdmin,
			CreatedAt: record.CreatedAt,
		})
	}
	return users, nil
}

func (m *MockConnection) UpdateUser(userID int64, updates map[string]interface{}) error {
	user, exists := m.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	if email, ok := updates["email"].(string); ok {
		user.Email = email
	}
	if passwordHash, ok := updates["password_hash"].(string); ok {
		user.PasswordHash = passwordHash
	}
	if isAdmin, ok := updates["is_admin"].(bool); ok {
		user.IsAdmin = isAdmin
	}
	if lastLogin, ok := updates["last_login"].(time.Time); ok {
		user.LastLogin = &lastLogin
	}

	return nil
}

func (m *MockConnection) DeleteUser(userID int64) error {
	if _, exists := m.users[userID]; !exists {
		return errors.New("user not found")
	}
	delete(m.users, userID)
	return nil
}

func (m *MockConnection) StoreAPIKey(userID int64, apiKey string) error {
	m.apiKeys[apiKey] = userID
	return nil
}

func (m *MockConnection) GetUserByAPIKey(apiKey string) (int64, error) {
	userID, exists := m.apiKeys[apiKey]
	if !exists {
		return 0, errors.New("invalid API key")
	}
	return userID, nil
}

func (m *MockConnection) ExportUserData(format string) ([]byte, error) {
	// Mock export functionality
	return []byte("mock export data"), nil
}

func (m *MockConnection) ImportUserData(file io.Reader, filename string) error {
	// Mock import functionality
	return nil
}

func (m *MockConnection) CreateFullBackup() (string, error) {
	return "backup_123456", nil
}

func (m *MockConnection) CleanupOldData() error {
	// Mock cleanup
	return nil
}

func (m *MockConnection) Close() error {
	return nil
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSLMode  string
}

// Migrator handles database migrations
type Migrator struct {
	db Connection
}

func NewMigrator(db Connection) *Migrator {
	return &Migrator{db: db}
}

func (m *Migrator) MigrateUp() error {
	// Mock migration
	return nil
}

// adding a random no call function
func databaseConnectionHelper() (Connection, error) {
	db, err := Connect(&DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Username: "postgres",
		Password: "postgres",
		Database: "postgres",
		SSLMode:  "disable",
	})
	return db, err
}
