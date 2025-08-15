package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Auth     AuthConfig     `yaml:"auth"`
	Security SecurityConfig `yaml:"security"`
	Worker   WorkerConfig   `yaml:"worker"`
	Legacy   LegacyConfig   `yaml:"legacy"`
	Server   ServerConfig   `yaml:"server"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"ssl_mode"`
}

type AuthConfig struct {
	JWTSecret        string `yaml:"jwt_secret"`
	TokenExpiry      int    `yaml:"token_expiry"`
	BCryptCost       int    `yaml:"bcrypt_cost"`
	MaxLoginAttempts int    `yaml:"max_login_attempts"`
}

type SecurityConfig struct {
	EncryptionKey    string   `yaml:"encryption_key"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	RateLimitEnabled bool     `yaml:"rate_limit_enabled"`
	CSRFProtection   bool     `yaml:"csrf_protection"`
}

type WorkerConfig struct {
	Concurrency     int    `yaml:"concurrency"`
	QueueName       string `yaml:"queue_name"`
	RetryAttempts   int    `yaml:"retry_attempts"`
	ProcessInterval int    `yaml:"process_interval"`
}

type LegacyConfig struct {
	XMLImportPath  string `yaml:"xml_import_path"`
	CSVImportPath  string `yaml:"csv_import_path"`
	YAMLImportPath string `yaml:"yaml_import_path"`
	BackupEnabled  bool   `yaml:"backup_enabled"`
}

type ServerConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	ReadTimeout    int    `yaml:"read_timeout"`
	WriteTimeout   int    `yaml:"write_timeout"`
	MaxHeaderBytes int    `yaml:"max_header_bytes"`
}

func LoadConfig(configPath string) (*Config, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return default config if file doesn't exist
		return getDefaultConfig(), nil
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults for missing values
	applyDefaults(&config)

	return &config, nil
}

func getDefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     3306,
			Username: "app_user",
			Password: "app_password",
			Database: "app_db",
			SSLMode:  "disable",
		},
		Auth: AuthConfig{
			JWTSecret:        "default_jwt_secret_change_me",
			TokenExpiry:      3600,
			BCryptCost:       12,
			MaxLoginAttempts: 5,
		},
		Security: SecurityConfig{
			EncryptionKey:    "default_encryption_key_32_chars!!",
			AllowedOrigins:   []string{"*"},
			RateLimitEnabled: true,
			CSRFProtection:   true,
		},
		Worker: WorkerConfig{
			Concurrency:     5,
			QueueName:       "default_queue",
			RetryAttempts:   3,
			ProcessInterval: 30,
		},
		Legacy: LegacyConfig{
			XMLImportPath:  "",
			CSVImportPath:  "",
			YAMLImportPath: "",
			BackupEnabled:  false,
		},
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8080,
			ReadTimeout:    30,
			WriteTimeout:   30,
			MaxHeaderBytes: 1048576,
		},
	}
}

func applyDefaults(config *Config) {
	defaults := getDefaultConfig()

	// Apply database defaults
	if config.Database.Host == "" {
		config.Database.Host = defaults.Database.Host
	}
	if config.Database.Port == 0 {
		config.Database.Port = defaults.Database.Port
	}

	// Apply auth defaults
	if config.Auth.JWTSecret == "" {
		config.Auth.JWTSecret = defaults.Auth.JWTSecret
	}
	if config.Auth.TokenExpiry == 0 {
		config.Auth.TokenExpiry = defaults.Auth.TokenExpiry
	}
	if config.Auth.BCryptCost == 0 {
		config.Auth.BCryptCost = defaults.Auth.BCryptCost
	}

	// Apply security defaults
	if config.Security.EncryptionKey == "" {
		config.Security.EncryptionKey = defaults.Security.EncryptionKey
	}
	if len(config.Security.AllowedOrigins) == 0 {
		config.Security.AllowedOrigins = defaults.Security.AllowedOrigins
	}

	// Apply worker defaults
	if config.Worker.Concurrency == 0 {
		config.Worker.Concurrency = defaults.Worker.Concurrency
	}
	if config.Worker.QueueName == "" {
		config.Worker.QueueName = defaults.Worker.QueueName
	}

	// Apply server defaults
	if config.Server.Host == "" {
		config.Server.Host = defaults.Server.Host
	}
	if config.Server.Port == 0 {
		config.Server.Port = defaults.Server.Port
	}
}

func ValidateConfig(config *Config) error {
	// Validate required fields
	if config.Auth.JWTSecret == "default_jwt_secret_change_me" {
		return fmt.Errorf("JWT secret must be changed from default value")
	}

	if len(config.Auth.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	if len(config.Security.EncryptionKey) != 32 {
		return fmt.Errorf("encryption key must be exactly 32 characters long")
	}

	if config.Database.Username == "" {
		return fmt.Errorf("database username is required")
	}

	if config.Database.Password == "" {
		return fmt.Errorf("database password is required")
	}

	return nil
}

func SaveConfig(config *Config, configPath string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
