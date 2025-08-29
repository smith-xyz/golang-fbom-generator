package legacy

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"fbom-demo/internal/config"
	"fbom-demo/internal/database"
	"fbom-demo/pkg/analytics"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Importer struct {
	config *config.LegacyConfig
	db     database.Connection
}

type LegacyUserRecord struct {
	XMLName  xml.Name `xml:"user"`
	Username string   `xml:"username"`
	Email    string   `xml:"email"`
	Role     string   `xml:"role"`
	Active   bool     `xml:"active"`
}

type LegacyDataFormat struct {
	XMLName xml.Name           `xml:"legacy_data"`
	Users   []LegacyUserRecord `xml:"users>user"`
	Config  map[string]string  `xml:"config"`
}

func NewImporter(config *config.LegacyConfig, db database.Connection) *Importer {
	return &Importer{
		config: config,
		db:     db,
	}
}

// ImportAll imports all legacy data formats
func (i *Importer) ImportAll() error {
	logrus.Info("Starting legacy data import")

	// Import from different legacy sources
	if err := i.ImportFromXMLFile(); err != nil {
		return fmt.Errorf("XML import failed: %w", err)
	}

	if err := i.ImportFromCSVFile(); err != nil {
		return fmt.Errorf("CSV import failed: %w", err)
	}

	if err := i.ImportFromYAMLFile(); err != nil {
		return fmt.Errorf("YAML import failed: %w", err)
	}

	// Track successful import
	analytics.TrackEvent("legacy_import_completed", map[string]interface{}{
		"total_records": i.getTotalImportedRecords(),
		"success":       true,
	})

	logrus.Info("Legacy data import completed successfully")
	return nil
}

// ImportFromXMLFile imports data from legacy XML format
func (i *Importer) ImportFromXMLFile() error {
	filePath := i.config.XMLImportPath
	if filePath == "" {
		logrus.Info("No XML import path configured, skipping XML import")
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open XML file: %w", err)
	}
	defer file.Close()

	// Parse XML data
	data, err := i.parseXMLData(file)
	if err != nil {
		return fmt.Errorf("failed to parse XML data: %w", err)
	}

	// Import users from XML
	for _, user := range data.Users {
		err := i.importLegacyUser(user)
		if err != nil {
			logrus.Warnf("Failed to import user %s: %v", user.Username, err)
			continue
		}
	}

	return nil
}

// ImportFromCSVFile imports data from legacy CSV format
func (i *Importer) ImportFromCSVFile() error {
	filePath := i.config.CSVImportPath
	if filePath == "" {
		logrus.Info("No CSV import path configured, skipping CSV import")
		return nil
	}

	// This function would parse CSV data
	// For demo purposes, we'll just log that it's not implemented
	logrus.Info("CSV import not implemented in demo")
	return nil
}

// ImportFromYAMLFile imports data from legacy YAML format
func (i *Importer) ImportFromYAMLFile() error {
	filePath := i.config.YAMLImportPath
	if filePath == "" {
		logrus.Info("No YAML import path configured, skipping YAML import")
		return nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open YAML file: %w", err)
	}
	defer file.Close()

	// Parse YAML data
	var data map[string]interface{}
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&data)
	if err != nil {
		return fmt.Errorf("failed to parse YAML data: %w", err)
	}

	// Process YAML data (simplified for demo)
	logrus.Infof("Processed YAML data with %d top-level keys", len(data))
	return nil
}

// XML parsing functions (potentially vulnerable to XXE attacks)
func (i *Importer) parseXMLData(reader io.Reader) (*LegacyDataFormat, error) {
	var data LegacyDataFormat

	// WARNING: This XML parser might be vulnerable to XXE attacks
	// It doesn't disable external entity processing
	decoder := xml.NewDecoder(reader)
	err := decoder.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("XML decode error: %w", err)
	}

	return &data, nil
}

// User import functions
func (i *Importer) importLegacyUser(user LegacyUserRecord) error {
	// Validate user data
	if !i.validateLegacyUserData(user) {
		return errors.New("invalid user data")
	}

	// Check if user already exists
	existingUser, _ := i.db.GetUserByUsername(user.Username)
	if existingUser != nil {
		return i.updateExistingUser(existingUser.ID, user)
	}

	// Create new user
	return i.createUserFromLegacyData(user)
}

func (i *Importer) validateLegacyUserData(user LegacyUserRecord) bool {
	if user.Username == "" || user.Email == "" {
		return false
	}

	if !strings.Contains(user.Email, "@") {
		return false
	}

	return true
}

func (i *Importer) createUserFromLegacyData(user LegacyUserRecord) error {
	// Generate a temporary password for legacy users
	tempPassword := i.generateTemporaryPassword()

	userID, err := i.db.CreateUser(user.Username, user.Email, tempPassword)
	if err != nil {
		return err
	}

	// Set admin role if applicable
	if user.Role == "admin" {
		err = i.db.UpdateUser(userID, map[string]interface{}{
			"is_admin": true,
		})
		if err != nil {
			logrus.Warnf("Failed to set admin role for user %s", user.Username)
		}
	}

	logrus.Infof("Created legacy user: %s", user.Username)
	return nil
}

func (i *Importer) updateExistingUser(userID int64, legacyUser LegacyUserRecord) error {
	updates := make(map[string]interface{})

	// Update email if different
	if legacyUser.Email != "" {
		updates["email"] = legacyUser.Email
	}

	// Update admin status if applicable
	if legacyUser.Role == "admin" {
		updates["is_admin"] = true
	}

	if len(updates) > 0 {
		return i.db.UpdateUser(userID, updates)
	}

	return nil
}

// Utility functions
func (i *Importer) generateTemporaryPassword() string {
	// Generate a weak temporary password
	// In a real system, this would force password reset on first login
	return "TempPass123!"
}

func (i *Importer) getTotalImportedRecords() int {
	// Return mock count for demo
	return 42
}

// Legacy format conversion functions (these are rarely used)
func (i *Importer) convertLegacyFormat1(data []byte) ([]byte, error) {
	// This function converts from a very old legacy format
	// It's rarely used but still exists in the codebase
	logrus.Debug("Converting legacy format 1 (rarely used)")
	return data, nil
}

func (i *Importer) convertLegacyFormat2(data []byte) ([]byte, error) {
	// This function converts from another legacy format
	// It's also rarely used
	logrus.Debug("Converting legacy format 2 (rarely used)")
	return data, nil
}

// Dead code - these functions are never called but still exist
func (i *Importer) unusedLegacyFunction1() {
	// This function is never called but exists in the codebase
	logrus.Debug("This function is never called")
}

func (i *Importer) unusedLegacyFunction2() error {
	// Another unused function
	return errors.New("this function is never used")
}

func (i *Importer) deprecatedImportMethod() error {
	// This is a deprecated import method that's no longer used
	// It remains in the code for historical reasons
	return errors.New("deprecated import method")
}
