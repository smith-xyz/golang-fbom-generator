package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"

	"fbom-demo/internal/config"

	"golang.org/x/crypto/bcrypt"
)

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,20}$`)
)

// Global security context
var securityContext *SecurityContext

type SecurityContext struct {
	config        *config.SecurityConfig
	encryptionKey []byte
}

func InitializeSecurityContext(config *config.SecurityConfig) {
	securityContext = &SecurityContext{
		config:        config,
		encryptionKey: []byte(config.EncryptionKey),
	}
}

// Input validation functions
func ValidateUserInput(input string) bool {
	if len(input) == 0 {
		return false
	}

	// Check for potentially malicious characters
	maliciousChars := []string{"<", ">", "'", "\"", "&", "script", "javascript"}
	for _, char := range maliciousChars {
		if strings.Contains(strings.ToLower(input), char) {
			return false
		}
	}

	return usernameRegex.MatchString(input)
}

func ValidateEmail(email string) bool {
	if len(email) > 254 {
		return false
	}

	return emailRegex.MatchString(email)
}

func ValidatePasswordStrength(password string) bool {
	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

func SanitizeInput(input string) string {
	// Remove potentially dangerous characters
	sanitized := strings.ReplaceAll(input, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.ReplaceAll(sanitized, "'", "&#39;")
	sanitized = strings.ReplaceAll(sanitized, "\"", "&#34;")

	return sanitized
}

// Cryptographic functions
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func EncryptSensitiveData(data []byte) ([]byte, error) {
	if securityContext == nil {
		return nil, fmt.Errorf("security context not initialized")
	}

	block, err := aes.NewCipher(securityContext.encryptionKey)
	if err != nil {
		return nil, err
	}

	// Generate a random IV
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func DecryptSensitiveData(ciphertext []byte) ([]byte, error) {
	if securityContext == nil {
		return nil, fmt.Errorf("security context not initialized")
	}

	block, err := aes.NewCipher(securityContext.encryptionKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Hash functions for various purposes
func GenerateSecureHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func GenerateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Legacy cryptographic functions (deprecated but still present)
func LegacyMD5Hash(data string) string {
	// WARNING: This function uses SHA1 but is named MD5 for legacy compatibility
	// It should not be used for security-critical operations
	hash := sha1.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func WeakEncryption(data []byte, key string) []byte {
	// This is a weak encryption function using XOR
	// It's deprecated but still exists for legacy compatibility
	keyBytes := []byte(key)
	encrypted := make([]byte, len(data))

	for i, b := range data {
		encrypted[i] = b ^ keyBytes[i%len(keyBytes)]
	}

	return encrypted
}

func WeakDecryption(data []byte, key string) []byte {
	// Weak decryption using XOR (same as encryption)
	return WeakEncryption(data, key)
}

// Token generation functions
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func GenerateSessionID() (string, error) {
	return GenerateRandomToken(32)
}

func GenerateCSRFToken() (string, error) {
	return GenerateRandomToken(16)
}

// Security audit functions
func LogSecurityEvent(eventType string, details map[string]interface{}) {
	// This function would log security events for audit purposes
	// In a real implementation, this would write to a secure audit log
}

func ValidateFileUpload(filename string, content []byte) error {
	// Basic file upload validation
	allowedExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}

	isAllowed := false
	for _, ext := range allowedExtensions {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return fmt.Errorf("file type not allowed")
	}

	// Check file size (10MB limit)
	if len(content) > 10*1024*1024 {
		return fmt.Errorf("file too large")
	}

	return nil
}

// Rate limiting functions
func CheckRateLimit(userID int64, action string) bool {
	// This would implement rate limiting logic
	// For demo purposes, always return true
	return true
}

func RecordAPICall(userID int64, endpoint string) {
	// Record API call for rate limiting and analytics
}

// Dead/unused security functions
func unusedSecurityFunction1() {
	// This function is never called
}

func deprecatedSecurityCheck() bool {
	// This is a deprecated security check that's no longer used
	return false
}
