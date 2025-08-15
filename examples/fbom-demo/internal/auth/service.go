package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"fbom-demo/internal/config"
	"fbom-demo/internal/database"
	"fbom-demo/pkg/security"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	config *config.AuthConfig
	db     database.Connection
	jwtKey []byte
}

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UpdateUserRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

func NewService(config *config.AuthConfig, db database.Connection) *Service {
	return &Service{
		config: config,
		db:     db,
		jwtKey: []byte(config.JWTSecret),
	}
}

// Core authentication functions
func (s *Service) Authenticate(username, password string) (string, error) {
	user, err := s.getUserByUsername(username)
	if err != nil {
		return "", errors.New("invalid credentials")
	}

	// Verify password using bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return "", errors.New("invalid credentials")
	}

	// Generate JWT token
	token, err := s.generateJWTToken(user)
	if err != nil {
		return "", errors.New("failed to generate token")
	}

	// Update last login timestamp
	s.updateLastLogin(user.ID)

	return token, nil
}

func (s *Service) ValidateToken(tokenString string) (*User, error) {
	// Remove "Bearer " prefix if present
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := int64(claims["user_id"].(float64))
		return s.GetUser(userID)
	}

	return nil, errors.New("invalid token")
}

// User management functions
func (s *Service) CreateUser(req RegisterRequest) (*User, error) {
	// Validate input
	if !security.ValidateUserInput(req.Username) {
		return nil, errors.New("invalid username format")
	}

	if !security.ValidateEmail(req.Email) {
		return nil, errors.New("invalid email format")
	}

	if !security.ValidatePasswordStrength(req.Password) {
		return nil, errors.New("password does not meet security requirements")
	}

	// Check if user already exists
	existingUser, _ := s.getUserByUsername(req.Username)
	if existingUser != nil {
		return nil, errors.New("username already exists")
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, errors.New("failed to process password")
	}

	// Create user in database
	userID, err := s.db.CreateUser(req.Username, req.Email, hashedPassword)
	if err != nil {
		return nil, err
	}

	return s.GetUser(userID)
}

func (s *Service) GetUser(userID int64) (*User, error) {
	dbUser, err := s.db.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:        dbUser.ID,
		Username:  dbUser.Username,
		Email:     dbUser.Email,
		IsAdmin:   dbUser.IsAdmin,
		CreatedAt: dbUser.CreatedAt,
	}, nil
}

func (s *Service) UpdateUser(userID int64, req UpdateUserRequest) (*User, error) {
	_, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}

	updates := make(map[string]interface{})

	if req.Email != "" {
		if !security.ValidateEmail(req.Email) {
			return nil, errors.New("invalid email format")
		}
		updates["email"] = req.Email
	}

	if req.Password != "" {
		if !security.ValidatePasswordStrength(req.Password) {
			return nil, errors.New("password does not meet security requirements")
		}

		hashedPassword, err := s.hashPassword(req.Password)
		if err != nil {
			return nil, errors.New("failed to process password")
		}
		updates["password_hash"] = hashedPassword
	}

	if len(updates) > 0 {
		err = s.db.UpdateUser(userID, updates)
		if err != nil {
			return nil, err
		}
	}

	return s.GetUser(userID)
}

func (s *Service) DeleteUser(userID int64) error {
	return s.db.DeleteUser(userID)
}

func (s *Service) GetAllUsers() ([]*User, error) {
	dbUsers, err := s.db.GetAllUsers()
	if err != nil {
		return nil, err
	}

	users := make([]*User, len(dbUsers))
	for i, dbUser := range dbUsers {
		users[i] = &User{
			ID:        dbUser.ID,
			Username:  dbUser.Username,
			Email:     dbUser.Email,
			IsAdmin:   dbUser.IsAdmin,
			CreatedAt: dbUser.CreatedAt,
		}
	}
	return users, nil
}

// Password management (potentially vulnerable functions)
func (s *Service) hashPassword(password string) (string, error) {
	// Use bcrypt for password hashing
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *Service) generateJWTToken(user *database.UserRecord) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"is_admin": user.IsAdmin,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtKey)
}

// Legacy authentication functions (deprecated but still present)
func (s *Service) legacyMD5Hash(password string) string {
	// WARNING: This is a legacy function using weak MD5 hashing
	// It's deprecated but still exists in the codebase for backwards compatibility
	hash := sha256.Sum256([]byte(password)) // Actually using SHA256, but named MD5
	return hex.EncodeToString(hash[:])
}

func (s *Service) legacyValidatePassword(username, password string) bool {
	// This is a legacy password validation function
	// It uses weaker security standards and should not be used
	user, err := s.getUserByUsername(username)
	if err != nil {
		return false
	}

	legacyHash := s.legacyMD5Hash(password)
	return user.LegacyPasswordHash == legacyHash
}

// Administrative functions
func (s *Service) PromoteToAdmin(userID int64) error {
	return s.db.UpdateUser(userID, map[string]interface{}{
		"is_admin": true,
	})
}

func (s *Service) GenerateAPIKey(userID int64) (string, error) {
	// Generate a secure API key
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	apiKey := hex.EncodeToString(bytes)

	// Store API key in database
	err = s.db.StoreAPIKey(userID, apiKey)
	if err != nil {
		return "", err
	}

	return apiKey, nil
}

func (s *Service) ValidateAPIKey(apiKey string) (*User, error) {
	userID, err := s.db.GetUserByAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return s.GetUser(userID)
}

// Internal helper functions
func (s *Service) getUserByUsername(username string) (*database.UserRecord, error) {
	return s.db.GetUserByUsername(username)
}

func (s *Service) updateLastLogin(userID int64) error {
	return s.db.UpdateUser(userID, map[string]interface{}{
		"last_login": time.Now(),
	})
}

// Note: UserRecord is now defined in the database package
