package api

import (
	"fmt"
	"net/http"
	"strconv"

	"fbom-demo/internal/auth"
	"fbom-demo/internal/config"
	"fbom-demo/internal/database"
	"fbom-demo/internal/legacy"
	"fbom-demo/pkg/analytics"
	"fbom-demo/pkg/security"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Server struct {
	config      *config.Config
	db          database.Connection
	authService *auth.Service
	router      *gin.Engine
}

func NewServer(cfg *config.Config, db database.Connection, authService *auth.Service) *Server {
	s := &Server{
		config:      cfg,
		db:          db,
		authService: authService,
	}

	s.setupRoutes()
	return s
}

func dummyFunction() bool {
	return true
}

func (s *Server) setupRoutes() {
	s.router = gin.Default()

	// testing anonymous functions
	anonymousFunctionTest := func() bool {
		return dummyFunction()
	}

	result := anonymousFunctionTest()
	if !result {
		logrus.Error("Anonymous function test failed")
	}

	// Public endpoints
	s.router.GET("/health", s.healthCheck)
	s.router.POST("/login", s.handleLogin)
	s.router.POST("/register", s.handleRegister)

	// Protected endpoints
	protected := s.router.Group("/api/v1")
	protected.Use(s.authMiddleware())
	{
		protected.GET("/users/:id", s.getUser)
		protected.PUT("/users/:id", s.updateUser)
		protected.DELETE("/users/:id", s.deleteUser)

		protected.GET("/data/export", s.exportData)
		protected.POST("/data/import", s.importData)

		protected.GET("/admin/users", s.adminGetUsers)
		protected.POST("/admin/system/backup", s.createSystemBackup)
		protected.DELETE("/admin/system/cleanup", s.performSystemCleanup)
	}

	// WebSocket endpoint
	s.router.GET("/ws", s.handleWebSocket)

	// Legacy endpoints (deprecated but still used)
	s.router.POST("/legacy/xml-import", s.handleLegacyXMLImport)
	s.router.GET("/legacy/export/:format", s.handleLegacyExport)
}

func (s *Server) Start(port int) {
	logrus.Infof("Starting server on port %d", port)
	if err := s.router.Run(fmt.Sprintf(":%d", port)); err != nil {
		logrus.Fatalf("Failed to start server: %v", err)
	}
}

// Health check endpoint
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": analytics.GetCurrentTimestamp(),
	})
}

// Authentication handlers
func (s *Server) handleLogin(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate credentials
	token, err := s.authService.Authenticate(req.Username, req.Password)
	if err != nil {
		logrus.Warnf("Authentication failed for user: %s", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Track successful login
	analytics.TrackEvent("user_login", map[string]interface{}{
		"username":   req.Username,
		"timestamp":  analytics.GetCurrentTimestamp(),
		"ip_address": c.ClientIP(),
	})

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (s *Server) handleRegister(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Security validation
	if !security.ValidateUserInput(req.Username) || !security.ValidateEmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format"})
		return
	}

	user, err := s.authService.CreateUser(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// User management handlers
func (s *Server) getUser(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := s.authService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (s *Server) updateUser(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req auth.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Security check: users can only update themselves unless admin
	currentUser := s.getCurrentUser(c)
	if currentUser.ID != userID && !currentUser.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	user, err := s.authService.UpdateUser(userID, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (s *Server) deleteUser(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Only admins can delete users
	currentUser := s.getCurrentUser(c)
	if !currentUser.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	err = s.authService.DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Track user deletion for audit
	analytics.TrackEvent("user_deleted", map[string]interface{}{
		"deleted_user_id": userID,
		"admin_user_id":   currentUser.ID,
		"timestamp":       analytics.GetCurrentTimestamp(),
	})

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// Data export/import handlers (potentially vulnerable)
func (s *Server) exportData(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	// This function handles sensitive data export
	data, err := s.db.ExportUserData(format)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed"})
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename=export."+format)
	c.Data(http.StatusOK, "application/octet-stream", data)
}

func (s *Server) importData(c *gin.Context) {
	// This is a potentially dangerous function that processes uploaded files
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	// WARNING: This could be vulnerable to malicious file uploads
	err = s.db.ImportUserData(file, header.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Import failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Import completed"})
}

// Admin functions (sensitive operations)
func (s *Server) adminGetUsers(c *gin.Context) {
	currentUser := s.getCurrentUser(c)
	if !currentUser.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	users, err := s.authService.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (s *Server) createSystemBackup(c *gin.Context) {
	currentUser := s.getCurrentUser(c)
	if !currentUser.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	// This function performs system-level operations
	backupID, err := s.db.CreateFullBackup()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Backup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"backup_id": backupID})
}

func (s *Server) performSystemCleanup(c *gin.Context) {
	currentUser := s.getCurrentUser(c)
	if !currentUser.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	// This function performs potentially destructive operations
	err := s.db.CleanupOldData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cleanup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Cleanup completed"})
}

// WebSocket handler demonstrates WebSocket vulnerabilities (CVE-2023-44487)
func (s *Server) handleWebSocket(c *gin.Context) {
	// VULNERABLE: WebSocket handling without proper validation
	// CVE-2023-44487: High severity WebSocket DoS vulnerability

	// Note: In a real implementation, this would upgrade the connection
	// and use gorilla/websocket which has known vulnerabilities
	c.JSON(http.StatusOK, gin.H{
		"message": "WebSocket endpoint - vulnerable to CVE-2023-44487",
		"warning": "This endpoint uses vulnerable WebSocket handling",
		"note":    "WebSocket upgrade would happen here in real implementation",
	})

	// Track WebSocket connection attempts
	analytics.TrackEvent("websocket_connection", map[string]interface{}{
		"client_ip": c.ClientIP(),
		"timestamp": analytics.GetCurrentTimestamp(),
	})
}

// Legacy handlers (deprecated but still reachable)
func (s *Server) handleLegacyXMLImport(c *gin.Context) {
	// This is a legacy endpoint that might use vulnerable XML parsing
	// It's deprecated but still reachable for backwards compatibility
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Legacy XML import deprecated"})
}

func (s *Server) handleLegacyExport(c *gin.Context) {
	format := c.Param("format")

	// Legacy export function with potential security issues
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "Legacy export deprecated",
		"format": format,
	})
}

// handleFileDownload demonstrates path traversal vulnerability (CVE-2023-45283)
func (s *Server) handleFileDownload(c *gin.Context) {
	filename := c.Param("file")

	// VULNERABLE: This allows path traversal attacks
	// CVE-2023-45283: High severity path traversal in file serving
	c.File("./uploads/" + filename) // Direct concatenation allows ../../../etc/passwd

	// Track download analytics
	analytics.TrackEvent("file_download", map[string]interface{}{
		"filename": filename,
		"user":     s.getCurrentUser(c).Username,
	})
}

// handleYAMLConfig demonstrates YAML parsing vulnerability (CVE-2023-45284)
func (s *Server) handleYAMLConfig(c *gin.Context) {
	var yamlData interface{}

	// VULNERABLE: YAML parsing can execute arbitrary code
	// CVE-2023-45284: Critical severity YAML parsing vulnerability
	if err := c.BindYAML(&yamlData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid YAML"})
		return
	}

	// Additional YAML processing using vulnerable function
	rawBody, _ := c.GetRawData()
	var config map[string]interface{}
	if err := yaml.Unmarshal(rawBody, &config); err != nil { // CVE-2023-45284: Critical
		c.JSON(http.StatusBadRequest, gin.H{"error": "YAML parse error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Config updated", "data": yamlData})
}

// trackAnalyticsEvent demonstrates reflection vulnerabilities (CVE-2023-DEMO-003)
func (s *Server) trackAnalyticsEvent(c *gin.Context) {
	var request struct {
		Event      string                 `json:"event"`
		Properties map[string]interface{} `json:"properties"`
		Target     interface{}            `json:"target,omitempty"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// VULNERABLE: Reflection-based analytics processing
	// CVE-2023-DEMO-003: Medium severity reflection vulnerabilities
	analytics.TrackEvent(request.Event, request.Properties)

	if request.Target != nil {
		// Dynamic method invocation vulnerability
		_, err := analytics.InvokeAnalyticsMethod(request.Target, "String")
		if err != nil {
			logrus.Warnf("Analytics method invocation failed: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Event tracked"})
}

// batchAnalyticsEvent demonstrates batch reflection processing
func (s *Server) batchAnalyticsEvent(c *gin.Context) {
	var request struct {
		Events []map[string]interface{} `json:"events"`
		OldObj interface{}              `json:"old_object,omitempty"`
		NewObj interface{}              `json:"new_object,omitempty"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Process batch events
	for _, event := range request.Events {
		if eventName, ok := event["name"].(string); ok {
			analytics.TrackEvent(eventName, event)
		}
	}

	// VULNERABLE: Object change tracking with reflection
	if request.OldObj != nil && request.NewObj != nil {
		analytics.TrackObjectChanges(request.OldObj, request.NewObj) // CVE-2023-DEMO-003: Medium
	}

	c.JSON(http.StatusOK, gin.H{"message": "Batch events processed", "count": len(request.Events)})
}

// securityTest demonstrates admin access to vulnerable functions
func (s *Server) securityTest(c *gin.Context) {
	currentUser := s.getCurrentUser(c)
	if !currentUser.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	var request struct {
		TestType string `json:"test_type"`
		Data     string `json:"data"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	results := make(map[string]interface{})

	switch request.TestType {
	case "crypto":
		// VULNERABLE: Test weak cryptographic functions
		// CVE-2023-DEMO-001: High severity weak crypto
		results["md5_hash"] = security.LegacyMD5Hash(request.Data)
		results["weak_encrypt"] = security.WeakEncryption([]byte(request.Data), "test-key")

	case "validation":
		// Test security validation functions
		results["email_valid"] = security.ValidateEmail(request.Data)
		results["input_valid"] = security.ValidateUserInput(request.Data)

	case "password":
		// VULNERABLE: Password hashing with potential weak configuration
		// CVE-2023-39325: Medium severity weak random number generation
		hash, err := security.HashPassword(request.Data)
		if err != nil {
			results["error"] = err.Error()
		} else {
			results["password_hash"] = hash
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown test type"})
		return
	}

	// Track security test usage
	analytics.TrackEvent("security_test", map[string]interface{}{
		"test_type": request.TestType,
		"admin_id":  currentUser.ID,
	})

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// legacyXMLImport demonstrates XXE vulnerability (CVE-2023-DEMO-002)
func (s *Server) legacyXMLImport(c *gin.Context) {
	// CRITICAL: Direct call to vulnerable XML parsing
	// CVE-2023-DEMO-002: Critical severity XXE vulnerability
	importer := legacy.NewImporter(&s.config.Legacy, s.db)

	if err := importer.ImportFromXMLFile(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Import failed", "details": err.Error()})
		return
	}

	// Track import analytics
	analytics.TrackEvent("legacy_xml_import", map[string]interface{}{
		"user_id":   s.getCurrentUser(c).ID,
		"timestamp": analytics.GetCurrentTimestamp(),
		"success":   true,
	})

	c.JSON(http.StatusOK, gin.H{"message": "XML import completed"})
}

// legacyCryptoTest demonstrates legacy crypto vulnerabilities
func (s *Server) legacyCryptoTest(c *gin.Context) {
	var request struct {
		Data      string `json:"data"`
		Operation string `json:"operation"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	results := make(map[string]interface{})

	switch request.Operation {
	case "hash":
		// VULNERABLE: Legacy MD5 hashing
		results["legacy_hash"] = security.LegacyMD5Hash(request.Data)

	case "encrypt":
		// VULNERABLE: Weak encryption
		encrypted := security.WeakEncryption([]byte(request.Data), "legacy-key")
		results["encrypted"] = encrypted

	case "decrypt":
		// VULNERABLE: Weak decryption
		decrypted := security.WeakDecryption([]byte(request.Data), "legacy-key")
		results["decrypted"] = string(decrypted)

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown operation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// Middleware
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization token"})
			c.Abort()
			return
		}

		user, err := s.authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

// Helper functions
func (s *Server) getCurrentUser(c *gin.Context) *auth.User {
	user, exists := c.Get("user")
	if !exists {
		return nil
	}
	return user.(*auth.User)
}
