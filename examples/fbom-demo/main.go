package main

import (
	"flag"
	"fmt"
	"os"

	"fbom-demo/internal/api"
	"fbom-demo/internal/auth"
	"fbom-demo/internal/config"
	"fbom-demo/internal/database"
	"fbom-demo/internal/legacy"
	"fbom-demo/internal/worker"
	"fbom-demo/pkg/analytics"
	"fbom-demo/pkg/security"

	"github.com/sirupsen/logrus"
)

func main() {
	var (
		configFile = flag.String("config", "config.yaml", "Configuration file path")
		mode       = flag.String("mode", "server", "Run mode: server, worker, migrate, legacy-import, demo")
		port       = flag.Int("port", 8080, "Server port")
		debug      = flag.Bool("debug", false, "Enable debug mode")
	)
	flag.Parse()

	// Initialize logging
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Debug mode enabled")
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}

	// Initialize security components
	security.InitializeSecurityContext(&cfg.Security)

	// Initialize database connection
	db, err := database.Connect((*database.DatabaseConfig)(&cfg.Database))
	if err != nil {
		logrus.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// DEMO: Call some vulnerable functions for demonstration purposes
	// This creates call paths that will show up in FBOM analysis
	demoSecurityScenarios()

	// Route to different run modes
	switch *mode {
	case "server":
		runServer(cfg, db, *port)
	case "worker":
		runWorker(cfg, db)
	case "migrate":
		runMigrations(db)
	case "legacy-import":
		runLegacyImport(cfg, db)
	case "demo":
		runSecurityDemo(cfg, db)
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

// demoSecurityScenarios calls various vulnerable functions to create realistic call paths
// This demonstrates different types of reachability for FBOM analysis
func demoSecurityScenarios() {
	// CRITICAL: Direct call to weak crypto (should show as directly reachable)
	testPassword := "demo123"
	_ = security.LegacyMD5Hash(testPassword) // CVE-2023-DEMO-001: High severity

	// CRITICAL: Call weak encryption (should show as directly reachable)
	testData := []byte("sensitive data")
	_ = security.WeakEncryption(testData, "key") // CVE-2023-DEMO-001: High severity

	// MEDIUM: Call analytics with reflection (should show reflection risk)
	analytics.TrackEvent("app_start", map[string]interface{}{"version": "1.0"}) // CVE-2023-DEMO-003: Medium

	// Demonstrate transitive calls through helper functions
	performUserManagement()
	performDataProcessing()
}

// performUserManagement demonstrates transitive reachability to auth vulnerabilities
func performUserManagement() {
	// This creates a call path: main -> performUserManagement -> auth functions
	// Any CVEs in auth functions will show as transitively reachable

	// MEDIUM: Password hashing (bcrypt CVE)
	_, _ = security.HashPassword("demo123") // CVE-2023-39325: Medium severity

	// Track user operations (leads to reflection calls)
	analytics.TrackEvent("user_management", map[string]interface{}{
		"operation": "demo",
		"timestamp": analytics.GetCurrentTimestamp(),
	})
}

// performDataProcessing demonstrates calls to data parsing vulnerabilities
func performDataProcessing() {
	// This creates call paths to data processing vulnerabilities

	// Call analytics reflection methods (medium severity)
	testObj := map[string]interface{}{
		"old": "value1",
		"new": "value2",
	}
	analytics.TrackObjectChanges(testObj, testObj) // CVE-2023-DEMO-003: Medium (uses reflection)

	// Demonstrate reflection method invocation
	_, _ = analytics.InvokeAnalyticsMethod(testObj, "String") // CVE-2023-DEMO-003: Medium
}

// runServer starts the HTTP API server
func runServer(cfg *config.Config, db database.Connection, port int) {
	logrus.Info("Starting HTTP server...")

	// Initialize authentication service (which may call vulnerable functions)
	authService := auth.NewService(&cfg.Auth, db)

	// Demo: Call auth service to create reachable paths to JWT vulnerabilities
	_, _ = authService.Authenticate("demo", "demo123") // Leads to JWT parsing (CVE-2023-39318: Critical)

	// Start API server
	server := api.NewServer(cfg, db, authService)
	server.Start(port)
}

// runWorker starts the background worker
func runWorker(cfg *config.Config, db database.Connection) {
	logrus.Info("Starting background worker...")

	// Demo: Worker operations that might call vulnerable functions
	performWorkerTasks()

	w := worker.New(&cfg.Worker, db)
	w.Start()
}

// performWorkerTasks demonstrates worker-related vulnerabilities
func performWorkerTasks() {
	// Workers often process data in batch, creating call paths to parsing functions

	// Security validation (could trigger validation vulnerabilities)
	testData := "user@example.com"
	_ = security.ValidateEmail(testData)

	// Batch analytics processing
	for i := 0; i < 3; i++ {
		analytics.TrackEvent("worker_task", map[string]interface{}{
			"task_id": i,
			"status":  "processing",
		})
	}
}

// runMigrations executes database migrations
func runMigrations(db database.Connection) {
	logrus.Info("Running database migrations...")

	migrator := database.NewMigrator(db)
	if err := migrator.MigrateUp(); err != nil {
		logrus.Fatalf("Migration failed: %v", err)
	}

	logrus.Info("Migrations completed successfully")
}

// runLegacyImport imports data from legacy systems
func runLegacyImport(cfg *config.Config, db database.Connection) {
	logrus.Info("Starting legacy data import...")

	// CRITICAL: This creates direct call paths to XML parsing vulnerabilities
	importer := legacy.NewImporter(&cfg.Legacy, db)

	// Call the vulnerable XML import function (XXE vulnerability)
	if err := importer.ImportFromXMLFile(); err != nil {
		logrus.Warnf("Import failed (expected in demo): %v", err)
	}

	// Import all data (calls multiple vulnerable functions)
	if err := importer.ImportAll(); err != nil { // CVE-2023-DEMO-002: Critical severity
		logrus.Warnf("Full import failed (expected in demo): %v", err)
	}

	logrus.Info("Legacy import completed")
}

// runSecurityDemo runs a comprehensive security demonstration
func runSecurityDemo(cfg *config.Config, db database.Connection) {
	logrus.Info("Running comprehensive security demo...")

	// CRITICAL severity demonstrations
	runCriticalSecurityDemo(cfg, db)

	// HIGH severity demonstrations
	runHighSecurityDemo(cfg, db)

	// MEDIUM severity demonstrations
	runMediumSecurityDemo(cfg, db)

	logrus.Info("Security demo completed - check FBOM analysis for reachability results")
}

// runCriticalSecurityDemo demonstrates CRITICAL severity vulnerabilities
func runCriticalSecurityDemo(cfg *config.Config, db database.Connection) {
	logrus.Info("Demonstrating CRITICAL vulnerabilities...")

	// XXE vulnerability in XML parsing (CVE-2023-DEMO-002: Critical 9.3)
	importer := legacy.NewImporter(&cfg.Legacy, db)
	_ = importer.ImportFromXMLFile() // Direct call to XXE function

	// JWT parsing vulnerability (CVE-2023-39318: Critical 9.1)
	authService := auth.NewService(&cfg.Auth, db)
	_, _ = authService.ValidateToken("fake.jwt.token") // Direct call to JWT parsing

	// YAML parsing vulnerability (CVE-2023-45284: Critical 9.8)
	// This would be called through config loading - already triggered in main
	logrus.Info("CRITICAL vulnerabilities demonstrated")
}

// runHighSecurityDemo demonstrates HIGH severity vulnerabilities
func runHighSecurityDemo(cfg *config.Config, db database.Connection) {
	logrus.Info("Demonstrating HIGH vulnerabilities...")

	// Weak cryptographic functions (CVE-2023-DEMO-001: High 8.2)
	weakHash := security.LegacyMD5Hash("password123")
	weakData := security.WeakEncryption([]byte("secret"), "key")
	_ = weakHash
	_ = weakData

	// Path traversal in file serving (CVE-2023-45283: High 7.5)
	// This would be triggered through Gin router - demonstrated in API calls

	// WebSocket vulnerabilities (CVE-2023-44487: High 7.2)
	// These would be called through WebSocket handlers in the API server
	logrus.Info("HIGH vulnerabilities demonstrated")
}

// runMediumSecurityDemo demonstrates MEDIUM severity vulnerabilities
func runMediumSecurityDemo(cfg *config.Config, db database.Connection) {
	logrus.Info("Demonstrating MEDIUM vulnerabilities...")

	// Reflection-based analytics vulnerabilities (CVE-2023-DEMO-003: Medium 6.8)
	testObject := map[string]interface{}{"test": "data"}
	analytics.TrackObjectChanges(testObject, testObject)         // Uses reflection
	_, _ = analytics.InvokeAnalyticsMethod(testObject, "String") // Dynamic method invocation

	// Weak password hashing (CVE-2023-39325: Medium 5.3)
	_, _ = security.HashPassword("demo123") // Uses bcrypt but could be configured weakly

	// SQL connection vulnerabilities (CVE-2023-39319: Medium 6.1)
	// Would be triggered through database connection establishment

	logrus.Info("MEDIUM vulnerabilities demonstrated")
}
