package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"multi-entrypoint/internal/common"
)

// App1 is a web server application that provides REST API endpoints
func main() {
	fmt.Println("Starting App1 - Web Server")

	// Initialize the application using shared library
	config, logger, err := common.InitializeApplication("app1-webserver")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Set up database connection
	db := common.NewDatabaseConnection(config.DatabaseURL, logger)
	if err := db.Connect(); err != nil {
		logger.Error("Failed to connect to database", err)
		os.Exit(1)
	}
	defer db.Close()

	// Set up HTTP routes
	setupRoutes(db, logger)

	// Start the server
	port := config.Port
	logger.Info(fmt.Sprintf("Starting web server on port %d", port))

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		logger.Error("Server failed to start", err)
		os.Exit(1)
	}
}

// setupRoutes configures the HTTP routes for the web server
func setupRoutes(db *common.DatabaseConnection, logger *common.Logger) {
	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		handleHealthCheck(w, r, db, logger)
	})

	// User management endpoints
	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetUsers(w, r, db, logger)
		case http.MethodPost:
			handleCreateUser(w, r, db, logger)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetUser(w, r, db, logger)
		case http.MethodPut:
			handleUpdateUser(w, r, db, logger)
		case http.MethodDelete:
			handleDeleteUser(w, r, db, logger)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	logger.Info("HTTP routes configured")
}

// HTTP Handlers

func handleHealthCheck(w http.ResponseWriter, r *http.Request, db *common.DatabaseConnection, logger *common.Logger) {
	logger.Debug("Health check requested")

	if err := common.HealthCheck(db); err != nil {
		logger.Error("Health check failed", err)
		http.Error(w, "Service unhealthy", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "app1-webserver",
	})
}

func handleGetUsers(w http.ResponseWriter, r *http.Request, db *common.DatabaseConnection, logger *common.Logger) {
	logger.Debug("Get users requested")

	users, err := db.ListUsers()
	if err != nil {
		logger.Error("Failed to get users", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request, db *common.DatabaseConnection, logger *common.Logger) {
	logger.Debug("Create user requested")

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user, err := db.CreateUser(req.Name, req.Email, req.Role)
	if err != nil {
		logger.Error("Failed to create user", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func handleGetUser(w http.ResponseWriter, r *http.Request, db *common.DatabaseConnection, logger *common.Logger) {
	logger.Debug("Get user requested")

	// Extract user ID from URL path
	idStr := r.URL.Path[len("/users/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := db.GetUser(id)
	if err != nil {
		logger.Error("Failed to get user", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request, db *common.DatabaseConnection, logger *common.Logger) {
	logger.Debug("Update user requested")

	// Extract user ID from URL path
	idStr := r.URL.Path[len("/users/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user, err := db.UpdateUser(id, req.Name, req.Email, req.Role)
	if err != nil {
		logger.Error("Failed to update user", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request, db *common.DatabaseConnection, logger *common.Logger) {
	logger.Debug("Delete user requested")

	// Extract user ID from URL path
	idStr := r.URL.Path[len("/users/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := db.DeleteUser(id); err != nil {
		logger.Error("Failed to delete user", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
