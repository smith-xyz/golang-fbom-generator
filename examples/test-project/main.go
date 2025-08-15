package main

import (
	"fmt"
	"reflect"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

// Config represents application configuration
type Config struct {
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
}

// Server represents a web server with methods
type Server struct {
	config Config
	router *gin.Engine
}

// NewServer creates a new server instance
func NewServer(config Config) *Server {
	return &Server{
		config: config,
		router: gin.Default(),
	}
}

// Start starts the server (public method)
func (s *Server) Start() error {
	s.setupRoutes()
	return s.router.Run(fmt.Sprintf(":%d", s.config.Port))
}

// setupRoutes configures the routes (private method)
func (s *Server) setupRoutes() {
	s.router.GET("/api/health", s.handleHealth)
	s.router.POST("/api/data", s.handleData)
}

// handleHealth handles health checks (method with receiver)
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok", "port": s.config.Port})
}

// handleData handles data processing (method with receiver)
func (s *Server) handleData(c *gin.Context) {
	result := s.processData()
	c.JSON(200, result)
}

// processData processes data internally (private method)
func (s *Server) processData() map[string]interface{} {
	return map[string]interface{}{
		"processed":   true,
		"server_port": s.config.Port,
	}
}

// GetConfig returns the server configuration (value receiver method)
func (s Server) GetConfig() Config {
	return s.config
}

func main() {
	fmt.Println("Starting web server...")

	// Load configuration using potentially vulnerable YAML library
	config := loadConfig("config.yaml")

	// Create server instance using the new struct
	server := NewServer(config)

	// Call struct method to start server
	if err := server.Start(); err != nil {
		panic(err)
	}

	// Set up additional routes for testing
	r := gin.Default()
	r.GET("/api/reflect", reflectionHandler)
	r.Run(fmt.Sprintf(":%d", config.Port+1))
}

// loadConfig demonstrates usage of vulnerable YAML library
func loadConfig(filename string) Config {
	data := []byte(`
port: 8080
database: "postgres://localhost/mydb"
`)

	var config Config
	// This uses gopkg.in/yaml.v2.Unmarshal - potentially vulnerable
	if err := yaml.Unmarshal(data, &config); err != nil {
		panic(err)
	}

	return config
}

// healthHandler is a simple handler (entry point)
func healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}

// dataHandler processes data and might use vulnerable functions
func dataHandler(c *gin.Context) {
	// This might trigger gin's AbortWithError if validation fails
	if c.GetHeader("Content-Type") != "application/json" {
		c.AbortWithError(400, fmt.Errorf("invalid content type"))
		return
	}

	// Process the data
	result := processUserData(c)
	c.JSON(200, result)
}

// reflectionHandler demonstrates reflection usage (high risk for static analysis)
func reflectionHandler(c *gin.Context) {
	// Use reflection to dynamically call methods
	result := performReflectionOperation()

	// CRITICAL: This demonstrates calling a vulnerable function via reflection
	// from a reachable entry point - this should trigger "UNCERTAIN" priority
	callVulnerableFunctionViaReflection()

	c.JSON(200, gin.H{"result": result})
}

// processUserData is an internal function that might call vulnerable code
func processUserData(c *gin.Context) map[string]interface{} {
	// Simulate some data processing
	data := make(map[string]interface{})
	data["processed"] = true
	data["timestamp"] = "2024-01-01T12:00:00Z"

	// This function is reachable from entry point but doesn't use vulnerable code directly
	return data
}

// performReflectionOperation uses reflection (makes static analysis difficult)
func performReflectionOperation() string {
	// Get the type of string
	stringType := reflect.TypeOf("")

	// Create a new string value
	stringValue := reflect.New(stringType).Elem()
	stringValue.SetString("reflection result")

	// This is an example of reflection usage that makes it hard to determine
	// what functions might be called dynamically
	methodName := "String"
	method := stringValue.MethodByName(methodName)
	if method.IsValid() {
		results := method.Call(nil)
		if len(results) > 0 {
			return results[0].String()
		}
	}

	// DANGEROUS: Call vulnerable function through reflection
	// This demonstrates how golang-fbom-generator flags reflection-based calls for manual review
	callVulnerableFunctionViaReflection()

	return "reflection result"
}

// callVulnerableFunctionViaReflection demonstrates calling a vulnerable function via reflection
// This should trigger the "UNCERTAIN (High reflection risk)" priority in golang-fbom-generator
func callVulnerableFunctionViaReflection() {
	// Use reflection to call yaml.Unmarshal - a known vulnerable function
	yamlPkg := reflect.ValueOf(yaml.Unmarshal)

	// Prepare arguments for yaml.Unmarshal(data []byte, out interface{}) error
	yamlData := reflect.ValueOf([]byte("test: value"))
	outValue := reflect.ValueOf(&Config{})

	// Call the vulnerable function dynamically
	// Static analysis can't easily determine this call path
	results := yamlPkg.Call([]reflect.Value{yamlData, outValue})

	// Check for errors (results[0] would be the error)
	if len(results) > 0 && !results[0].IsNil() {
		fmt.Printf("Reflection call failed: %v\n", results[0].Interface())
	}
}

// unusedFunction demonstrates a function that's not reachable from main
func unusedFunction() {
	// This function is not called anywhere, so even if it contained
	// vulnerable code, golang-fbom-generator would mark it as low priority
	fmt.Println("This function is never called")

	// Simulate using a vulnerable function that's not reachable
	_ = yaml.Unmarshal([]byte("test: data"), &Config{})
}

// deepFunction shows a function that's multiple calls away from entry points
func deepFunction() {
	// This function is not directly called by handlers,
	// so its priority would be adjusted based on call distance
	helperFunction()
}

func helperFunction() {
	// Even deeper in the call chain
	anotherHelper()
}

func anotherHelper() {
	// Very deep - any vulnerable code here would be lower priority
	// due to distance from entry points
	fmt.Println("Deep in the call stack")
}
