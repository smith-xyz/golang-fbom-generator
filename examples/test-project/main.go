package main

import (
	"fmt"
	"reflect"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/yaml.v2"

	"test-project/internal/processor"
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
	s.router.POST("/api/protobuf", s.handleProtobufProcessing)                      // SIMPLE: Single-layer reflection vulnerability
	s.router.POST("/api/advanced-reflection", s.handleAdvancedReflectionProcessing) // COMPLEX: Multi-layered reflection vulnerability
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

// handleProtobufProcessing handles protobuf processing requests - SIMPLE VULNERABLE ENDPOINT!
// This creates a real attack vector where user input can trigger GO-2024-2611
func (s *Server) handleProtobufProcessing(c *gin.Context) {
	// Get function name from query parameter (user-controlled input!)
	functionName := c.DefaultQuery("function", "unmarshal")

	// Get JSON payload from request body (user-controlled input!)
	jsonData, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read request body"})
		return
	}

	fmt.Printf("HTTP Request: Processing %s with %d bytes of data\n", functionName, len(jsonData))

	// CRITICAL: This calls our reflection-based protobuf processor with user input!
	// An attacker can send: POST /api/protobuf?function=unmarshal with malicious JSON
	dynamicProtobufProcessor(functionName, jsonData)

	c.JSON(200, gin.H{
		"status":   "processed",
		"function": functionName,
		"size":     len(jsonData),
	})
}

// handleAdvancedReflectionProcessing demonstrates MULTI-LAYERED reflection vulnerability
// This creates a much more sophisticated attack chain that static analysis will struggle to trace
func (s *Server) handleAdvancedReflectionProcessing(c *gin.Context) {
	// Get processing parameters from user input
	handlerType := c.DefaultQuery("handler", "protobuf")     // User controls which handler
	methodName := c.DefaultQuery("method", "ProcessDynamic") // User controls which method

	// Get payload from request body
	jsonData, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read request body"})
		return
	}

	fmt.Printf("Advanced Reflection Request: handler=%s, method=%s, dataLen=%d\n",
		handlerType, methodName, len(jsonData))

	// SOPHISTICATED ATTACK CHAIN:
	// 1. User sends: POST /api/advanced-reflection?handler=protobuf&method=ProcessDynamic
	// 2. This calls processAdvancedReflectionRequest (Layer 1)
	// 3. Which calls processor.ProcessMessage via reflection (Layer 2)
	// 4. Which calls ProtobufMessageProcessor.ProcessDynamic via reflection (Layer 3)
	// 5. Which calls VulnerableProtobufStruct.ProcessUnsafeProtobuf via reflection (Layer 4)
	// 6. Which finally calls protojson.Unmarshal (VULNERABLE FUNCTION!)

	err = s.processAdvancedReflectionRequest(handlerType, methodName, jsonData)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"status":  "processed",
		"handler": handlerType,
		"method":  methodName,
		"layers":  "multi-layered reflection executed",
	})
}

// processAdvancedReflectionRequest is the first layer of the sophisticated reflection chain
// LAYER 1: This method uses reflection to call the advanced processor
func (s *Server) processAdvancedReflectionRequest(handlerType, methodName string, data []byte) error {
	fmt.Println("LAYER 1: processAdvancedReflectionRequest - Starting sophisticated reflection chain...")

	// Create the advanced reflection processor
	advancedProcessor := processor.NewAdvancedReflectionProcessor()

	// LAYER 1 REFLECTION CALL: Use reflection to call ProcessMessage
	// This obscures the call path from static analysis
	processorValue := reflect.ValueOf(advancedProcessor)
	processMethod := processorValue.MethodByName("ProcessMessage")

	if !processMethod.IsValid() {
		return fmt.Errorf("ProcessMessage method not found")
	}

	// Prepare arguments for reflection call
	args := []reflect.Value{
		reflect.ValueOf(handlerType),
		reflect.ValueOf(methodName),
		reflect.ValueOf(data),
	}

	fmt.Println("LAYER 1: Calling ProcessMessage via reflection...")

	// CRITICAL: This starts the multi-layered reflection chain that eventually
	// reaches protojson.Unmarshal through multiple layers of indirection
	results := processMethod.Call(args)

	// Check for errors
	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			return fmt.Errorf("advanced reflection processing failed: %w", err)
		}
	}

	fmt.Println("LAYER 1: Advanced reflection processing completed")
	return nil
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

	// NEW: Now call the GO-2024-2611 vulnerable function via reflection!
	callProtojsonVulnerabilityViaReflection()
}

// callProtojsonVulnerabilityViaReflection demonstrates the GO-2024-2611 vulnerability
// This creates a sophisticated reflection-based attack that static analysis will struggle with
func callProtojsonVulnerabilityViaReflection() {
	fmt.Println("Attempting reflection-based protojson vulnerability trigger...")

	// Step 1: Use reflection to get the protojson.Unmarshal function
	// This makes it very hard for static analysis to detect the call
	protojsonPkg := reflect.ValueOf(protojson.Unmarshal)

	// Step 2: Create malicious JSON that triggers the infinite loop
	// This JSON contains a google.protobuf.Any that will cause the vulnerability
	maliciousJSON := []byte(`{
		"@type": "type.googleapis.com/google.protobuf.Any",
		"value": {
			"@type": "type.googleapis.com/google.protobuf.Any",
			"value": "recursive_any_payload"
		}
	}`)

	// Step 3: Create an Any message to unmarshal into (this triggers the vulnerability)
	anyMessage := &anypb.Any{}

	// Step 4: Use reflection to call protojson.Unmarshal dynamically
	// This is the vulnerable call path: protojson.Unmarshal(maliciousJSON, anyMessage)
	jsonArg := reflect.ValueOf(maliciousJSON)
	messageArg := reflect.ValueOf(anyMessage)

	fmt.Println("Calling protojson.Unmarshal via reflection with malicious payload...")

	// This reflection call will trigger GO-2024-2611 if the vulnerability exists
	// The infinite loop occurs when unmarshaling nested Any messages
	results := protojsonPkg.Call([]reflect.Value{jsonArg, messageArg})

	// Check results (this might not execute if infinite loop occurs)
	if len(results) > 0 && !results[0].IsNil() {
		fmt.Printf("Protojson reflection call failed: %v\n", results[0].Interface())
	} else {
		fmt.Println("Protojson reflection call completed (vulnerability may be patched)")
	}
}

// dynamicProtobufProcessor demonstrates even more sophisticated reflection usage
// This function dynamically determines which protobuf function to call based on input
func dynamicProtobufProcessor(functionName string, jsonData []byte) {
	fmt.Printf("Dynamic protobuf processing: %s\n", functionName)

	// Use reflection to dynamically select protobuf functions
	var targetFunc reflect.Value

	switch functionName {
	case "unmarshal":
		// This could be called from HTTP input, making it a real attack vector
		targetFunc = reflect.ValueOf(protojson.Unmarshal)
	case "marshal":
		targetFunc = reflect.ValueOf(protojson.Marshal)
	default:
		fmt.Println("Unknown function requested")
		return
	}

	// Create target message dynamically
	anyMessage := &anypb.Any{}

	// Dynamic reflection call - very hard for static analysis to track
	if targetFunc.IsValid() {
		args := []reflect.Value{
			reflect.ValueOf(jsonData),
			reflect.ValueOf(anyMessage),
		}

		fmt.Println("Executing dynamic protobuf function via reflection...")
		results := targetFunc.Call(args)

		if len(results) > 0 && !results[0].IsNil() {
			fmt.Printf("Dynamic call failed: %v\n", results[0].Interface())
		}
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
