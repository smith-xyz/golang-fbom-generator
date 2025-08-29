package processor

import (
	"fmt"
	"reflect"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

// AdvancedReflectionProcessor demonstrates sophisticated multi-layered reflection
// This creates a scenario that's much harder for static analysis to trace
type AdvancedReflectionProcessor struct {
	handlers map[string]interface{}
}

// NewAdvancedReflectionProcessor creates a new processor with registered handlers
func NewAdvancedReflectionProcessor() *AdvancedReflectionProcessor {
	processor := &AdvancedReflectionProcessor{
		handlers: make(map[string]interface{}),
	}

	// Register handlers dynamically - this obscures the call path for static analysis
	processor.registerHandlers()
	return processor
}

// registerHandlers dynamically registers processing handlers
// This makes it very difficult for static analysis to determine what gets called
func (p *AdvancedReflectionProcessor) registerHandlers() {
	// Register different message processors
	p.handlers["protobuf"] = &ProtobufMessageProcessor{}
	p.handlers["json"] = &JsonMessageProcessor{}
	p.handlers["advanced"] = &AdvancedMessageProcessor{}

	fmt.Println("Registered handlers:", len(p.handlers))
}

// ProcessMessage is the main entry point that uses reflection to route to handlers
// LAYER 1: This function uses reflection to call methods on different processors
func (p *AdvancedReflectionProcessor) ProcessMessage(handlerType string, methodName string, data []byte) error {
	fmt.Printf("ProcessMessage: handlerType=%s, methodName=%s, dataLen=%d\n", handlerType, methodName, len(data))

	// Get handler by type name (dynamic lookup)
	handler, exists := p.handlers[handlerType]
	if !exists {
		return fmt.Errorf("handler not found: %s", handlerType)
	}

	// CRITICAL: Use reflection to call method on handler
	// This is the first layer of indirection that makes tracing difficult
	handlerValue := reflect.ValueOf(handler)
	method := handlerValue.MethodByName(methodName)

	if !method.IsValid() {
		return fmt.Errorf("method not found: %s.%s", handlerType, methodName)
	}

	// Prepare arguments for the reflection call
	args := []reflect.Value{
		reflect.ValueOf(data),
	}

	fmt.Printf("Calling %s.%s via reflection...\n", handlerType, methodName)

	// LAYER 1 REFLECTION CALL: This calls into the next layer
	results := method.Call(args)

	// Check for errors from the reflection call
	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			return err
		}
	}

	return nil
}

// ProtobufMessageProcessor handles protobuf-specific message processing
type ProtobufMessageProcessor struct{}

// ProcessDynamic is called via reflection from ProcessMessage
// LAYER 2: This method uses reflection on a custom struct to call vulnerable functions
func (p *ProtobufMessageProcessor) ProcessDynamic(data []byte) error {
	fmt.Println("ProtobufMessageProcessor.ProcessDynamic called via reflection")

	// Create a custom struct that contains vulnerable operations
	processor := &VulnerableProtobufStruct{
		data: data,
	}

	// LAYER 2 REFLECTION: Use reflection to call methods on our custom struct
	return p.executeViaReflection(processor)
}

// executeViaReflection uses reflection to call methods on the VulnerableProtobufStruct
// This creates another layer of indirection that static analysis will struggle with
func (p *ProtobufMessageProcessor) executeViaReflection(processor *VulnerableProtobufStruct) error {
	fmt.Println("Using reflection to call struct methods...")

	// Get the struct value
	structValue := reflect.ValueOf(processor)

	// Dynamically determine which method to call
	methodNames := []string{"ProcessUnsafeProtobuf", "ProcessNormalData"}

	for _, methodName := range methodNames {
		method := structValue.MethodByName(methodName)
		if method.IsValid() {
			fmt.Printf("Calling %s via reflection...\n", methodName)

			// LAYER 2 REFLECTION CALL: This will eventually reach the vulnerable function
			results := method.Call([]reflect.Value{})

			// Check results
			if len(results) > 0 && !results[0].IsNil() {
				if err, ok := results[0].Interface().(error); ok {
					fmt.Printf("Method %s returned error: %v\n", methodName, err)
				}
			}
		}
	}

	return nil
}

// VulnerableProtobufStruct contains the actual vulnerable operations
// LAYER 3: This struct's methods call the actual vulnerable protojson.Unmarshal function
type VulnerableProtobufStruct struct {
	data []byte
}

// ProcessUnsafeProtobuf is called via reflection and contains the vulnerable call
// LAYER 3: This is where the actual vulnerable function is called
func (v *VulnerableProtobufStruct) ProcessUnsafeProtobuf() error {
	fmt.Println("ProcessUnsafeProtobuf: About to call vulnerable protojson.Unmarshal...")

	// Create malicious JSON that will trigger GO-2024-2611
	maliciousJSON := []byte(`{
		"@type": "type.googleapis.com/google.protobuf.Any",
		"value": {
			"@type": "type.googleapis.com/google.protobuf.Any",
			"value": {
				"@type": "type.googleapis.com/google.protobuf.Any",
				"value": "deeply_nested_any_payload"
			}
		}
	}`)

	// Use the malicious data if provided, otherwise use our default
	dataToProcess := v.data
	if len(dataToProcess) == 0 {
		dataToProcess = maliciousJSON
	}

	// Create target message
	anyMessage := &anypb.Any{}

	// FINAL VULNERABLE CALL: This is the actual GO-2024-2611 vulnerability
	// It's now 3 layers deep in reflection calls:
	// 1. HTTP handler calls ProcessMessage via reflection
	// 2. ProcessMessage calls ProcessDynamic via reflection
	// 3. ProcessDynamic calls ProcessUnsafeProtobuf via reflection
	// 4. ProcessUnsafeProtobuf calls protojson.Unmarshal (VULNERABLE!)
	fmt.Println("Calling protojson.Unmarshal with potentially malicious data...")
	err := protojson.Unmarshal(dataToProcess, anyMessage)

	if err != nil {
		fmt.Printf("protojson.Unmarshal error (expected): %v\n", err)
		return err
	}

	fmt.Println("protojson.Unmarshal completed successfully")
	return nil
}

// ProcessNormalData provides a non-vulnerable path for comparison
func (v *VulnerableProtobufStruct) ProcessNormalData() error {
	fmt.Println("ProcessNormalData: Safe processing path")

	// This method doesn't call vulnerable functions
	// It's here to show how the reflection analysis needs to distinguish
	// between safe and unsafe paths

	return nil
}

// JsonMessageProcessor handles JSON-specific processing (safe alternative)
type JsonMessageProcessor struct{}

// ProcessDynamic for JSON (safe, no vulnerable calls)
func (j *JsonMessageProcessor) ProcessDynamic(data []byte) error {
	fmt.Println("JsonMessageProcessor.ProcessDynamic - safe processing")
	return nil
}

// AdvancedMessageProcessor demonstrates even more complex reflection patterns
type AdvancedMessageProcessor struct{}

// ProcessDynamic uses nested reflection calls
func (a *AdvancedMessageProcessor) ProcessDynamic(data []byte) error {
	fmt.Println("AdvancedMessageProcessor.ProcessDynamic - complex reflection patterns")

	// This could contain additional reflection-based vulnerable calls
	// For now, it's safe to show the pattern

	return nil
}
