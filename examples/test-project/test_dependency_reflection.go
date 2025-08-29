package main

import (
	"encoding/json"
	"fmt"
)

// Simulate a dependency that uses reflection internally
// This would normally be in a separate external dependency
func simulateDependencyWithReflection(data []byte) error {
	// This simulates a dependency like "github.com/some-lib/processor"
	// that internally uses reflection to call protojson.Unmarshal
	fmt.Println("Dependency is using reflection internally...")

	// In real scenario, this would be:
	// reflect.ValueOf(protojson.Unmarshal).Call(...)
	// But for our test, we will call json.Unmarshal to simulate the pattern
	var result map[string]interface{}
	return json.Unmarshal(data, &result)
}

func callDependencyThatUsesReflection() {
	// User code calls what appears to be a safe dependency
	data := []byte(`{"test": "data"}`)
	if err := simulateDependencyWithReflection(data); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
