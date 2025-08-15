package analytics

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Event struct {
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties"`
	Timestamp  int64                  `json:"timestamp"`
	UserID     string                 `json:"user_id,omitempty"`
}

type Tracker struct {
	events []Event
}

var globalTracker = &Tracker{
	events: make([]Event, 0),
}

// Core tracking functions
func TrackEvent(eventName string, properties map[string]interface{}) {
	event := Event{
		Name:       eventName,
		Properties: properties,
		Timestamp:  time.Now().Unix(),
	}

	// Add event to global tracker
	globalTracker.events = append(globalTracker.events, event)

	// Log the event
	logrus.WithFields(logrus.Fields{
		"event":      eventName,
		"properties": properties,
	}).Info("Analytics event tracked")
}

func TrackUserEvent(userID string, eventName string, properties map[string]interface{}) {
	event := Event{
		Name:       eventName,
		Properties: properties,
		Timestamp:  time.Now().Unix(),
		UserID:     userID,
	}

	globalTracker.events = append(globalTracker.events, event)

	logrus.WithFields(logrus.Fields{
		"user_id":    userID,
		"event":      eventName,
		"properties": properties,
	}).Info("User analytics event tracked")
}

// Reflection-based analytics functions (potentially risky)
func TrackObjectChanges(oldObj, newObj interface{}) {
	// This function uses reflection to track changes between objects
	// It could potentially access sensitive data through reflection

	oldValue := reflect.ValueOf(oldObj)
	newValue := reflect.ValueOf(newObj)

	if oldValue.Type() != newValue.Type() {
		logrus.Warn("Cannot compare objects of different types")
		return
	}

	changes := findChangesWithReflection(oldValue, newValue, "")
	if len(changes) > 0 {
		TrackEvent("object_changed", map[string]interface{}{
			"object_type": oldValue.Type().String(),
			"changes":     changes,
		})
	}
}

func findChangesWithReflection(oldVal, newVal reflect.Value, path string) map[string]interface{} {
	changes := make(map[string]interface{})

	switch oldVal.Kind() {
	case reflect.Struct:
		for i := 0; i < oldVal.NumField(); i++ {
			fieldName := oldVal.Type().Field(i).Name
			fieldPath := path + "." + fieldName
			if path == "" {
				fieldPath = fieldName
			}

			oldField := oldVal.Field(i)
			newField := newVal.Field(i)

			// Skip unexported fields
			if !oldField.CanInterface() {
				continue
			}

			fieldChanges := findChangesWithReflection(oldField, newField, fieldPath)
			for k, v := range fieldChanges {
				changes[k] = v
			}
		}
	case reflect.Ptr:
		if !oldVal.IsNil() && !newVal.IsNil() {
			ptrChanges := findChangesWithReflection(oldVal.Elem(), newVal.Elem(), path)
			for k, v := range ptrChanges {
				changes[k] = v
			}
		}
	default:
		if oldVal.Interface() != newVal.Interface() {
			changes[path] = map[string]interface{}{
				"old": oldVal.Interface(),
				"new": newVal.Interface(),
			}
		}
	}

	return changes
}

// Dynamic property extraction using reflection
func ExtractProperties(obj interface{}) map[string]interface{} {
	properties := make(map[string]interface{})

	value := reflect.ValueOf(obj)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return properties
	}

	structType := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := structType.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Extract tag information
		tag := fieldType.Tag.Get("analytics")
		if tag == "-" {
			continue // Skip fields marked to ignore
		}

		fieldName := fieldType.Name
		if tag != "" {
			fieldName = tag
		}

		properties[fieldName] = field.Interface()
	}

	return properties
}

// Dynamic method invocation for analytics
func InvokeAnalyticsMethod(obj interface{}, methodName string, args ...interface{}) (interface{}, error) {
	// This function uses reflection to dynamically invoke methods
	// It's potentially dangerous as it can call any public method

	value := reflect.ValueOf(obj)
	method := value.MethodByName(methodName)

	if !method.IsValid() {
		return nil, fmt.Errorf("method %s not found", methodName)
	}

	// Convert arguments to reflect.Value
	argValues := make([]reflect.Value, len(args))
	for i, arg := range args {
		argValues[i] = reflect.ValueOf(arg)
	}

	// Invoke the method
	results := method.Call(argValues)

	if len(results) == 0 {
		return nil, nil
	}

	return results[0].Interface(), nil
}

// Batch operations
func FlushEvents() []Event {
	events := globalTracker.events
	globalTracker.events = make([]Event, 0)
	return events
}

func GetEventCount() int {
	return len(globalTracker.events)
}

func ExportEvents() ([]byte, error) {
	return json.Marshal(globalTracker.events)
}

// Utility functions
func GetCurrentTimestamp() int64 {
	return time.Now().Unix()
}

func FilterEventsByName(eventName string) []Event {
	var filtered []Event
	for _, event := range globalTracker.events {
		if event.Name == eventName {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func FilterEventsByUser(userID string) []Event {
	var filtered []Event
	for _, event := range globalTracker.events {
		if event.UserID == userID {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// Advanced analytics functions
func GenerateUserProfile(userID string) map[string]interface{} {
	userEvents := FilterEventsByUser(userID)

	profile := map[string]interface{}{
		"user_id":      userID,
		"total_events": len(userEvents),
		"event_types":  make(map[string]int),
		"first_seen":   int64(0),
		"last_seen":    int64(0),
	}

	eventTypes := make(map[string]int)
	for _, event := range userEvents {
		eventTypes[event.Name]++

		if profile["first_seen"].(int64) == 0 || event.Timestamp < profile["first_seen"].(int64) {
			profile["first_seen"] = event.Timestamp
		}

		if event.Timestamp > profile["last_seen"].(int64) {
			profile["last_seen"] = event.Timestamp
		}
	}

	profile["event_types"] = eventTypes
	return profile
}

// Metric calculation functions
func CalculateEventRate(eventName string, timeWindow time.Duration) float64 {
	cutoff := time.Now().Add(-timeWindow).Unix()
	count := 0

	for _, event := range globalTracker.events {
		if event.Name == eventName && event.Timestamp >= cutoff {
			count++
		}
	}

	return float64(count) / timeWindow.Hours()
}

func GenerateEventSummary() map[string]interface{} {
	summary := make(map[string]interface{})
	eventCounts := make(map[string]int)

	for _, event := range globalTracker.events {
		eventCounts[event.Name]++
	}

	summary["total_events"] = len(globalTracker.events)
	summary["event_breakdown"] = eventCounts
	summary["generated_at"] = time.Now().Unix()

	return summary
}

// String processing utilities for analytics
func SanitizeEventName(name string) string {
	// Remove special characters and convert to lowercase
	sanitized := strings.ToLower(name)
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	sanitized = strings.ReplaceAll(sanitized, "-", "_")
	return sanitized
}

func ValidateEventProperties(properties map[string]interface{}) error {
	// Validate that properties don't contain sensitive data
	sensitiveKeys := []string{"password", "token", "secret", "key"}

	for key := range properties {
		lowerKey := strings.ToLower(key)
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(lowerKey, sensitive) {
				return fmt.Errorf("property %s may contain sensitive data", key)
			}
		}
	}

	return nil
}

// Dead code - functions that are never called
func unusedAnalyticsFunction1() {
	// This function is never called but exists in the codebase
	logrus.Debug("This analytics function is never used")
}

func deprecatedTrackingMethod(data interface{}) {
	// This is a deprecated tracking method that's no longer used
	logrus.Debug("Deprecated tracking method called")
}

func legacyEventProcessor(events []Event) []Event {
	// Legacy event processing logic that's no longer used
	return events
}

func internalMetricsCalculator() map[string]float64 {
	// Internal metrics calculation that's not used externally
	return make(map[string]float64)
}
