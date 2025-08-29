package utils

import "strings"

// TrimSpaceSlice trims whitespace from all strings in a slice and filters out empty strings
func TrimSpaceSlice(items []string) []string {
	var result []string
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// ParseCommaDelimited parses a comma-delimited string into a slice of trimmed, non-empty strings
func ParseCommaDelimited(input string) []string {
	if input == "" {
		return nil
	}

	parts := strings.Split(input, ",")
	return TrimSpaceSlice(parts)
}

// TrimSpaceNonEmpty returns the trimmed string if it's non-empty, otherwise returns empty string
func TrimSpaceNonEmpty(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	return trimmed
}
