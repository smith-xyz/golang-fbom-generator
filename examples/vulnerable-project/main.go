package main

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

func main() {
	fmt.Println("Vulnerable Project Example")

	// Use vulnerable golang.org/x/text package
	parseLanguageTags()

	// Use vulnerable golang.org/x/net package
	parseHTML()

	// Use text normalization (potential vulnerability vector)
	normalizeText("café")

	// Use reflection to call vulnerable function - high risk scenario
	reflectiveVulnerableCall()

	// Advanced reflection attack vector - interface-based dynamic execution
	performDynamicInterfaceExecution()
}

func parseLanguageTags() {
	tags := []string{"en-US", "fr-FR", "es-ES"}
	fmt.Println("Parsing language tags:")

	for _, tagStr := range tags {
		tag, err := language.Parse(tagStr)
		if err != nil {
			fmt.Printf("  %s: error: %v\n", tagStr, err)
		} else if tag == language.Und {
			fmt.Printf("  %s: undefined\n", tagStr)
		} else {
			fmt.Printf("  %s: tag %s\n", tagStr, tag)
		}
	}
}

func parseHTML() {
	htmlContent := `<html><body><h1>Hello World</h1></body></html>`
	fmt.Println("Parsing HTML content:")

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		fmt.Printf("  Error parsing HTML: %v\n", err)
		return
	}

	// Traverse the HTML tree (vulnerable operation in old versions)
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			fmt.Printf("  Found element: %s\n", n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
}

func normalizeText(input string) {
	fmt.Printf("Normalizing text: %s\n", input)

	// Using text normalization which had vulnerabilities in older versions
	normalized := norm.NFC.String(input)
	fmt.Printf("  Normalized: %s\n", normalized)
}

func vulnerableHTTPClient() {
	// This function demonstrates usage that could be vulnerable
	client := &http.Client{}

	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Printf("HTTP error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP response status: %s\n", resp.Status)
}

// reflectiveVulnerableCall demonstrates a high-risk scenario where reflection
// is used to call vulnerable functions from external packages
func reflectiveVulnerableCall() {
	fmt.Println("Demonstrating reflection-based vulnerable function call:")

	// Get the html package via reflection
	htmlPkg := reflect.ValueOf(html.Parse)

	// Use reflection to call Parse function (which is vulnerable in some CVEs)
	htmlContent := `<html><body><script>alert('xss')</script></body></html>`
	reader := strings.NewReader(htmlContent)

	// Call html.Parse via reflection - this represents a high-risk pattern
	// where vulnerable functions might be called dynamically
	args := []reflect.Value{reflect.ValueOf(reader)}
	results := htmlPkg.Call(args)

	if len(results) > 1 && !results[1].IsNil() {
		err := results[1].Interface().(error)
		fmt.Printf("  Reflection-based HTML parsing error: %v\n", err)
	} else if len(results) > 0 {
		fmt.Println("  Successfully parsed HTML via reflection (potential security risk)")

		// This creates a reflection-based call path to vulnerable functions
		// Our CVE analysis should detect this as high-risk
		doc := results[0].Interface().(*html.Node)
		reflectiveTraversal(doc)
	}
}

// reflectiveTraversal uses reflection to traverse the HTML tree
// This demonstrates another reflection pattern that could be risky
func reflectiveTraversal(node *html.Node) {
	// Use reflection to access node properties and methods
	nodeValue := reflect.ValueOf(node)
	if nodeValue.IsNil() {
		return
	}

	// Access Type field via reflection
	typeField := nodeValue.Elem().FieldByName("Type")
	if typeField.IsValid() && typeField.Int() == int64(html.ElementNode) {
		// Access Data field via reflection
		dataField := nodeValue.Elem().FieldByName("Data")
		if dataField.IsValid() {
			fmt.Printf("  Reflected element: %s\n", dataField.String())
		}
	}

	// Recursively traverse children using reflection
	firstChildField := nodeValue.Elem().FieldByName("FirstChild")
	if firstChildField.IsValid() && !firstChildField.IsNil() {
		reflectiveTraversal(firstChildField.Interface().(*html.Node))
	}

	nextSiblingField := nodeValue.Elem().FieldByName("NextSibling")
	if nextSiblingField.IsValid() && !nextSiblingField.IsNil() {
		reflectiveTraversal(nextSiblingField.Interface().(*html.Node))
	}
}

// Parser represents any type that can parse content
// This interface abstracts away the specific implementation
type Parser interface {
	Parse(input interface{}) (interface{}, error)
}

// TextParser implements Parser for text processing
type TextParser struct{}

func (tp *TextParser) Parse(input interface{}) (interface{}, error) {
	if str, ok := input.(string); ok {
		// This calls golang.org/x/text/language.Parse - a vulnerable function
		return language.Parse(str)
	}
	return nil, fmt.Errorf("invalid input type")
}

// HTMLParser implements Parser for HTML processing
type HTMLParser struct{}

func (hp *HTMLParser) Parse(input interface{}) (interface{}, error) {
	if reader, ok := input.(strings.Reader); ok {
		// This calls golang.org/x/net/html.Parse - a vulnerable function
		return html.Parse(&reader)
	}
	return nil, fmt.Errorf("invalid input type")
}

// ConfigurableParser uses reflection to dynamically select and execute parsing methods
type ConfigurableParser struct {
	parsers map[string]interface{}
}

func NewConfigurableParser() *ConfigurableParser {
	return &ConfigurableParser{
		parsers: map[string]interface{}{
			"text": &TextParser{},
			"html": &HTMLParser{},
			// Could dynamically add more parsers at runtime
		},
	}
}

// ExecuteParser uses reflection to dynamically call Parse methods on unknown types
// This is extremely difficult to analyze statically because:
// 1. The parser type is determined at runtime from external input
// 2. The method called is determined by interface reflection
// 3. Multiple vulnerable functions could be called depending on runtime conditions
func (cp *ConfigurableParser) ExecuteParser(parserType, methodName string, input interface{}) (interface{}, error) {
	// Get parser instance through map lookup - statically unpredictable
	parserInterface, exists := cp.parsers[parserType]
	if !exists {
		return nil, fmt.Errorf("unknown parser type: %s", parserType)
	}

	// Use reflection to get the parser's type and methods
	parserValue := reflect.ValueOf(parserInterface)
	parserType = parserValue.Type().String()

	// Dynamically find method by name - could be any method
	method := parserValue.MethodByName(methodName)
	if !method.IsValid() {
		return nil, fmt.Errorf("method %s not found on parser %s", methodName, parserType)
	}

	// Call the method with runtime-determined arguments
	// The actual function called depends on:
	// - Runtime parser selection
	// - Runtime method name selection
	// - Runtime input type
	args := []reflect.Value{reflect.ValueOf(input)}
	results := method.Call(args)

	if len(results) != 2 {
		return nil, fmt.Errorf("unexpected return values from %s.%s", parserType, methodName)
	}

	// Handle error result
	if !results[1].IsNil() {
		err := results[1].Interface().(error)
		return nil, err
	}

	return results[0].Interface(), nil
}

// performDynamicInterfaceExecution demonstrates advanced reflection attack vector
// This simulates how malicious code might use reflection to call vulnerable functions
// in ways that are extremely difficult to detect through static analysis
func performDynamicInterfaceExecution() {
	fmt.Println("Demonstrating advanced interface-based reflection attack:")

	parser := NewConfigurableParser()

	// Simulate dynamic configuration that could come from:
	// - External config files
	// - Network requests
	// - User input
	// - Environment variables
	dynamicConfigs := []struct {
		parserType string
		method     string
		input      interface{}
		desc       string
	}{
		{
			parserType: "text",
			method:     "Parse",
			input:      "en-US",
			desc:       "Dynamic language parsing via reflection",
		},
		{
			parserType: "html",
			method:     "Parse",
			input:      *strings.NewReader("<html><body>Dynamic HTML</body></html>"),
			desc:       "Dynamic HTML parsing via reflection",
		},
	}

	// Execute dynamic parsing - vulnerable functions called via reflection
	// Static analysis cannot determine which functions will be called because:
	// 1. Parser selection happens at runtime
	// 2. Method invocation uses reflection
	// 3. Input types vary dynamically
	for i, config := range dynamicConfigs {
		fmt.Printf("  [%d] %s\n", i+1, config.desc)

		result, err := parser.ExecuteParser(config.parserType, config.method, config.input)
		if err != nil {
			fmt.Printf("    Error: %v\n", err)
		} else {
			fmt.Printf("    Success: parsed result type %T\n", result)
		}

		// Additional reflection to make analysis even more complex
		executeAdditionalReflectionOperations(result)
	}

	// Demonstrate method enumeration attack
	demonstrateMethodEnumeration(parser)
}

// executeAdditionalReflectionOperations adds more reflection complexity
// This simulates how attackers might chain reflection operations
func executeAdditionalReflectionOperations(result interface{}) {
	if result == nil {
		return
	}

	resultValue := reflect.ValueOf(result)
	resultType := resultValue.Type()

	// Enumerate all methods on the result object
	for i := 0; i < resultType.NumMethod(); i++ {
		// Call methods with compatible signatures
		methodValue := resultValue.Method(i)
		methodType := methodValue.Type()

		// Look for methods that could be called without parameters
		if methodType.NumIn() == 0 && methodType.NumOut() > 0 {
			// This could potentially call vulnerable methods on result objects
			_ = methodValue.Call(nil)
		}
	}
}

// demonstrateMethodEnumeration shows how reflection can be used to discover
// and call methods that static analysis might miss
func demonstrateMethodEnumeration(parser *ConfigurableParser) {
	fmt.Println("  [3] Method enumeration via reflection")

	// Use reflection to enumerate all available parsers
	parsersValue := reflect.ValueOf(parser.parsers)
	parsersType := parsersValue.Type()

	if parsersType.Kind() == reflect.Map {
		for _, key := range parsersValue.MapKeys() {
			parserInstance := parsersValue.MapIndex(key)
			parserType := parserInstance.Type()

			// Enumerate methods on each parser
			for i := 0; i < parserType.NumMethod(); i++ {
				method := parserType.Method(i)

				// Could potentially call any discovered method
				// This demonstrates how reflection can be used to discover
				// and invoke functions that weren't explicitly called in code
				fmt.Printf("    Discovered: %s.%s\n", parserType.String(), method.Name)
			}
		}
	}
}
