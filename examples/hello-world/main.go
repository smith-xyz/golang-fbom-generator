package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Hello world! Sum of 1 and 2 is", sum(1, 2))
	fmt.Println("Hello world! Transitive multiplication of 1 and 2 is", multiplication(1, 2))
	os.Exit(0)
}

// This function is called directly by the main function
func sum(a int, b int) int {
	return a + b
}

// This function is called directly by the main function
func multiplication(a int, b int) int {
	return transitiveMultiplication(a, b)
}

// This function is called transitively by the multiplication function
func transitiveMultiplication(a int, b int) int {
	return a * b
}

func notCalled() {
	fmt.Println("This function is not called")
}
