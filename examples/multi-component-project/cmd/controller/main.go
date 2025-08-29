package main

import (
	"fmt"

	"github.com/example/multi-component-project/pkg/api"
	"github.com/example/multi-component-project/pkg/processor"
)

func main() {
	fmt.Println("Controller entry point")
	runController()
}

func runController() {
	fmt.Println("Running controller")
	processor.ProcessData("controller-data")
	api.HandleRequests()
}

func controllerLoop() {
	for i := 0; i < 10; i++ {
		fmt.Printf("Controller iteration %d\n", i)
	}
}
