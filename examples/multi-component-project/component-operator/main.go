package main

import (
	"fmt"

	"github.com/example/multi-component-project/pkg/api"
	"github.com/example/multi-component-project/pkg/processor"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use: "hypershift-operator",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("HyperShift operator entry point")
			runHypershiftOperator()
		},
	}

	if err := cmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func runHypershiftOperator() {
	fmt.Println("Running HyperShift operator")
	api.StartServer()
	processor.ProcessData("hypershift-operator-data")
	startControllers()
}

func startControllers() {
	fmt.Println("Starting controllers")
	nodePoolController()
	hostedClusterController()
}

func nodePoolController() {
	fmt.Println("NodePool controller started")
}

func hostedClusterController() {
	fmt.Println("HostedCluster controller started")
}
