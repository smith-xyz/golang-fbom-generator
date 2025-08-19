package operator

import (
	"fmt"

	"github.com/example/multi-component-project/pkg/api"
	"github.com/example/multi-component-project/pkg/processor"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use: "operator",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Operator entry point")
			runOperator()
		},
	}
}

func runOperator() {
	fmt.Println("Running operator")
	api.StartServer()
	processor.ProcessData("operator-data")
}

func operatorSpecificFunction() {
	fmt.Println("Operator-specific functionality")
}
