package main

import (
	"fmt"
	"os"

	"github.com/example/multi-component-project/cmd/cli"
	"github.com/example/multi-component-project/cmd/operator"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use: "hypershift-reproduction",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Main entry point")
			mainFunction()
		},
	}

	cmd.AddCommand(operator.NewCommand())
	cmd.AddCommand(cli.NewCommand())

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func mainFunction() {
	fmt.Println("This is a user-defined function in main")
}

func helperFunction(input string) string {
	return "processed: " + input
}
