package support

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func InitializeSupport() {
	fmt.Println("Initializing support utilities")
	setupLogging()
	setupMetrics()
}

func setupLogging() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.Info("Logging configured")
}

func setupMetrics() {
	fmt.Println("Metrics configured")
}

func GetVersion() string {
	return "v1.0.0"
}

func ValidateConfiguration() error {
	// Simulate configuration validation
	return nil
}
