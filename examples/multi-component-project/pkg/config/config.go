package config

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Port     int
	LogLevel string
	Debug    bool
}

func LoadConfig() *Config {
	fmt.Println("Loading configuration")
	logrus.Info("Configuration loaded")
	return &Config{
		Port:     8080,
		LogLevel: "info",
		Debug:    false,
	}
}

func (c *Config) Validate() error {
	if c.Port <= 0 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	return nil
}

func GetDefaultConfig() *Config {
	return &Config{
		Port:     8080,
		LogLevel: "info",
		Debug:    false,
	}
}
