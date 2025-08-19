package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func StartServer() {
	fmt.Println("Starting API server")
	logrus.Info("Server started")
	setupRoutes()
}

func setupRoutes() {
	r := gin.Default()
	r.GET("/health", healthHandler)
	r.GET("/status", statusHandler)
}

func healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "healthy"})
}

func statusHandler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "running"})
}

func HandleRequests() {
	fmt.Println("Handling requests")
	processRequest("test-request")
}

func processRequest(req string) {
	logrus.WithField("request", req).Info("Processing request")
}
