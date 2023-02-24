package main

import (
	"github.com/DigitalTroller/nosql_proj/configs"
	"github.com/DigitalTroller/nosql_proj/middleware"
	"github.com/DigitalTroller/nosql_proj/routes" //add this
	"github.com/gin-gonic/gin"
	_ "github.com/heroku/x/hmetrics/onload"
)

func main() {
	r := gin.New()

	configs.ConnectDB()
	r.Static("/css", "./css")

	r.Use(gin.Logger())
	routes.UserRoutes(r)

	r.Use(middleware.Authentication())

	// API-2
	//r.GET("/api-1", func(c *gin.Context) {
	//	c.Redirect(http.StatusFound, "/task")
	//})

	// API-1
	r.GET("/api-2", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for api-2"})
	})

	r.Run(":" + "4000")

}
