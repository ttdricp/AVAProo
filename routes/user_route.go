package routes

import (
	"github.com/DigitalTroller/nosql_proj/controllers"
	"github.com/gin-gonic/gin"
	"net/http"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/users/signup", controllers.SignUp())
	incomingRoutes.POST("/users/login", controllers.Login())
	incomingRoutes.GET("/api-1", func(c *gin.Context) {

		c.Redirect(http.StatusFound, "/task")

	})
	incomingRoutes.POST("/addNewTask", controllers.AddNewTask())
	//incomingRoutes.GET("/", controllers.Main())
	incomingRoutes.LoadHTMLGlob("web_pages/*")

	incomingRoutes.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Main website",
		})
	})
	incomingRoutes.GET("/:filename", func(c *gin.Context) {
		c.HTML(http.StatusOK, c.Param("filename")+".html", gin.H{})
	})
}
