package main

import (
	"auth/controllers"
	"auth/initializers"
	"auth/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.POST("/me", middleware.RequireAuth, controllers.Validate)
	r.Run()
}
