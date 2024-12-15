package routes

import (
	"github.com/gin-gonic/gin"
	controller "golang-jwt-project/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/singup", controller.SingUp())
	incomingRoutes.POST("users/login", controller.Login())
}
