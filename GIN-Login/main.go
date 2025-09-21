package main

import (
	"fmt"

	"ginpackage/database"
	"ginpackage/handler"
	"ginpackage/models"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
)

func main() {
	var err error
	dsn := "user=postgres password=Arun@1435 dbname=postgres host=localhost port=5432 sslmode=disable"
	database.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	database.Db.AutoMigrate(&models.User{})
	database.Db.AutoMigrate(&models.Admin{Email: "admin@gmail.com", Password: "123"})

	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")
	router.Static("/static", "./static")
	router.GET("/", handler.IndexPage)
	router.POST("/", handler.IndexPage)
	router.GET("/signup", handler.Signup)
	router.POST("/signuppost", handler.SignupPost)
	router.GET("/login", handler.Login)
	router.POST("/loginpost", handler.LoginPost)
	router.GET("/home", handler.HomeMethod)
	router.POST("/logout", handler.Logout)
	router.POST("/adminloginpost", handler.AdminLoginPost)
	router.GET("/adminlogin", handler.Adminlogin)
	router.GET("/admin", handler.AdminPage)
	router.GET("/adminlogout", handler.AdminLogout)
	router.GET("/searchusers", handler.Search)
	router.POST("/deleteuser/:id", handler.DeleteUser)
	router.GET("/edituser/:id", handler.EditUser)
	router.POST("/updateuser/:id", handler.UpdateUser)
	router.GET("/createuser", handler.CreateUserPage)
	router.POST("/adduser", handler.AddNewUser)

	router.Run()

}
