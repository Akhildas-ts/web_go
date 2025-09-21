// main.go
package main

import (
	"fmt"
	"os"

	"ginpackage/database"
	"ginpackage/handler"
	"ginpackage/middleware"
	"ginpackage/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	var err error
	dsn := "user=postgres password=akhil@123 dbname=postgres host=localhost port=5432 sslmode=disable"
	database.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		os.Exit(1)
	}

	// Auto migrate models
	database.Db.AutoMigrate(&models.User{})
	database.Db.AutoMigrate(&models.Admin{})

	// Create default admin if doesn't exist
	var admin models.Admin
	result := database.Db.Where("email = ?", "admin@gmail.com").First(&admin)
	if result.Error != nil {
		// Hash the default admin password
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("123"), 14)
		defaultAdmin := models.Admin{
			Email:    "admin@gmail.com",
			Password: string(hashedPassword), // In a real app, hash this too
		}
		database.Db.Create(&defaultAdmin)
		fmt.Println("Default admin created with email: admin@gmail.com, password: 123")
	}

	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")
	router.Static("/static", "./static")

	// Public routes (no authentication required)
	router.GET("/", handler.IndexPage)
	router.POST("/", handler.IndexPage)
	router.GET("/signup", handler.Signup)
	router.POST("/signuppost", handler.SignupPost)
	router.GET("/login", handler.Login)
	router.POST("/loginpost", handler.LoginPost)
	router.GET("/adminlogin", handler.Adminlogin)
	router.POST("/adminloginpost", handler.AdminLoginPost)

	// Protected user routes
	userRoutes := router.Group("/")
	userRoutes.Use(middleware.JWTAuthMiddleware())
	userRoutes.Use(middleware.UserAuthMiddleware())
	{
		userRoutes.GET("/home", handler.HomeMethod)
		userRoutes.POST("/logout", handler.Logout)
	}

	// Protected admin routes
	adminRoutes := router.Group("/")
	adminRoutes.Use(middleware.JWTAuthMiddleware())
	adminRoutes.Use(middleware.AdminAuthMiddleware())
	{
		adminRoutes.GET("/admin", handler.AdminPage)
		adminRoutes.GET("/adminlogout", handler.AdminLogout)
		adminRoutes.GET("/searchusers", handler.Search)
		adminRoutes.POST("/deleteuser/:id", handler.DeleteUser)
		adminRoutes.GET("/edituser/:id", handler.EditUser)
		adminRoutes.POST("/updateuser/:id", handler.UpdateUser)
		adminRoutes.GET("/createuser", handler.CreateUserPage)
		adminRoutes.POST("/adduser", handler.AddNewUser)
	}

	fmt.Println("Server starting on :8080")
	router.Run(":8080")
}