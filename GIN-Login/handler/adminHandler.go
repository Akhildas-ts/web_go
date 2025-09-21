// handler/adminHandler.go
package handler

import (
	"ginpackage/database"
	"ginpackage/models"
	"net/http"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type Admin struct {
	Email    string
	Password string
}

func AdminLoginPost(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	email := strings.TrimSpace(c.Request.FormValue("adminEmail"))
	password := strings.TrimSpace(c.Request.FormValue("adminPassword"))

	// Validation
	if email == "" {
		c.HTML(200, "adminLogin.html", PageData{EmailInvalid: "Email is required"})
		return
	}
	if password == "" {
		c.HTML(200, "adminLogin.html", PageData{PassInvalid: "Password is required"})
		return
	}

	// Find admin
	var admin models.Admin
	result := database.Db.Where("email = ?", email).First(&admin)
	if result.Error != nil || result.RowsAffected == 0 {
		c.HTML(200, "adminLogin.html", PageData{EmailInvalid: "Admin not found"})
		return
	}

	// Check password (Note: In production, admin passwords should also be hashed)
	if password != admin.Password {
		c.HTML(200, "adminLogin.html", PageData{PassInvalid: "Invalid password"})
		return
	}

	// Generate JWT token for admin
	token, err := GenerateJWT(admin.ID, admin.Email, "admin")
	if err != nil {
		c.HTML(http.StatusInternalServerError, "adminLogin.html", PageData{PassInvalid: "Error generating token"})
		return
	}

	// Set JWT in cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("jwt_token", token, 24*60*60, "/", "", false, true) // 24 hours

	c.Redirect(303, "/admin")
}

func Adminlogin(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	// Check if admin already has valid JWT
	tokenString, err := c.Cookie("jwt_token")
	if err == nil && tokenString != "" {
		// Validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err == nil && token.Valid && claims.UserType == "admin" {
			c.Redirect(http.StatusSeeOther, "/admin")
			return
		}
	}

	c.HTML(200, "adminLogin.html", nil)
}

func AdminPage(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	// Get admin info from JWT claims (set by middleware)
	adminEmail, _ := c.Get("email")

	var users []models.User
	database.Db.Find(&users)

	c.HTML(200, "admin.html", gin.H{
		"users":       users,
		"admin_email": adminEmail,
	})
}

func AdminLogout(c *gin.Context) {
	// Clear JWT cookie
	c.SetCookie("jwt_token", "", -1, "/", "", false, true)
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.Redirect(303, "/adminlogin")
}

func Search(c *gin.Context) {
	var users []models.User
	searchQuery := c.DefaultQuery("query", "")

	if searchQuery != "" {
		database.Db.Where("name ILIKE ? OR email ILIKE ?", "%"+searchQuery+"%", "%"+searchQuery+"%").Find(&users)
	} else {
		database.Db.Find(&users)
	}

	c.HTML(200, "admin.html", gin.H{
		"users": users,
	})
}

func DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	// Convert string ID to uint
	id, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	// Delete user
	result := database.Db.Delete(&models.User{}, uint(id))
	if result.Error != nil {
		c.JSON(500, gin.H{"error": "Failed to delete user"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	c.Redirect(303, "/admin")
}

func EditUser(c *gin.Context) {
	var user models.User
	userID := c.Param("id")

	if err := database.Db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	c.HTML(200, "edituser.html", gin.H{
		"users": user,
	})
}

func UpdateUser(c *gin.Context) {
	var user models.User
	userID := c.Param("id")

	if err := database.Db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	email := strings.TrimSpace(c.PostForm("email"))
	password := strings.TrimSpace(c.PostForm("password"))

	// Validate input
	if name == "" || email == "" {
		c.JSON(400, gin.H{"error": "Name and email are required"})
		return
	}

	user.Name = name
	user.Email = email

	// Only update password if provided
	if password != "" {
		hashedPassword, err := HashPassword(password)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error processing password"})
			return
		}
		user.Password = hashedPassword
	}

	if err := database.Db.Save(&user).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to update user"})
		return
	}

	c.Redirect(303, "/admin")
}

func CreateUserPage(c *gin.Context) {
	c.HTML(200, "createuser.html", nil)
}

func AddNewUser(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("name"))
	email := strings.TrimSpace(c.PostForm("email"))
	password := strings.TrimSpace(c.PostForm("password"))

	// Validate input
	if name == "" || email == "" || password == "" {
		c.JSON(400, gin.H{"error": "All fields are required"})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := database.Db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		c.JSON(400, gin.H{"error": "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error processing password"})
		return
	}

	user := models.User{
		Name:     name,
		Email:    email,
		Password: hashedPassword,
	}

	if err := database.Db.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	c.Redirect(303, "/admin")
}
