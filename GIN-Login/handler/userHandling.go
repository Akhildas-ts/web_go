// handler/userHandling.go
package handler

import (
	"fmt"
	"ginpackage/database"
	"ginpackage/models"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type PageData struct {
	EmailInvalid string
	PassInvalid  string
}

type User struct {
	Name     string
	Email    string
	Password string
}

type Claims struct {
	UserID   uint   `json:"user_id"`
	Email    string `json:"email"`
	UserType string `json:"user_type"`
	jwt.StandardClaims
}

var jwtKey = []byte("SecretKey") // In production, use environment variable

// HashPassword hashes a plain text password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPassword compares hashed password with plain text password
func CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// GenerateJWT generates a new JWT token
func GenerateJWT(userID uint, email, userType string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Email:    email,
		UserType: userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func IndexPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

func Signup(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

func SignupPost(c *gin.Context) {
	name := strings.TrimSpace(c.Request.FormValue("name"))
	email := strings.TrimSpace(c.Request.FormValue("email"))
	password := strings.TrimSpace(c.Request.FormValue("password"))

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	// Validation
	if name == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "Name is required"})
		return
	}
	if email == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "Email is required"})
		return
	}
	if password == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "Password is required"})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := database.Db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{"error": "Error processing password"})
		return
	}

	// Create user
	user := models.User{Name: name, Email: email, Password: hashedPassword}
	if database.Db == nil {
		fmt.Println("Database connection is nil!")
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{"error": "Database error"})
		return
	}

	result := database.Db.Create(&user)
	if result.Error != nil {
		fmt.Println(result.Error)
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{"error": "Failed to create user"})
		return
	}

	c.Redirect(http.StatusSeeOther, "/login")
}

func Login(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	
	// Check if user already has valid JWT
	tokenString, err := c.Cookie("jwt_token")
	if err == nil && tokenString != "" {
		// Validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		
		if err == nil && token.Valid && claims.UserType == "user" {
			c.Redirect(http.StatusSeeOther, "/home")
			return
		}
	}
	
	c.HTML(200, "login.html", nil)
}

func LoginPost(c *gin.Context) {
	email := strings.TrimSpace(c.Request.FormValue("emailName"))
	password := strings.TrimSpace(c.Request.FormValue("passwordName"))
	
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	// Validation
	if email == "" {
		c.HTML(200, "login.html", PageData{EmailInvalid: "Email is required"})
		return
	}
	if password == "" {
		c.HTML(200, "login.html", PageData{PassInvalid: "Password is required"})
		return
	}

	// Find user
	var user models.User
	result := database.Db.Where("email = ?", email).First(&user)
	if result.Error != nil || result.RowsAffected == 0 {
		c.HTML(200, "login.html", PageData{EmailInvalid: "User not found"})
		return
	}

	// Check password
	if !CheckPassword(user.Password, password) {
		c.HTML(200, "login.html", PageData{PassInvalid: "Invalid password"})
		return
	}

	// Generate JWT token
	token, err := GenerateJWT(user.ID, user.Email, "user")
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", PageData{PassInvalid: "Error generating token"})
		return
	}

	// Set JWT in cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("jwt_token", token, 24*60*60, "/", "", false, true) // 24 hours

	c.Redirect(http.StatusSeeOther, "/home")
}

func HomeMethod(c *gin.Context) {
	// Get user info from JWT claims (set by middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(303, "/login")
		return
	}

	email, _ := c.Get("email")
	
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	
	c.HTML(200, "index.html", gin.H{
		"user_id": userID,
		"email":   email,
	})
}

func Logout(c *gin.Context) {
	// Clear JWT cookie
	c.SetCookie("jwt_token", "", -1, "/", "", false, true)
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.Redirect(303, "/login")
}