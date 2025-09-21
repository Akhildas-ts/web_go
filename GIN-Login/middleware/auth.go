// middleware/auth.go - NEW FILE
package middleware

import (
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("SecretKey") // In production, use environment variable

type Claims struct {
	UserID   uint   `json:"user_id"`
	Email    string `json:"email"`
	UserType string `json:"user_type"` // "user" or "admin"
	jwt.StandardClaims
}

// JWTAuthMiddleware validates JWT tokens
func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get token from Authorization header first
		authHeader := c.GetHeader("Authorization")
		var tokenString string

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// Fallback to cookie
			cookie, err := c.Cookie("jwt_token")
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
				c.Abort()
				return
			}
			tokenString = cookie
		}

		// Parse and validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("user_type", claims.UserType)

		c.Next()
	}
}

// AdminAuthMiddleware ensures only admins can access
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userType, exists := c.Get("user_type")
		if !exists || userType != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// UserAuthMiddleware ensures only users can access
func UserAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userType, exists := c.Get("user_type")
		if !exists || userType != "user" {
			c.JSON(http.StatusForbidden, gin.H{"error": "User access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
