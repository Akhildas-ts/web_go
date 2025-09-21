package handler

import (
	"fmt"
	"ginpackage/database"
	"ginpackage/models"
	"time"

	"net/http"
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

	var admin = models.Admin{}
	fmt.Println(admin)
	cookie, err := c.Cookie("adumin")
	if err != nil {
		fmt.Println(err, "erorr1")
	} else if cookie != "" {

		c.Redirect(303, "/adminloginpost")
		return
	}

	if email == "" {
		var n = PageData{EmailInvalid: "Email is Invalid"}
		c.HTML(200, "adminLogin.html", n)

		fmt.Println("EmailEmpty")
		return
	} else if password == "" {
		var n = PageData{PassInvalid: "Password is Invalid"}
		c.HTML(200, "adminLogin.html", n)
		fmt.Println("PasswordEmpty")
		return
	}
	result := database.Db.Where("email = ?", email).Where("password = ?", password).First(&admin)

	if result.Error != nil || result.RowsAffected == 0 {
		c.HTML(303, "adminLogin.html", PageData{EmailInvalid: "Email Not Found"})
	}
	if password != admin.Password {
		c.HTML(303, "adminLogin.html", PageData{PassInvalid: "Password not matches"})
	}
	if password == admin.Password {

		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("adumin", "124", 300, "/", "", false, true)
		cookie, _ := c.Cookie("adumin")
		fmt.Println(cookie, "adumin-cookie here")
		var users []models.User

		database.Db.Find(&users)

		// c.HTML(200, "admin.html", gin.H{
		// 	"users": users,
		// })
		c.Redirect(303, "/admin")

	} else {
		c.Redirect(303, "/adminlogin")
		return
	}
}
func Adminlogin(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	cookie, err := c.Cookie("adumin")
	fmt.Println(cookie, "HEy cooke")
	if err != nil {
		fmt.Println(err, "error2")
	}
	if err == nil && cookie != "" {
		fmt.Print("ethii")
		c.Redirect(http.StatusSeeOther, "/admin")
		// c.HTML(200, "admin.html", nil)

		return
	}
	c.HTML(200, "adminLogin.html", nil)
}
func AdminPage(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	cookie, err := c.Cookie("adumin")
	if err != nil || cookie == "" {
		c.Redirect(303, "/adminlogin")
		return
	}
	var users []models.User
	database.Db.Find(&users)
	c.HTML(200, "admin.html", gin.H{
		"users": users,
	})
}
func AdminLogout(c *gin.Context) {
	c.SetCookie("adumin", "", -1, "", "", true, true)
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.Redirect(303, "/adminlogin")
}

func Search(c *gin.Context) {
	var users []models.User
	database.Db.Find(&users)
	searchQuery := c.DefaultQuery("query", "")
	if searchQuery != "" {
		database.Db.Where("name ILIKE ?", "%"+searchQuery+"%").Find(&users)
	} else {
		database.Db.Find(&users)
	}
	c.HTML(200, "admin.html", gin.H{
		"users": users,
	})
}
func DeleteUser(c *gin.Context) {
	var users models.User
	userID := c.Param("id")
	if err := database.Db.Where("id =?", userID).Delete(&users).Error; err != nil {
		c.JSON(404, gin.H{
			"error": "user not found",
		})
		return
	}
	c.Redirect(303, "/admin")

}
func EditUser(c *gin.Context) {
	var users models.User
	userID := c.Param("id")
	if err := database.Db.Where("id=?", userID).First(&users).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	c.HTML(200, "edituser.html", gin.H{
		"users": users,
	})

}
func UpdateUser(c *gin.Context) {
	var users models.User
	userID := c.Param("id")
	if err := database.Db.Where("id=?", userID).First(&users).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	users.Name = c.PostForm("name")
	users.Email = c.PostForm("email")
	users.Password = c.PostForm("password")
	database.Db.Save(&users)
	c.Redirect(303, "/admin")

}
func CreateUserPage(c *gin.Context) {
	c.HTML(200, "createuser.html", nil)
}
func AddNewUser(c *gin.Context) {
	var users models.User
	users.Name = c.PostForm("name")
	users.Email = c.PostForm("email")
	users.Password = c.PostForm("password")
	database.Db.Save(&users)
	c.Redirect(303, "/admin")
}
func GenerateJWT(cookievalue string) (string, error) {
	mySigningKey := []byte("SecretKey")
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Subject:   cookievalue,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	return ss, err

}
