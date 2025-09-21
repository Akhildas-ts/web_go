package handler

import (
	"fmt"
	"ginpackage/database"
	"ginpackage/models"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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

func IndexPage(c *gin.Context) {
	c.HTML(http.StatusFound, "signup.html", nil)
}
func Signup(c *gin.Context) {
	c.HTML(http.StatusFound, "signup.html", nil)
}
func SignupPost(c *gin.Context) {

	name := strings.TrimSpace(c.Request.FormValue("name"))
	email := strings.TrimSpace(c.Request.FormValue("email"))
	password := strings.TrimSpace(c.Request.FormValue("password"))

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	if email == "" {
		c.HTML(http.StatusBadGateway, "signup.html", "EmailInvalid")

		return
	}
	if password == "" {
		c.HTML(http.StatusBadGateway, "signup.html", "Password Invalid")

		return
	}
	user := models.User{Name: name, Email: email, Password: password}
	if database.Db == nil {
		fmt.Println("Database connection is nil!")
		return
	}
	result := database.Db.Create(&user)
	if result.Error != nil {
		fmt.Println(result.Error)
	}

	c.Redirect(http.StatusSeeOther, "/login")
	fmt.Printf("%+v", user)
}
func Login(c *gin.Context) {

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	cookie, err := c.Cookie("logincookie")
	fmt.Println(cookie, "getUserCookie")
	if err == nil && cookie != "" {
		c.Redirect(http.StatusSeeOther, "/home")
		return
	}
	c.HTML(200, "login.html", nil)
}
func LoginPost(c *gin.Context) {

	email := strings.TrimSpace(c.Request.FormValue("emailName"))
	password := strings.TrimSpace(c.Request.FormValue("passwordName"))
	var user = models.User{}
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	cookie, err := c.Cookie("logincookie")
	fmt.Println(cookie, "loginpostcookie")
	if err != nil {
		fmt.Println(err)
	} else if cookie != "" {

		c.Redirect(303, "/loginpost")
		return
	}

	// user, ok := userData[email]

	if email == "" {
		var n = PageData{EmailInvalid: "Email is Invalid"}
		c.HTML(200, "login.html", n)

		fmt.Println("EmailEmpty")
		return
	} else if password == "" {
		var n = PageData{PassInvalid: "Password is Invalid"}
		c.HTML(200, "login.html", n)
		fmt.Println("PasswordEmpty")
		return
	}
	result := database.Db.Where("email =  ?", email).First(&user)

	if result.Error != nil || result.RowsAffected == 0 {
		c.HTML(303, "login.html", PageData{EmailInvalid: "Email Not Found"})
	}
	if password != user.Password {
		c.HTML(303, "login.html", PageData{PassInvalid: "Password not matches"})
	}
	if password == user.Password {

		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("logincookie", "123", 300, "/", "", false, true)

		cookie, _ := c.Cookie("logincookie")
		fmt.Println(cookie)
		c.HTML(http.StatusSeeOther, "index.html", cookie)

	} else {

		c.Redirect(303, "/login")

		return
	}

}
func HomeMethod(c *gin.Context) {
	cookie, err := c.Cookie("logincookie")
	if err != nil || cookie == "" {
		// c.HTML(200,"login.html",nil)
		c.Redirect(303, "/login")

		return
	}

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.HTML(200, "index.html", nil)
}
func Logout(c *gin.Context) {
	c.SetCookie("logincookie", "", -1, "", "", true, true)
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.Redirect(303, "/login")
}
