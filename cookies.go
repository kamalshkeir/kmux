package kmux

import (
	"net/http"
	"strings"
	"time"
)


var (
	COOKIES_Expires = time.Now().Add(7 * 24 * time.Hour)
	COOKIES_SameSite = http.SameSiteStrictMode
	COOKIES_HttpOnly = true
	COOKIES_Secure = false
)

func init() {
	if strings.Contains(PORT,"443") {
		COOKIES_Secure=true
	}
}


// SetCookie set cookie given key and value
func (c *Context) SetCookie(key, value string) {
	http.SetCookie(c.ResponseWriter, &http.Cookie{
		Name:     key,
		Value:    value,
		Path:     "/",
		Expires:  COOKIES_Expires,
		HttpOnly: COOKIES_HttpOnly,
		SameSite: COOKIES_SameSite,
		Secure: COOKIES_Secure,
		MaxAge: 30 * 24 * 3600,
	})
}

// GetCookie get cookie with specific key
func (c *Context) GetCookie(key string) (string, error) {
	v, err := c.Request.Cookie(key)
	if err != nil {
		return "", err
	}
	return v.Value, nil
}

// DeleteCookie delete cookie with specific key
func (c *Context) DeleteCookie(key string) {
	http.SetCookie(c.ResponseWriter, &http.Cookie{
		Name:     key,
		Value:    "",
		Path:     "/",
		Expires:  time.Now(),
		HttpOnly: COOKIES_HttpOnly,
		SameSite: COOKIES_SameSite,
		Secure: COOKIES_Secure,
		MaxAge: -1,
	})
}
