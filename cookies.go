package kmux

import (
	"net/http"
	"strings"
	"time"
)

func init() {
	if strings.Contains(PORT, "443") {
		COOKIES_SECURE = true
	}
}

// SetCookie set cookie given key and value
func (c *Context) SetCookie(key, value string, maxAge ...time.Duration) {
	if !COOKIES_SECURE {
		if c.Request.TLS != nil {
			COOKIES_SECURE = true
		}
	}
	if corsEnabled {
		COOKIES_SameSite = http.SameSiteNoneMode
	}
	var ma int
	if len(maxAge) > 0 {
		ma = int(maxAge[0].Seconds())
		http.SetCookie(c.ResponseWriter, &http.Cookie{
			Name:     key,
			Value:    value,
			Path:     "/",
			Expires:  time.Now().Add(maxAge[0]),
			HttpOnly: COOKIES_HttpOnly,
			SameSite: COOKIES_SameSite,
			Secure:   COOKIES_SECURE,
			MaxAge:   ma,
		})
	} else {
		ma = int(COOKIES_Expires.Seconds())
		http.SetCookie(c.ResponseWriter, &http.Cookie{
			Name:     key,
			Value:    value,
			Path:     "/",
			Expires:  time.Now().Add(COOKIES_Expires),
			HttpOnly: COOKIES_HttpOnly,
			SameSite: COOKIES_SameSite,
			Secure:   COOKIES_SECURE,
			MaxAge:   ma,
		})
	}
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
		Secure:   COOKIES_SECURE,
		MaxAge:   -1,
	})
}
