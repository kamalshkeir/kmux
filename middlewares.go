package kmux

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kamalshkeir/kmux/gzip"

	"github.com/kamalshkeir/kmux/ratelimiter"

	"github.com/kamalshkeir/klog"
)

type GlobalMiddlewareFunc func(handler http.Handler) http.Handler

type KmuxMiddlewareFunc interface {
	func(Handler,string,string) Handler | func(Handler) Handler
}

func Gzip() GlobalMiddlewareFunc {
	return gzip.GZIP
}

func Limiter() GlobalMiddlewareFunc {
	return ratelimiter.LIMITER
}

// Recovery is a global requests recovery middleware, print error if any panic
func Recovery() GlobalMiddlewareFunc {
	return recovery
}

func BasicAuth(kmuxHandlerFunc Handler, user, pass string) Handler {
	return func(c *Context) {
		// Extract the username and password from the request
		// Authorization header. If no Authentication header is present
		// or the header value is invalid, then the 'ok' return value
		// will be false.
		username, password, ok := c.Request.BasicAuth()
		if ok {
			// Calculate SHA-256 hashes for the provided and expected
			// usernames and passwords.
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(user))
			expectedPasswordHash := sha256.Sum256([]byte(pass))

			// Use the subtle.ConstantTimeCompare() function to check if
			// the provided username and password hashes equal the
			// expected username and password hashes. ConstantTimeCompare
			// will return 1 if the values are equal, or 0 otherwise.
			// Importantly, we should to do the work to evaluate both the
			// username and password before checking the return values to
			// avoid leaking information.
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			// If the username and password are correct, then call
			// the kmuxHandlerFunc in the chain. Make sure to return
			// afterwards, so that none of the code below is run.
			if usernameMatch && passwordMatch {
				kmuxHandlerFunc(c)
				return
			}
		}

		// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		c.ResponseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(c.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
	}
}

func (router *Router) AllowOrigines(origines ...string) {
	if !corsAdded {
		midwrs = append(midwrs, cors)
		corsAdded = true
	}
	origineslist = append(origineslist, origines...)
}

 

func recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				klog.Printf("rd%v\n",err)
				jsonBody, _ := json.Marshal(map[string]string{
					"error": "There was an internal server error",
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(jsonBody)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var corsAdded = false
var origineslist = []string{}
var cors = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set headers
		o := strings.Join(origineslist, ",")
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Set("Access-Control-Allow-Headers:", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Next
		next.ServeHTTP(w, r)
	})
}




