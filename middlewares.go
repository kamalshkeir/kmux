package kmux

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kamalshkeir/kmux/gzip"

	"github.com/kamalshkeir/kmux/ratelimiter"

	"github.com/kamalshkeir/klog"
)

type GlobalMiddlewareFunc func(handler http.Handler) http.Handler

type KmuxMiddlewareFunc interface {
	func(Handler, string, string) Handler | func(Handler) Handler
}

func Gzip() GlobalMiddlewareFunc {
	return gzip.GZIP
}

func Limiter() GlobalMiddlewareFunc {
	return ratelimiter.LIMITER
}

func Recovery() GlobalMiddlewareFunc {
	return recovery
}

func recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				klog.Printf("rd%v\n", err)
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

func BasicAuth(kmuxHandlerFunc Handler, user, pass string) Handler {
	return func(c *Context) {
		username, password, ok := c.Request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			if user == "" || pass == "" {
				c.ResponseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(c.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
				return
			}
			expectedUsernameHash := sha256.Sum256([]byte(user))
			expectedPasswordHash := sha256.Sum256([]byte(pass))
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				kmuxHandlerFunc(c)
				return
			}
		}
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

// Logs middleware log requests, and can execute one optional callback on each request
func Logs(callback ...func(method, path, remote string, status int, took time.Duration)) GlobalMiddlewareFunc {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ignored := []string{"/metrics", "sw.js", "favicon", "/static/", "/sse/", "/ws/", "/wss/"}
			for _, ig := range ignored {
				if strings.Contains(r.URL.Path, ig) {
					handler.ServeHTTP(w, r)
					return
				}
			}
			//check if connection is ws
			for _, header := range r.Header["Upgrade"] {
				if header == "websocket" {
					// connection is ws
					handler.ServeHTTP(w, r)
					return
				}
			}
			recorder := &StatusRecorder{
				ResponseWriter: w,
				Status:         200,
			}
			t := time.Now()
			handler.ServeHTTP(recorder, r)
			took := time.Since(t)
			res := fmt.Sprintf("[%s] --> '%s' --> [%d]  from: %s ---------- Took: %v", r.Method, r.URL.Path, recorder.Status, r.RemoteAddr, took)

			if len(callback) > 0 {
				callback[0](r.Method, r.URL.Path, r.RemoteAddr, recorder.Status, took)
			}
			if recorder.Status >= 200 && recorder.Status < 400 {
				klog.Printfs("gr%s\n", res)
			} else if recorder.Status >= 400 || recorder.Status < 200 {
				klog.Printfs("rd%s\n", res)
			} else {
				klog.Printfs("yl%s\n", res)
			}
		})
	}
}

type StatusRecorder struct {
	http.ResponseWriter
	Status int
}

func (r *StatusRecorder) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *StatusRecorder) Flush() {
	if v, ok := r.ResponseWriter.(http.Flusher); ok {
		v.Flush()
	}
}

func (r *StatusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("LOGS MIDDLEWARE: http.Hijacker interface is not supported")
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
