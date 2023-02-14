package kmux

import (
	"net/http"
	"net/http/pprof"
	"regexp"
	"strings"

	"github.com/kamalshkeir/kmux/ws"
)

const (
	GET int = iota
	POST
	PUT
	PATCH
	DELETE
	HEAD
	OPTIONS
	WS
	SSE
)

var methods = map[int]string{
	GET:     "GET",
	POST:    "POST",
	PUT:     "PUT",
	PATCH:   "PATCH",
	DELETE:  "DELETE",
	HEAD:    "HEAD",
	OPTIONS: "OPTIONS",
	WS:      "WS",
	SSE:     "SSE",
}

// Handler
type Handler func(c *Context)
type WsHandler func(c *WsContext)

// Router
type Router struct {
	Routes       map[int][]Route
	DefaultRoute Handler
	Server       *http.Server
}

type GroupRouter struct {
	Router
	Group string
}

// Route
type Route struct {
	Method  string
	Pattern *regexp.Regexp
	Handler
	WsHandler
	Clients         map[string]*ws.Conn
	AllowedOrigines []string
}

// New Create New Router from env file default: '.env'
func New() *Router {
	app := &Router{
		Routes: map[int][]Route{},
		DefaultRoute: func(c *Context) {
			c.Status(404).Text("Page Not Found")
		},
	}
	return app
}

// handle a route
func (router *Router) handle(method int, pattern string, handler Handler, wshandler WsHandler, allowed []string) {
	re := regexp.MustCompile(adaptParams(pattern))
	route := Route{Method: methods[method], Pattern: re, Handler: handler, WsHandler: wshandler, Clients: nil, AllowedOrigines: []string{}}
	if len(allowed) > 0 && method != GET && method != HEAD && method != OPTIONS {
		route.AllowedOrigines = append(route.AllowedOrigines, allowed...)
	}
	if method == WS {
		route.Clients = map[string]*ws.Conn{}
	}
	if _, ok := router.Routes[method]; !ok {
		router.Routes[method] = []Route{}
	}
	if len(router.Routes[method]) == 0 {
		router.Routes[method] = append(router.Routes[method], route)
		return
	}
	for i, rt := range router.Routes[method] {
		if rt.Pattern.String() == re.String() {
			router.Routes[method] = append(router.Routes[method][:i], router.Routes[method][i+1:]...)
		}
	}
	router.Routes[method] = append(router.Routes[method], route)
}

// WithPprof enable std library pprof at /debug/pprof, prefix default to 'debug'
func (router *Router) WithPprof(path ...string) {
	if len(path) > 0 && strings.Contains(path[0], "/") {
		path[0] = strings.TrimPrefix(path[0], "/")
		path[0] = strings.TrimSuffix(path[0], "/")
	} else {
		path = append(path, "debug")
	}
	handler := func(c *Context) {
		ty := c.Param("type")
		switch ty {
		case "pprof", "":
			pprof.Index(c.ResponseWriter, c.Request)
			return
		case "profile":
			pprof.Profile(c.ResponseWriter, c.Request)
			return
		case "trace":
			pprof.Trace(c.ResponseWriter, c.Request)
			return
		default:
			pprof.Handler(ty).ServeHTTP(c.ResponseWriter, c.Request)
			return
		}
	}
	router.GET("/"+path[0]+"/:type", handler)
}

// WithMetrics enable path /metrics (default) using http.Handler like promhttp.Handler()
func (router *Router) WithMetrics(httpHandler http.Handler, path ...string) {
	if len(path) > 0 && strings.Contains(path[0], "/") {
		path[0] = strings.TrimPrefix(path[0], "/")
		path[0] = strings.TrimSuffix(path[0], "/")
	} else {
		path = append(path, "metrics")
	}

	router.GET("/"+path[0], func(c *Context) {
		httpHandler.ServeHTTP(c.ResponseWriter, c.Request)
	})
}

func (router *Router) Group(prefix string) *GroupRouter {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return &GroupRouter{
		Router: *router,
		Group:  prefix,
	}
}

// GET handle GET to a route
func (gr *GroupRouter) GET(pattern string, handler Handler) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(GET, gr.Group+pattern, handler, nil, nil)
}

// GET handle GET to a route
func (router *Router) GET(pattern string, handler Handler) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(GET, pattern, handler, nil, nil)
}

// HandlerFunc support standard library http.HandlerFunc
func (router *Router) HandlerFunc(method string, pattern string, handler http.HandlerFunc, allowed ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	var meth int
	mm := []int{}
	for i, v := range methods {
		if strings.EqualFold(v, method) {
			meth = i
		} else {
			if v != "WS" && v != "SSE" {
				mm = append(mm, i)
			}
		}
	}

	switch method {
	case "*", "all", "ALL":
		for _, smethod := range mm {
			router.handle(smethod, pattern, func(c *Context) { handler.ServeHTTP(c.ResponseWriter, c.Request) }, nil, allowed)
		}
	default:
		router.handle(meth, pattern, func(c *Context) { handler.ServeHTTP(c.ResponseWriter, c.Request) }, nil, allowed)
	}
}

// HandlerFunc support standard library http.HandlerFunc
func (gr *GroupRouter) HandlerFunc(method string, pattern string, handler http.HandlerFunc, allowed ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	var meth int
	mm := []int{}
	for i, v := range methods {
		if strings.EqualFold(v, method) {
			meth = i
		} else {
			if v != "WS" && v != "SSE" {
				mm = append(mm, i)
			}
		}
	}

	switch method {
	case "*", "all", "ALL":
		for _, smethod := range mm {
			gr.Router.handle(smethod, gr.Group+pattern, func(c *Context) { handler.ServeHTTP(c.ResponseWriter, c.Request) }, nil, allowed)
		}
	default:
		gr.Router.handle(meth, gr.Group+pattern, func(c *Context) { handler.ServeHTTP(c.ResponseWriter, c.Request) }, nil, allowed)
	}
}

// HandlerFunc support standard library http.HandlerFunc
func (router *Router) Handle(method string, pattern string, handler Handler, allowed ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	var meth int
	mm := []int{}
	for i, v := range methods {
		if strings.EqualFold(v, method) {
			meth = i
		} else {
			if v != "WS" && v != "SSE" {
				mm = append(mm, i)
			}
		}
	}

	switch method {
	case "*", "all", "ALL":
		for _, smethod := range mm {
			router.handle(smethod, pattern, handler, nil, allowed)
		}
	default:
		router.handle(meth, pattern, handler, nil, allowed)
	}
}

func (gr *GroupRouter) Handle(method string, pattern string, handler Handler, allowed ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	var meth int
	mm := []int{}
	for i, v := range methods {
		if strings.EqualFold(v, method) {
			meth = i
		} else {
			if v != "WS" && v != "SSE" {
				mm = append(mm, i)
			}
		}
	}

	switch method {
	case "*", "all", "ALL":
		for _, smethod := range mm {
			gr.Router.handle(smethod, gr.Group+pattern, handler, nil, allowed)
		}
	default:
		gr.Router.handle(meth, gr.Group+pattern, handler, nil, allowed)
	}
}

// POST handle POST to a route
func (router *Router) POST(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(POST, pattern, handler, nil, allowed_origines)
}

func (gr *GroupRouter) POST(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(POST, gr.Group+pattern, handler, nil, allowed_origines)
}

// PUT handle PUT to a route
func (router *Router) PUT(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(PUT, pattern, handler, nil, allowed_origines)
}

func (gr *GroupRouter) PUT(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(PUT, gr.Group+pattern, handler, nil, allowed_origines)
}

// PATCH handle PATCH to a route
func (router *Router) PATCH(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(PATCH, pattern, handler, nil, allowed_origines)
}
func (gr *GroupRouter) PATCH(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(PATCH, gr.Group+pattern, handler, nil, allowed_origines)
}

// DELETE handle DELETE to a route
func (router *Router) DELETE(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(DELETE, pattern, handler, nil, allowed_origines)
}
func (gr *GroupRouter) DELETE(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(DELETE, gr.Group+pattern, handler, nil, allowed_origines)
}

// HEAD handle HEAD to a route
func (router *Router) HEAD(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(HEAD, pattern, handler, nil, nil)
}
func (gr *GroupRouter) HEAD(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(HEAD, gr.Group+pattern, handler, nil, nil)
}

// OPTIONS handle OPTIONS to a route
func (router *Router) OPTIONS(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(OPTIONS, pattern, handler, nil, nil)
}
func (gr *GroupRouter) OPTIONS(pattern string, handler Handler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(OPTIONS, gr.Group+pattern, handler, nil, nil)
}

// WS handle WS connection on a pattern
func (router *Router) WS(pattern string, wsHandler WsHandler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	router.handle(WS, pattern, nil, wsHandler, allowed_origines)
}
func (gr *GroupRouter) WS(pattern string, wsHandler WsHandler, allowed_origines ...string) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	gr.Router.handle(WS, gr.Group+pattern, nil, wsHandler, allowed_origines)
}

// SSE handle SSE to a route
func (router *Router) SSE(pattern string, handler Handler) {
	router.GET(pattern, func(c *Context) {
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
		c.SetHeader("Content-Type", "text/event-stream")
		c.SetHeader("Cache-Control", "no-cache")
		c.SetHeader("Connection", "keep-alive")
		handler(c)
	})
}
func (gr *GroupRouter) SSE(pattern string, handler Handler) {
	gr.GET(pattern, func(c *Context) {
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
		c.SetHeader("Content-Type", "text/event-stream")
		c.SetHeader("Cache-Control", "no-cache")
		c.SetHeader("Connection", "keep-alive")
		handler(c)
	})
}
