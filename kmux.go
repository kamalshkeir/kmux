package kmux

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"

	"github.com/kamalshkeir/kmap"
	"github.com/kamalshkeir/kmux/ws"

	"github.com/kamalshkeir/klog"
)

type Handler func(c *Context)
type WsHandler func(c *WsContext)
type M map[string]any

type Route struct {
	Method  string
	Pattern string
	Handler
	WsHandler
	Clients map[string]*ws.Conn
	Docs    *DocsRoute
	Origine string
}

type Router struct {
	Server           *http.Server
	Routes           *kmap.SafeMap[string, []Route]
	NotFound         Handler
	GlobalOPTIONS    Handler
	MethodNotAllowed Handler
	contextPool      sync.Pool
	wscontextPool    sync.Pool
	paramsPool       sync.Pool
	trees            map[string]*node
	PanicHandler     func(http.ResponseWriter, *http.Request, interface{})
	maxParams        uint16
}

type GroupRouter struct {
	*Router
	Group string
}

// New returns a new initialized Router.
// Path auto-correction, including trailing slashes, is enabled by default.
func New() *Router {
	r := &Router{
		Routes: kmap.New[string, []Route](false),
	}
	if r.contextPool.New == nil {
		r.contextPool.New = func() interface{} {
			return &Context{
				status:    200,
				CtxParams: Params{},
			}
		}
	}
	if r.wscontextPool.New == nil {
		r.wscontextPool.New = func() interface{} {
			return &WsContext{
				Clients:   make(map[string]*ws.Conn),
				CtxParams: Params{},
			}
		}
	}
	return r
}

func (router *Router) Group(prefix string) *GroupRouter {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return &GroupRouter{
		Router: router,
		Group:  prefix,
	}
}

// Use chain global middlewares applied on the router
func (router *Router) Use(midws ...func(http.Handler) http.Handler) {
	midwrs = append(midwrs, midws...)
}

// Get is a shortcut for router.Handle(http.MethodGet, path, handle)
func (r *Router) Get(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodGet, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Get(pattern string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	return gr.Router.handle("GET", gr.Group+pattern, handler, nil, allowedOrigine...)
}

// Head is a shortcut for router.Handle(http.MethodHead, path, handle)
func (r *Router) Head(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodHead, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Head(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodHead, gr.Group+path, handler, nil, allowedOrigine...)
}

// Options is a shortcut for router.Handle(http.MethodOptions, path, handle)
func (r *Router) Options(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodOptions, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Options(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodOptions, gr.Group+path, handler, nil, allowedOrigine...)
}

// Post is a shortcut for router.Handle(http.MethodPost, path, handle)
func (r *Router) Post(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodPost, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Post(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodPost, gr.Group+path, handler, nil, allowedOrigine...)
}

// Put is a shortcut for router.Handle(http.MethodPut, path, handle)
func (r *Router) Put(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodPut, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Put(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodPut, gr.Group+path, handler, nil, allowedOrigine...)
}

// Patch is a shortcut for router.Handle(http.MethodPatch, path, handle)
func (r *Router) Patch(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodPatch, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Patch(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodPatch, gr.Group+path, handler, nil, allowedOrigine...)
}

// Delete is a shortcut for router.Handle(http.MethodDelete, path, handle)
func (r *Router) Delete(path string, handle Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodDelete, path, handle, nil, allowedOrigine...)
}

func (gr *GroupRouter) Delete(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodDelete, gr.Group+path, handler, nil, allowedOrigine...)
}

func (r *Router) Ws(path string, wshandle WsHandler, allowedOrigine ...string) *Route {
	return r.handle("WS", path, nil, wshandle, allowedOrigine...)
}

func (gr *GroupRouter) Ws(path string, handler Handler, allowedOrigine ...string) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	gr.Router.handle("WS", gr.Group+path, handler, nil, allowedOrigine...)
}

func (r *Router) Sse(path string, handler Handler, allowedOrigine ...string) {
	r.Get(path, func(c *Context) {
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
		c.SetHeader("Content-Type", "text/event-stream")
		c.SetHeader("Cache-Control", "no-cache")
		c.SetHeader("Connection", "keep-alive")
		handler(c)
	}, allowedOrigine...)
}

func (gr *GroupRouter) Sse(path string, handler Handler, allowedOrigine ...string) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.Get(gr.Group+path, func(c *Context) {
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
		c.SetHeader("Content-Type", "text/event-stream")
		c.SetHeader("Cache-Control", "no-cache")
		c.SetHeader("Connection", "keep-alive")
		handler(c)
	}, allowedOrigine...)
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
	router.Get("/"+path[0]+"/:type", handler)
}

func (router *Router) WithMetrics(httpHandler http.Handler, path ...string) {
	if len(path) > 0 && strings.Contains(path[0], "/") {
		path[0] = strings.TrimPrefix(path[0], "/")
	} else {
		path = append(path, "metrics")
	}

	router.Get("/"+path[0], func(c *Context) {
		httpHandler.ServeHTTP(c.ResponseWriter, c.Request)
	})
}

func (r *Router) handle(method, path string, handler Handler, wshandler WsHandler, allowed ...string) *Route {
	varsCount := uint16(0)
	if len(path) > 1 && path[len(path)-1] != '/' && !strings.Contains(path, "*") {
		path += "/"
	}
	route := Route{}
	route.Method = method
	route.Pattern = path
	route.Handler = handler
	route.WsHandler = wshandler
	route.Clients = nil
	if len(allowed) > 0 {
		route.Origine = allowed[0]
		route.Origine = strings.Replace(route.Origine, "localhost", "127.0.0.1", 1)
		if !strings.HasPrefix(route.Origine, "http") {
			route.Origine = "http://" + route.Origine
		}
	}
	if withDocs && !strings.Contains(path, "*") {
		route.Docs = &DocsRoute{
			Pattern:     path,
			Summary:     "A " + method + " request on " + path,
			Description: "A " + method + " request on " + path,
			Method:      strings.ToLower(method),
			Accept:      "json",
			Produce:     "json",
			Params:      []string{},
		}
		if len(route.Docs.Pattern) > 1 && route.Docs.Pattern[len(route.Docs.Pattern)-1] == '/' {
			route.Docs.Pattern = route.Docs.Pattern[:len(route.Docs.Pattern)-1]
		}
	}
	if method == "" {
		klog.Printf("rdmethod must not be empty\n")
		return nil
	}
	if method == "WS" {
		route.Clients = map[string]*ws.Conn{}
	}
	if len(path) < 1 || path[0] != '/' {
		path = "/" + path
	}

	if handler == nil && wshandler == nil {
		klog.Printf("rdhandle or wshandler must be set\n")
		return nil
	}

	if r.trees == nil {
		r.trees = make(map[string]*node)
	}

	root := r.trees[method]
	if root == nil {
		root = new(node)
		r.trees[method] = root
	}
	if strings.ContainsAny(path, ":*") {
		root.addRoute(path, handler, wshandler, allowed)
	} else {
		if v, ok := r.Routes.Get(path); ok {
			v = append(v, route)
			r.Routes.Set(path, v)
		} else {
			r.Routes.Set(path, []Route{route})
		}
	}

	if paramsCount := countParams(path); paramsCount+varsCount > r.maxParams {
		r.maxParams = paramsCount + varsCount
	}

	if r.paramsPool.New == nil && r.maxParams > 0 {
		r.paramsPool.New = func() interface{} {
			ps := make(Params, 0, r.maxParams)
			return &ps
		}
	}

	return &route
}

func GetParamsFromCtx(requestContext context.Context) Params {
	p, _ := requestContext.Value(ParamsKey).(Params)
	return p
}

func (r *Router) HandlerFunc(method, path string, handler http.Handler) *Route {
	return r.handle(method, path,
		func(c *Context) {
			handler.ServeHTTP(c.ResponseWriter, c.Request)
		},
		nil,
	)
}

func (handler Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := Context{
		ResponseWriter: w,
		Request:        r,
		status:         200,
		CtxParams:      GetParamsFromCtx(r.Context()),
	}
	handler(&ctx)
}

func (r *Router) GetParamsFromPath(method, path string) Params {
	if root := r.trees[strings.ToUpper(method)]; root != nil {
		if _, _, prms, _, _ := root.search(path, r.getPoolParams); prms != nil && len(*prms) > 0 {
			p := *prms
			r.putPoolParams(prms)
			return p
		}
	}
	return nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}
	path := req.URL.Path
	if len(path) > 1 && path[len(path)-1] != '/' {
		path += "/"
	}

	if req.Method == "GET" {
		if req.Header.Get("Upgrade") == "websocket" {
			if v, ok := r.Routes.Get(path); ok {
				for _, vv := range v {
					if vv.Method == "WS" && vv.WsHandler != nil {
						if vv.Origine != "" {
							w.Header().Set("Access-Control-Allow-Origin", vv.Origine)
						}
						accept := ws.FuncBeforeUpgradeWS(req)
						if !accept {
							w.Write([]byte("error: origin not allowed"))
							return
						}
						ws.FuncBeforeUpgradeWSHandler(w, req)
						conn, err := ws.DefaultUpgraderKMUX.Upgrade(w, req, nil)
						if klog.CheckError(err) {
							return
						}
						ctx := r.wscontextPool.Get().(*WsContext)
						ctx.Request = req
						if conn != nil {
							ctx.Ws = conn
							vv.WsHandler(ctx)
						}
						r.contextPool.Put(ctx)
						return
					}
				}
			}

			if root := r.trees["WS"]; root != nil {
				if _, wshandle, prms, origines, _ := root.search(path, r.getPoolParams); wshandle != nil {
					if len(origines) > 0 {
						w.Header().Set("Access-Control-Allow-Origin", origines[0])
					}
					accept := ws.FuncBeforeUpgradeWS(req)
					if !accept {
						w.Write([]byte("error: origin not allowed"))
						return
					}
					ws.FuncBeforeUpgradeWSHandler(w, req)
					conn, err := ws.DefaultUpgraderKMUX.Upgrade(w, req, nil)
					if klog.CheckError(err) {
						return
					}
					ctx := r.wscontextPool.Get().(*WsContext)
					ctx.Request = req
					if conn != nil {
						ctx.Ws = conn
						if prms != nil {
							ctx.CtxParams = *prms
							wshandle(ctx)
							r.putPoolParams(prms)
						} else {
							wshandle(ctx)
						}
					}
					if ctx != nil {
						r.wscontextPool.Put(ctx)
					}
					return
				}
			}
		}
	}

	if v, ok := r.Routes.Get(path); ok {
		for _, vv := range v {
			if vv.Method == req.Method && vv.Handler != nil {
				if vv.Origine != "" {
					w.Header().Set("Access-Control-Allow-Origin", vv.Origine)
				}
				ctx := r.contextPool.Get().(*Context)
				ctx.ResponseWriter = w
				ctx.Request = req
				vv.Handler(ctx)
				r.contextPool.Put(ctx)
				return
			}
		}
	}

	if root := r.trees[req.Method]; root != nil {
		if handle, _, ps, origines, tsr := root.search(path, r.getPoolParams); handle != nil {
			ctx := r.contextPool.Get().(*Context)
			ctx.ResponseWriter = w
			ctx.Request = req
			if ps != nil {
				ctx.CtxParams = *ps
				if len(origines) > 0 {
					w.Header().Set("Access-Control-Allow-Origin", origines[0])
				}
				handle(ctx)
				r.putPoolParams(ps)
			} else {
				if len(origines) > 0 {
					w.Header().Set("Access-Control-Allow-Origin", origines[0])
				}
				handle(ctx)
			}
			if ctx != nil {
				r.contextPool.Put(ctx)
			}
			return
		} else if req.Method != http.MethodConnect && path != "/" {
			code := http.StatusMovedPermanently
			if req.Method != "GET" {
				code = http.StatusPermanentRedirect
			}

			if tsr {
				if len(path) > 1 && path[len(path)-1] == '/' {
					req.URL.Path = path[:len(path)-1]
				} else {
					req.URL.Path = path + "/"
				}
				http.Redirect(w, req, req.URL.String(), code)
				return
			}

			// fix path
			fixedPath, found := root.findInsensitivePath(
				AdaptPath(path),
				true,
			)
			if found {
				req.URL.Path = fixedPath
				http.Redirect(w, req, req.URL.String(), code)
				return
			}
		}
	}

	if req.Method == http.MethodOptions {
		// OPTIONS request
		if allow := r.AllowedMethods(path, http.MethodOptions); allow != "" {
			w.Header().Set("Allow", allow)
			if r.GlobalOPTIONS != nil {
				ctx := r.contextPool.Get().(*Context)
				ctx.ResponseWriter = w
				ctx.Request = req
				ctx.CtxParams = Params{}
				r.GlobalOPTIONS(ctx)
				r.contextPool.Put(ctx)
			}
			return
		}
	} else if allow := r.AllowedMethods(path, req.Method); allow != "" {
		w.Header().Set("Allow", allow)
		if r.MethodNotAllowed != nil {
			ctx := r.contextPool.Get().(*Context)
			ctx.ResponseWriter = w
			ctx.Request = req
			ctx.CtxParams = Params{}
			r.MethodNotAllowed(ctx)
			r.contextPool.Put(ctx)
		} else {
			http.Error(w,
				methNothAllowed,
				http.StatusMethodNotAllowed,
			)
		}
		return
	}

	if r.NotFound != nil {
		ctx := r.contextPool.Get().(*Context)
		ctx.ResponseWriter = w
		ctx.Request = req
		ctx.CtxParams = Params{}
		r.NotFound(ctx)
		r.contextPool.Put(ctx)
	} else {
		http.NotFound(w, req)
	}
}

// Run HTTP server on address
func (router *Router) Run(addr string) {
	if ADDRESS != addr {
		sp := strings.Split(addr, ":")
		if len(sp) > 0 {
			if sp[0] != "" && sp[1] != "" {
				ADDRESS = addr
			} else {
				HOST = "localhost"
				PORT = sp[1]
				ADDRESS = HOST + addr
			}
		} else {
			fmt.Println("error: server address not valid")
			return
		}
	}

	router.initServer(ADDRESS)

	// Listen and serve
	go func() {
		if err := router.Server.ListenAndServe(); err != http.ErrServerClosed {
			klog.Printf("rdUnable to shutdown the server : %v\n", err)
			os.Exit(1)
		} else {
			klog.Printfs("grServer Off!\n")
		}
	}()

	if generateSwaggerJson {
		DocsGeneralDefaults.Host = ADDRESS
		router.Routes.Range(func(s string, routes []Route) {
			for _, route := range routes {
				if route.Method != "SSE" && route.Method != "WS" {
					for i, r := range routes {
						if r.Docs != nil && r.Docs.Triggered {
							docsPatterns = append(docsPatterns, &routes[i])
						}
					}
				}
			}
		})
		if generateGoComments {
			GenerateGoDocsComments()
		}
		GenerateJsonDocs()
		OnDocsGenerationReady()
	}
	klog.Printfs("mgrunning on http://%s\n", ADDRESS)
	// graceful Shutdown server
	router.gracefulShutdown()
}

// RunTLS HTTPS server using certificates
func (router *Router) RunTLS(addr, cert, certKey string) {
	if ADDRESS != addr {
		sp := strings.Split(addr, ":")
		if len(sp) > 0 {
			if sp[0] != "" && sp[1] != "" {
				ADDRESS = addr
			} else {
				HOST = "localhost"
				PORT = sp[1]
				ADDRESS = HOST + addr
			}
		} else {
			fmt.Println("error: server address not valid")
			return
		}
	}
	// graceful Shutdown server
	router.initServer(ADDRESS)

	go func() {
		klog.Printfs("mgrunning on https://%s\n", ADDRESS)
		if err := router.Server.ListenAndServeTLS(cert, certKey); err != http.ErrServerClosed {
			klog.Printf("rdUnable to shutdown the server : %v\n", err)
		} else {
			klog.Printfs("grServer Off!\n")
		}
	}()
	if generateSwaggerJson {
		DocsGeneralDefaults.Host = ADDRESS
		router.Routes.Range(func(s string, routes []Route) {
			for _, route := range routes {
				if route.Method != "SSE" && route.Method != "WS" {
					for i, r := range routes {
						if r.Docs != nil && r.Docs.Triggered {
							docsPatterns = append(docsPatterns, &routes[i])
						}
					}
				}
			}
		})
		if generateGoComments {
			GenerateGoDocsComments()
		}
		GenerateJsonDocs()
		OnDocsGenerationReady()
	}
	router.gracefulShutdown()
}

// RunAutoTLS HTTPS server generate certificates and handle renew
func (router *Router) RunAutoTLS(domainName string, subDomains ...string) {
	if DOMAIN != domainName {
		if strings.Contains(domainName, ":") {
			sp := strings.Split(domainName, ":")
			if sp[0] != "" {
				ADDRESS = domainName
				DOMAIN = sp[0]
				PORT = sp[1]
			} else {
				fmt.Println("error: server domainName not valid")
				return
			}
		} else {
			err := checkDomain(domainName)
			if err == nil {
				DOMAIN = domainName
				PORT = ":443"
				ADDRESS = domainName + PORT
			} else {
				fmt.Println("error: server domainName not valid")
				return
			}
		}
		DOMAIN = domainName
	}
	if len(SUBDOMAINS) != len(subDomains) {
		SUBDOMAINS = subDomains
	}
	// graceful Shutdown server

	router.createServerCerts(DOMAIN, SUBDOMAINS...)
	go func() {
		klog.Printfs("mgrunning on https://%s , subdomains: %v\n", DOMAIN, SUBDOMAINS)
		if err := router.Server.ListenAndServe(); err != http.ErrServerClosed {
			klog.Printf("rdUnable to shutdown the server : %v\n", err)
		} else {
			klog.Printf("grServer Off !\n")
		}
	}()
	if generateSwaggerJson {
		DocsGeneralDefaults.Host = ADDRESS
		router.Routes.Range(func(s string, routes []Route) {
			for _, route := range routes {
				if route.Method != "SSE" && route.Method != "WS" {
					for i, r := range routes {
						if r.Docs != nil && r.Docs.Triggered {
							docsPatterns = append(docsPatterns, &routes[i])
						}
					}
				}
			}
		})
		if generateGoComments {
			GenerateGoDocsComments()
		}
		GenerateJsonDocs()
		OnDocsGenerationReady()
	}
	router.gracefulShutdown()
}
