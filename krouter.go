package kmux

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"

	"github.com/kamalshkeir/kmux/ws"

	"github.com/kamalshkeir/klog"
)

type Handler func(c *Context)
type WsHandler func(c *WsContext)

type Route struct {
	Method  string
	Pattern string
	Handler
	WsHandler
	Clients map[string]*ws.Conn
	Docs    *DocsRoute
}

type Router struct {
	Server                 *http.Server
	NotFound               Handler
	GlobalOPTIONS          Handler
	MethodNotAllowed       Handler
	allRoutes              map[string][]Route
	contextPool            sync.Pool
	paramsPool             sync.Pool
	maxParams              uint16
	HandleMethodNotAllowed bool
	HandleOPTIONS          bool
	globalAllowed          string
	RedirectTrailingSlash  bool
	trees                  map[string]*node
	RedirectFixedPath      bool
	PanicHandler           func(http.ResponseWriter, *http.Request, interface{})
}

type GroupRouter struct {
	*Router
	Group string
}

// New returns a new initialized Router.
// Path auto-correction, including trailing slashes, is enabled by default.
func New() *Router {
	return &Router{
		RedirectTrailingSlash:  true,
		RedirectFixedPath:      true,
		HandleMethodNotAllowed: true,
		HandleOPTIONS:          true,
		allRoutes:              map[string][]Route{},
	}
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

// GET is a shortcut for router.Handle(http.MethodGet, path, handle)
func (r *Router) GET(path string, handler Handler) *Route {
	return r.handle(http.MethodGet, path, handler, nil)
}

func (gr *GroupRouter) GET(pattern string, handler Handler) *Route {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	return gr.Router.handle("GET", gr.Group+pattern, handler, nil)
}

// HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
func (r *Router) HEAD(path string, handler Handler) *Route {
	return r.handle(http.MethodHead, path, handler, nil)
}

func (gr *GroupRouter) HEAD(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodHead, gr.Group+path, handler, nil)
}

// OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
func (r *Router) OPTIONS(path string, handler Handler) *Route {
	return r.handle(http.MethodOptions, path, handler, nil)
}

func (gr *GroupRouter) OPTIONS(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodOptions, gr.Group+path, handler, nil)
}

// POST is a shortcut for router.Handle(http.MethodPost, path, handle)
func (r *Router) POST(path string, handler Handler) *Route {
	return r.handle(http.MethodPost, path, handler, nil)
}

func (gr *GroupRouter) POST(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodPost, gr.Group+path, handler, nil)
}

// PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
func (r *Router) PUT(path string, handler Handler) *Route {
	return r.handle(http.MethodPut, path, handler, nil)
}

func (gr *GroupRouter) PUT(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodPut, gr.Group+path, handler, nil)
}

// PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
func (r *Router) PATCH(path string, handler Handler) *Route {
	return r.handle(http.MethodPatch, path, handler, nil)
}

func (gr *GroupRouter) PATCH(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodPatch, gr.Group+path, handler, nil)
}

// DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
func (r *Router) DELETE(path string, handle Handler) *Route {
	return r.handle(http.MethodDelete, path, handle, nil)
}

func (gr *GroupRouter) DELETE(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle(http.MethodDelete, gr.Group+path, handler, nil)
}

func (r *Router) WS(path string, wshandle WsHandler) *Route {
	return r.handle("WS", path, nil, wshandle)
}

func (gr *GroupRouter) WS(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.handle("WS", gr.Group+path, handler, nil)
}

func (r *Router) SSE(path string, handler Handler) *Route {
	return r.GET(path, func(c *Context) {
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
		c.SetHeader("Content-Type", "text/event-stream")
		c.SetHeader("Cache-Control", "no-cache")
		c.SetHeader("Connection", "keep-alive")
		handler(c)
	})

}

func (gr *GroupRouter) SSE(path string, handler Handler) *Route {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return gr.Router.GET(gr.Group+path, func(c *Context) {
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
		c.SetHeader("Content-Type", "text/event-stream")
		c.SetHeader("Cache-Control", "no-cache")
		c.SetHeader("Connection", "keep-alive")
		handler(c)
	})
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

func (router *Router) WithMetrics(httpHandler http.Handler, path ...string) {
	if len(path) > 0 && strings.Contains(path[0], "/") {
		path[0] = strings.TrimPrefix(path[0], "/")
	} else {
		path = append(path, "metrics")
	}

	router.GET("/"+path[0], func(c *Context) {
		httpHandler.ServeHTTP(c.ResponseWriter, c.Request)
	})
}

func (r *Router) handle(method, path string, handler Handler, wshandler WsHandler) *Route {
	varsCount := uint16(0)
	route := Route{}
	route.Method = method
	route.Pattern = path
	route.Handler = handler
	route.WsHandler = wshandler
	route.Clients = nil
	if withDocs {
		route.Docs = &DocsRoute{
			Pattern:     path,
			Summary:     "A " + method + " request on " + path,
			Description: "A " + method + " request on " + path,
			Method:      strings.ToLower(method),
			Accept:      "json",
			Produce:     "json",
			Params:      []string{},
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

		r.globalAllowed = r.AllowedMethods("*", "")
	}
	root.addRoute(path, handler, wshandler)
	if _, ok := r.allRoutes[method]; ok {
		r.allRoutes[method] = append(r.allRoutes[method], route)
	} else {
		r.allRoutes[method] = []Route{route}
	}
	// Update maxParams
	if paramsCount := countParams(path); paramsCount+varsCount > r.maxParams {
		r.maxParams = paramsCount + varsCount
	}

	// Lazy-init paramsPool alloc func
	if r.paramsPool.New == nil && r.maxParams > 0 {
		r.paramsPool.New = func() interface{} {
			ps := make(Params, 0, r.maxParams)
			return &ps
		}
	}

	if r.contextPool.New == nil {
		r.contextPool.New = func() interface{} {
			return &Context{
				status:    200,
				CtxParams: Params{},
			}
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

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}
	path := req.URL.Path
	if root := r.trees["WS"]; root != nil && req.Method == "GET" {
		if req.Header.Get("Upgrade") == "websocket" {
			if _, wshandle, prms, _ := root.search(path, r.getPoolParams); wshandle != nil {
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
				if conn != nil {
					var ctxParams Params
					if prms != nil {
						ctxParams = *prms
					}
					ctx := &WsContext{
						Router:    r,
						Ws:        conn,
						CtxParams: ctxParams,
						Route:     &Route{Method: req.Method, Pattern: path, WsHandler: root.wshandler, Clients: make(map[string]*ws.Conn)},
						Request:   req,
					}
					wshandle(ctx)
					return
				}
			}
		}
	}

	if root := r.trees[req.Method]; root != nil {
		if handle, _, ps, tsr := root.search(path, r.getPoolParams); handle != nil {
			ctx := r.contextPool.Get().(*Context)
			ctx.Router = r
			ctx.ResponseWriter = w
			ctx.Request = req

			if handle != nil {
				if ps != nil {
					ctx.CtxParams = *ps
					handle(ctx)
					r.putPoolParams(ps)
				} else {
					handle(ctx)
				}
				r.contextPool.Put(ctx)
				return
			}
		} else if req.Method != http.MethodConnect && path != "/" {
			code := http.StatusMovedPermanently
			if req.Method != "GET" {
				code = http.StatusPermanentRedirect
			}

			if tsr && r.RedirectTrailingSlash {
				if len(path) > 1 && path[len(path)-1] == '/' {
					req.URL.Path = path[:len(path)-1]
				} else {
					req.URL.Path = path + "/"
				}
				http.Redirect(w, req, req.URL.String(), code)
				return
			}

			// fix path
			if r.RedirectFixedPath {
				fixedPath, found := root.findInsensitivePath(
					AdaptPath(path),
					r.RedirectTrailingSlash,
				)
				if found {
					req.URL.Path = fixedPath
					http.Redirect(w, req, req.URL.String(), code)
					return
				}
			}
		}
	}

	if req.Method == http.MethodOptions && r.HandleOPTIONS {
		// OPTIONS request
		if allow := r.AllowedMethods(path, http.MethodOptions); allow != "" {
			w.Header().Set("Allow", allow)
			if r.GlobalOPTIONS != nil {
				ctx := r.contextPool.Get().(*Context)
				ctx.Router = r
				ctx.ResponseWriter = w
				ctx.Request = req
				ctx.CtxParams = Params{}
				r.GlobalOPTIONS(ctx)
				r.contextPool.Put(ctx)
			}
			return
		}
	} else if r.HandleMethodNotAllowed {
		if allow := r.AllowedMethods(path, req.Method); allow != "" {
			w.Header().Set("Allow", allow)
			if r.MethodNotAllowed != nil {
				ctx := r.contextPool.Get().(*Context)
				ctx.Router = r
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
	}

	if r.NotFound != nil {
		ctx := r.contextPool.Get().(*Context)
		ctx.Router = r
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
		for method, routes := range router.allRoutes {
			if method != "SSE" && method != "WS" {
				for i, r := range routes {
					if r.Docs != nil && r.Docs.Triggered {
						docsPatterns = append(docsPatterns, &routes[i])
					}
				}
			}
		}
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
		for method, routes := range router.allRoutes {
			if method != "SSE" && method != "WS" {
				for _, r := range routes {
					if r.Docs != nil && r.Docs.Triggered {
						docsPatterns = append(docsPatterns, &r)
					}
				}
			}
		}
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
		for method, routes := range router.allRoutes {
			if method != "SSE" && method != "WS" {
				for _, r := range routes {
					if r.Docs != nil && r.Docs.Triggered {
						docsPatterns = append(docsPatterns, &r)
					}
				}
			}
		}
		if generateGoComments {
			GenerateGoDocsComments()
		}
		GenerateJsonDocs()
		OnDocsGenerationReady()
	}
	router.gracefulShutdown()
}
