package kmux

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kamalshkeir/kencoding/json"
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
	Origine string
	Docs    *DocsRoute
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
	proxyFor         string
	middlewares      []func(http.Handler) http.Handler
}

type GroupRouter struct {
	*Router
	Group string
	midws []func(Handler) Handler
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

// Group create group path
func (router *Router) Group(prefix string) *GroupRouter {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return &GroupRouter{
		Router: router,
		Group:  prefix,
	}
}

// Use chain global router middlewares
func (router *Router) Use(midws ...func(http.Handler) http.Handler) {
	if len(router.middlewares) == 0 {
		router.middlewares = midws
	} else {
		router.middlewares = append(router.middlewares, midws...)
	}
}

// Use chain handler middlewares
func (gr *GroupRouter) Use(middlewares ...func(Handler) Handler) {
	gr.midws = middlewares
}

func (r *Router) Get(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodGet, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Get(pattern string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle("GET", gr.Group+pattern, h, nil, allowedOrigine...)
}

func (r *Router) Head(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodHead, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Head(path string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle(http.MethodHead, gr.Group+path, h, nil, allowedOrigine...)
}

func (r *Router) Options(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodOptions, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Options(path string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle(http.MethodOptions, gr.Group+path, h, nil, allowedOrigine...)
}

func (r *Router) Post(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodPost, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Post(path string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle(http.MethodPost, gr.Group+path, h, nil, allowedOrigine...)
}

func (r *Router) Put(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodPut, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Put(path string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle(http.MethodPut, gr.Group+path, h, nil, allowedOrigine...)
}

func (r *Router) Patch(path string, handler Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodPatch, path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Patch(path string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle(http.MethodPatch, gr.Group+path, h, nil, allowedOrigine...)
}

func (r *Router) Delete(path string, handle Handler, allowedOrigine ...string) *Route {
	return r.handle(http.MethodDelete, path, handle, nil, allowedOrigine...)
}

func (gr *GroupRouter) Delete(path string, handler Handler, allowedOrigine ...string) *Route {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	return gr.Router.handle(http.MethodDelete, gr.Group+path, h, nil, allowedOrigine...)
}

func (r *Router) Ws(path string, wshandle WsHandler, allowedOrigine ...string) *Route {
	return r.handle("WS", path, nil, wshandle, allowedOrigine...)
}

func (gr *GroupRouter) Ws(path string, wshandle WsHandler, allowedOrigine ...string) {
	gr.Router.handle("WS", gr.Group+path, nil, wshandle, allowedOrigine...)
}

func (r *Router) Sse(path string, handler Handler, allowedOrigine ...string) {
	r.handle("SSE", path, handler, nil, allowedOrigine...)
}

func (gr *GroupRouter) Sse(path string, handler Handler, allowedOrigine ...string) {
	var h Handler
	if len(gr.midws) > 0 {
		for i := range gr.midws {
			if i == 0 {
				h = gr.midws[0](handler)
			} else {
				h = gr.midws[i](h)
			}
		}
	} else {
		h = handler
	}
	gr.Router.handle("SSE", gr.Group+path, h, nil, allowedOrigine...)
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

// WithMetrics take prometheus handler and serve metrics on path or default /metrics
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
		for i := range allowed {
			if allowed[i] == "*" {
				route.Origine = allowed[i]
				break
			} else if !strings.Contains(allowed[i], ",") {
				allowed[i] = strings.Replace(allowed[i], "localhost", "127.0.0.1", -1)
				if !strings.HasPrefix(allowed[i], "http") {
					allowed[i] = "http://" + allowed[i]
				}
			}
		}
		route.Origine = strings.Join(allowed, ",")
	}
	if withDocs && !strings.Contains(path, "*") && method != "WS" && method != "SSE" {
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
	}
	if !strings.Contains(path, "*") {
		if strings.Contains(path, ":") {
			if withDocs {
				if v, ok := r.Routes.Get(path); ok {
					v = append(v, route)
					r.Routes.Set(path, v)
				} else {
					r.Routes.Set(path, []Route{route})
				}
			}
		} else {
			if v, ok := r.Routes.Get(path); ok {
				v = append(v, route)
				r.Routes.Set(path, v)
			} else {
				r.Routes.Set(path, []Route{route})
			}
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

// GetParamsFromCtx get a list of params from path, have 2 methods Get(param)
func GetParamsFromCtx(requestContext context.Context) Params {
	p, _ := requestContext.Value(ParamsKey).(Params)
	return p
}

// HandlerFunc adapter for kmux Handler
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

func jsonResponse(status int, w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	by, err := json.Marshal(data)
	if !klog.CheckError(err) {
		w.Write(by)
	}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}
	path := req.URL.Path
	if len(path) > 1 && path[len(path)-1] != '/' {
		path += "/"
	}

	if routes, ok := r.Routes.Get(path); ok {
		for _, vv := range routes {
			if req.Method == vv.Method && vv.Handler != nil {
				ctx := r.contextPool.Get().(*Context)
				ctx.ResponseWriter = w
				if corsEnabled && vv.Origine != "" && vv.Origine != "*" {
					reqOrigin := req.Header.Get("Origin")
					if !strings.Contains(vv.Origine, reqOrigin) {
						jsonResponse(http.StatusUnauthorized, w, map[string]any{
							"error": "Cross Origin Not Allowed",
						})
						return
					}
				}
				ctx.Request = req
				vv.Handler(ctx)
				r.contextPool.Put(ctx)
				return
			}
			if vv.Method == "WS" && vv.WsHandler != nil {
				if corsEnabled && vv.Origine != "" && vv.Origine != "*" {
					reqOrigin := req.Header.Get("Origin")
					if !strings.Contains(vv.Origine, reqOrigin) {
						jsonResponse(http.StatusUnauthorized, w, map[string]any{
							"error": "Cross Origin Not Allowed",
						})
						return
					}
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
				r.wscontextPool.Put(ctx)
				return
			}
			if vv.Method == "SSE" && vv.Handler != nil {
				if corsEnabled && vv.Origine != "" && vv.Origine != "*" {
					reqOrigin := req.Header.Get("Origin")
					if !strings.Contains(vv.Origine, reqOrigin) {
						jsonResponse(http.StatusUnauthorized, w, map[string]any{
							"error": "Cross Origin Not Allowed",
						})
						return
					}
				}
				controller := http.NewResponseController(w)
				controller.SetReadDeadline(time.Time{})
				controller.SetWriteDeadline(time.Time{})
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")
				ctx := r.contextPool.Get().(*Context)
				ctx.ResponseWriter = w
				ctx.Request = req
				vv.Handler(ctx)
				r.contextPool.Put(ctx)
				return
			}
		}
	}
	current := req.Method
	root := r.trees[req.Method]
	if root == nil {
		current = "WS"
		root = r.trees[current]
		if root == nil {
			current = "SSE"
			root = r.trees["SSE"]
		}
	}
	if root == nil {
		http.Error(w, "NOT FOUND", http.StatusNotFound)
		return
	}

	handle, wshandle, ps, origines, tsr := root.search(path, r.getPoolParams)
currentState:
	switch current {
	case req.Method:
		if handle != nil {
			ctx := r.contextPool.Get().(*Context)
			ctx.ResponseWriter = w
			ctx.Request = req
			if corsEnabled && len(origines) > 0 && origines[0] != "*" {
				reqOrigin := req.Header.Get("Origin")
				found := false
				for _, o := range origines {
					if o == reqOrigin {
						found = true
					}
				}
				if !found {
					jsonResponse(http.StatusUnauthorized, w, map[string]any{
						"error": "Cross Origin Not Allowed",
					})
					return
				}
			}
			if ps != nil {
				ctx.CtxParams = *ps
				handle(ctx)
				r.putPoolParams(ps)
			} else {
				handle(ctx)
			}
			if ctx != nil {
				r.contextPool.Put(ctx)
			}
			return
		} else {
			current = "WS"
			root = r.trees[current]
			if root == nil {
				current = "SSE"
				root = r.trees[current]
			}
			if root != nil {
				handle, wshandle, ps, origines, tsr = root.search(path, r.getPoolParams)
				goto currentState
			}
		}
	case "WS":
		if wshandle != nil {
			if corsEnabled && len(origines) > 0 && origines[0] != "*" {
				reqOrigin := req.Header.Get("Origin")
				found := false
				for _, o := range origines {
					if o == reqOrigin {
						found = true
					}
				}
				if !found {
					jsonResponse(http.StatusUnauthorized, w, map[string]any{
						"error": "Cross Origin Not Allowed",
					})
					return
				}
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
			ctx.Ws = conn
			ctx.Request = req

			if ps != nil {
				ctx.CtxParams = *ps
				wshandle(ctx)
				r.putPoolParams(ps)
			} else {
				wshandle(ctx)
			}
			if ctx != nil {
				r.wscontextPool.Put(ctx)
			}
			return
		} else {
			current = "SSE"
			root = r.trees[current]
			if root != nil {
				handle, wshandle, ps, origines, tsr = root.search(path, r.getPoolParams)
				goto currentState
			}
		}
	case "SSE":
		if handle != nil {
			controller := http.NewResponseController(w)
			controller.SetReadDeadline(time.Time{})
			controller.SetWriteDeadline(time.Time{})
			w.Header().Add("Content-Type", "text/event-stream")
			w.Header().Add("Cache-Control", "no-cache")
			w.Header().Add("Connection", "keep-alive")
			ctx := r.contextPool.Get().(*Context)
			ctx.ResponseWriter = w
			ctx.Request = req
			if corsEnabled && len(origines) > 0 && origines[0] != "*" {
				reqOrigin := req.Header.Get("Origin")
				found := false
				for _, o := range origines {
					if o == reqOrigin {
						found = true
					}
				}
				if !found {
					jsonResponse(http.StatusUnauthorized, w, map[string]any{
						"error": "Cross Origin Not Allowed",
					})
					return
				}
			}
			if ps != nil {
				ctx.CtxParams = *ps
				handle(ctx)
				r.putPoolParams(ps)
			} else {
				handle(ctx)
			}
			if ctx != nil {
				r.contextPool.Put(ctx)
			}
			return
		}
	}

	if req.Method != http.MethodConnect && path != "/" {
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
		if root != nil {
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
				port = ":" + PORT
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
			for i, route := range routes {
				if route.Docs != nil && route.Docs.Triggered && route.Method != "SSE" && route.Method != "WS" {
					docsPatterns = append(docsPatterns, &routes[i])
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
				port = ":" + PORT
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
			for i, route := range routes {
				if route.Docs != nil && route.Docs.Triggered && route.Method != "SSE" && route.Method != "WS" {
					docsPatterns = append(docsPatterns, &routes[i])
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
func (router *Router) RunAutoTLS(domainName string, subdomains ...string) {
	if !strings.Contains(domainName, ":") {
		err := checkDomain(domainName)
		if err == nil {
			DOMAIN = domainName
			ADDRESS = domainName
			PORT = "443"
			port = ":" + PORT
		}
	} else {
		sp := strings.Split(domainName, ":")
		if sp[0] != "" {
			DOMAIN = sp[0]
			PORT = sp[1]
			port = ":" + PORT
		}
	}
	if proxyUsed {
		if len(SUBDOMAINS) != proxies.Len() {
			SUBDOMAINS = proxies.Keys()
		}
	}

	for _, d := range subdomains {
		found := false
		for _, dd := range SUBDOMAINS {
			if dd == d {
				found = true
			}
		}
		if !found {
			SUBDOMAINS = append(SUBDOMAINS, d)
		}
	}

	// graceful Shutdown server
	certManager, tlsconf := router.createServerCerts(DOMAIN, SUBDOMAINS...)
	if certManager == nil || tlsconf == nil {
		klog.Printf("rdunable to create tls config\n")
		os.Exit(1)
		return
	}
	router.initAutoServer(tlsconf)
	go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
	go func() {
		klog.Printfs("mgrunning on https://%s , subdomains: %v\n", router.Server.Addr, SUBDOMAINS)
		if err := router.Server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			klog.Printf("rdUnable to run the server : %v\n", err)
		} else {
			klog.Printf("grServer Off !\n")
		}
	}()
	if generateSwaggerJson {
		DocsGeneralDefaults.Host = DOMAIN
		router.Routes.Range(func(s string, routes []Route) {
			for i, route := range routes {
				if route.Docs != nil && route.Docs.Triggered && route.Method != "SSE" && route.Method != "WS" {
					docsPatterns = append(docsPatterns, &routes[i])
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
