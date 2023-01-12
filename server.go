package kmux

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kamalshkeir/kmux/ws"

	"github.com/kamalshkeir/klog"
	"golang.org/x/crypto/acme/autocert"
)

var (
	CORSDebug        = false
	ReadTimeout      = 5 * time.Second
	WriteTimeout     = 20 * time.Second
	IdleTimeout      = 20 * time.Second
	midwrs           []func(http.Handler) http.Handler
	FuncCorsSameSite = func(c *Context, rt Route) bool {
		return true
	}
	FuncOnServerShutdown = func(srv *http.Server) error {
		return nil
	}
)

// Use chain global middlewares applied on the router
func (router *Router) Use(midws ...func(http.Handler) http.Handler) {
	midwrs = append(midwrs, midws...)
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
		} else {
			klog.Printfs("grServer Off!\n")
		}
	}()

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
		if err := router.Server.ListenAndServeTLS(cert, certKey); err != http.ErrServerClosed {
			klog.Printf("rdUnable to shutdown the server : %v\n", err)
		} else {
			klog.Printfs("grServer Off!\n")
		}
	}()

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
		if err := router.Server.ListenAndServe(); err != http.ErrServerClosed {
			klog.Printf("rdUnable to shutdown the server : %v\n", err)
		} else {
			klog.Printf("grServer Off !\n")
		}
	}()

	router.gracefulShutdown()
}

// ServeHTTP serveHTTP by handling methods,pattern,and params
func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const key ContextKey = "params"
	c := &Context{Request: r, ResponseWriter: w, CtxParamsMap: map[string]string{}}
	var allRoutes []Route
	switch r.Method {
	case "GET":
		if r.Header.Get("Upgrade") == "websocket" {
			allRoutes = router.Routes[WS]
		} else if strings.Contains(r.URL.Path, "/sse/") {
			allRoutes = router.Routes[SSE]
		} else {
			allRoutes = router.Routes[GET]
		}
	case "POST":
		allRoutes = router.Routes[POST]
	case "PUT":
		allRoutes = router.Routes[PUT]
	case "PATCH":
		allRoutes = router.Routes[PATCH]
	case "DELETE":
		allRoutes = router.Routes[DELETE]
	case "HEAD":
		allRoutes = router.Routes[HEAD]
	case "OPTIONS":
		allRoutes = router.Routes[OPTIONS]
	default:
		c.Status(http.StatusBadRequest).Text("Method Not Allowed")
		return
	}

	if len(allRoutes) > 0 {
		for _, rt := range allRoutes {
			// match route
			if matches := rt.Pattern.FindStringSubmatch(c.URL.Path); len(matches) > 0 {
				// add params
				paramsValues := matches[1:]
				if names := rt.Pattern.SubexpNames(); len(names) > 0 {
					for i, name := range rt.Pattern.SubexpNames()[1:] {
						if name != "" {
							c.CtxParamsMap[name] = paramsValues[i]
						}
					}
					ctx := context.WithValue(c.Request.Context(), key, c.CtxParamsMap)
					c.Request = r.WithContext(ctx)
				}
				if rt.WsHandler != nil {
					// WS
					rt.Method = r.Method
					handleWebsockets(c, rt)
					return
				} else {
					// HTTP
					rt.Method = r.Method
					handleHttp(c, rt)
					return
				}
			}
		}
	}
	router.DefaultRoute(c)
}

func handleWebsockets(c *Context, rt Route) {
	accept := ws.FuncBeforeUpgradeWS(c.Request)
	if !accept {
		c.Status(http.StatusMethodNotAllowed).Json(map[string]any{
			"error": "origin not allowed",
		})
		return
	}
	ws.FuncBeforeUpgradeWSHandler(c.ResponseWriter, c.Request)
	conn, err := ws.DefaultUpgraderKMUX.Upgrade(c.ResponseWriter, c.Request, nil)
	if klog.CheckError(err) {
		return
	}
	if conn != nil {
		ctx := &WsContext{
			Ws:      conn,
			Params:  make(map[string]string),
			Route:   rt,
			Request: c.Request,
		}
		rt.WsHandler(ctx)
		return
	}
}

func handleHttp(c *Context, rt Route) {
	switch rt.Method {
	case "GET":
		if rt.Method == "SSE" {
			sseHeaders(c)
		}
		rt.Handler(c)
		return
	case "SSE":
		sseHeaders(c)
		rt.Handler(c)
		return
	case "HEAD", "OPTIONS":
		rt.Handler(c)
		return
	default:
		// check cross origin
		if checkSameSite(*c) || FuncCorsSameSite(c, rt) {
			// same site
			rt.Handler(c)
			return
		} else {
			// cross origin
			if len(rt.AllowedOrigines) == 0 {
				c.Status(http.StatusBadRequest).Text("cross origin not allowed")
				return
			} else {
				if rt.AllowedOrigines[0] == "*" {
					rt.Handler(c)
					return
				}

				allowed := false
				for _, dom := range rt.AllowedOrigines {
					if strings.Contains(c.Request.Header.Get("Origin"), dom) {
						allowed = true
					}
				}
				if allowed {
					rt.Handler(c)
					return
				} else {
					c.Status(http.StatusBadRequest).Text("you are not allowed cross origin this url")
					return
				}
			}
		}
	}
}

// initServer init the server with midws without tlsConfig
func (router *Router) initServer(addr string) {
	if addr != ADDRESS {
		ADDRESS = addr
	}
	var handler http.Handler
	if len(midwrs) != 0 {
		handler = midwrs[0](router)
		for i := 1; i < len(midwrs); i++ {
			handler = midwrs[i](handler)
		}
	} else {
		handler = router
	}
	server := http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}
	router.Server = &server
}

// initAutoServer init the server with midws with tlsConfig
func (router *Router) initAutoServer(addr string, tlsconf *tls.Config) {
	var handler http.Handler
	if len(midwrs) != 0 {
		handler = midwrs[0](router)
		for i := 1; i < len(midwrs); i++ {
			handler = midwrs[i](handler)
		}
	} else {
		handler = router
	}
	// Setup Server
	server := http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
		TLSConfig:    tlsconf,
	}
	router.Server = &server
}

// Graceful Shutdown
func (router *Router) gracefulShutdown() {
	err := onShutdown(func() error {
		// Shutdown server
		err := router.Server.Shutdown(context.Background())
		if klog.CheckError(err) {
			return err
		}
		err = FuncOnServerShutdown(router.Server)
		if klog.CheckError(err) {
			return err
		}
		return nil
	})
	if klog.CheckError(err) {
		os.Exit(1)
	}
}

// will run after shutting down the server
func (router *Router) OnShutdown(fn func(srv *http.Server) error) {
	FuncOnServerShutdown = fn
}

func (router *Router) createServerCerts(domainName string, subDomains ...string) {
	uniqueDomains := []string{}
	domainsToCertify := map[string]bool{}
	// add domainName
	err := checkDomain(domainName)
	if err == nil {
		if !strings.Contains(domainName, ":") {
			domainName += ":443"
		}
		domainsToCertify[domainName] = true
	}
	// add pIP
	pIP := GetPrivateIp()
	if _, ok := domainsToCertify[pIP]; !ok {
		domainsToCertify[pIP] = true
	}
	// add subdomains
	for _, sub := range subDomains {
		if _, ok := domainsToCertify[sub]; !ok {
			domainsToCertify[sub] = true
		}
	}
	for k := range domainsToCertify {
		uniqueDomains = append(uniqueDomains, k)
	}

	if len(uniqueDomains) > 0 {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("certs"),
			HostPolicy: autocert.HostWhitelist(uniqueDomains...),
		}
		tlsConfig := m.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
		router.initAutoServer(router.Server.Addr, tlsConfig)
		klog.Printfs("grAuto certified domains: %v", uniqueDomains)
	}
}

func checkDomain(name string) error {
	switch {
	case len(name) == 0:
		return nil
	case len(name) > 255:
		return fmt.Errorf("cookie domain: name length is %d, can't exceed 255", len(name))
	}
	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			switch {
			case i == l:
				return fmt.Errorf("cookie domain: invalid character '%c' at offset %d: label can't begin with a period", b, i)
			case i-l > 63:
				return fmt.Errorf("cookie domain: byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("cookie domain: label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("cookie domain: label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
			// show the printable unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("cookie domain: invalid rune at offset %d", i)
			}
			return fmt.Errorf("cookie domain: invalid character '%c' at offset %d", c, i)
		}
	}
	switch {
	case l == len(name):
		return fmt.Errorf("cookie domain: missing top level domain, domain can't end with a period")
	case len(name)-l > 63:
		return fmt.Errorf("cookie domain: byte length of top level domain '%s' is %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d begins with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("cookie domain: top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}
	return nil
}

func GetParam(r *http.Request) (map[string]string, bool) {
	const key ContextKey = "params"
	params, ok := r.Context().Value(key).(map[string]string)
	if ok {
		return params, true
	}
	return nil, false
}

func adaptParams(url string) string {
	if strings.Contains(url, ":") {
		urlElements := strings.Split(url, "/")
		urlElements = urlElements[1:]
		for i, elem := range urlElements {
			// named types
			if elem[0] == ':' {
				urlElements[i] = `(?P<` + elem[1:] + `>\w+)`
			} else if strings.Contains(elem, ":") {
				nameType := strings.Split(elem, ":")
				name := nameType[0]
				name_type := nameType[1]
				switch name_type {
				case "str":
					//urlElements[i] = `(?P<` + name + `>\w+)+\/?`
					urlElements[i] = `(?P<` + name + `>\w+)`
				case "int":
					urlElements[i] = `(?P<` + name + `>\d+)`
				case "slug":
					urlElements[i] = `(?P<` + name + `>[a-z0-9]+(?:-[a-z0-9]+)*)`
				case "float":
					urlElements[i] = `(?P<` + name + `>[-+]?([0-9]*\.[0-9]+|[0-9]+))`
				default:
					urlElements[i] = `(?P<` + name + `>[a-z0-9]+(?:-[a-z0-9]+)*)`
				}
			}
		}
		join := strings.Join(urlElements, "/")
		if !strings.HasSuffix(join, "*") {
			join += "(|/)?$"
		}
		return "^/" + join
	}

	if url[len(url)-1] == '*' {
		return url
	} else {
		if strings.HasSuffix(url, "/") {
			return "^" + url[:len(url)-1] + "(|/)?$"
		}
		return "^" + url + "(|/)?$"
	}
}

func checkSameSite(c Context) bool {
	privateIp := ""
	origin := c.Request.Header.Get("Origin")
	if CORSDebug {
		klog.Printfs("ORIGIN:%s\n", origin)
		klog.Printfs("ADDRESS:%s\n", ADDRESS)
		klog.Printfs("DOMAINS:%s %v\n", DOMAIN, SUBDOMAINS)
	}
	if origin == "" {
		return false
	}

	if len(origineslist) > 0 {
		for _, o := range origineslist {
			if strings.Contains(origin, o) || o == "*" {
				return true
			}
		}
	}

	privateIp = GetPrivateIp()
	if StringContains(c.Request.RemoteAddr, ADDRESS, "localhost", "127.0.0.1", privateIp) {
		return true
	}

	if CORSDebug {
		klog.Printfs("ORIGIN of remote %s is : %s\n", c.Request.RemoteAddr, origin)
		klog.Printfs("ADDRESS:%s\n", ADDRESS)
		klog.Printfs("DOMAINS:%s %v\n", DOMAIN, SUBDOMAINS)
	}

	for _, s := range SUBDOMAINS {
		if strings.Contains(origin, s) || strings.Contains(s, origin) {
			return true
		}
	}

	foundInPrivateIps := false
	if strings.Contains(origin, ADDRESS) {
		foundInPrivateIps = true
	} else if strings.Contains(origin, privateIp) {
		foundInPrivateIps = true
	} else {
		klog.Printf("origin: %s not equal to privateIp: %s\n", origin, privateIp)
	}

	sp := strings.Split(ADDRESS, ".")
	if strings.Contains(origin, ADDRESS) || foundInPrivateIps || (len(sp) < 4 && !StringContains(ADDRESS, "localhost", "127.0.0.1")) {
		return true
	} else {
		return false
	}
}

func sseHeaders(c *Context) {
	o := strings.Join(origineslist, ",")
	c.SetHeader("Access-Control-Allow-Origin", o)
	c.SetHeader("Access-Control-Allow-Headers", "Content-Type")
	c.SetHeader("Cache-Control", "no-cache")
	c.SetHeader("Connection", "keep-alive")
}
