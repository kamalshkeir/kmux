package kmux

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/kamalshkeir/klog"
	"github.com/kamalshkeir/kmap"
)

var (
	proxyUsed bool
	proxies   = kmap.New[string, http.Handler](false)
	port      = ""
)

func proxyHandler(req *http.Request, resp http.ResponseWriter, proxy *httputil.ReverseProxy, url *url.URL, reverseProxyRoutePrefix string) {
	req.Host = url.Host
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	//path := req.URL.Path
	//req.URL.Path = strings.TrimLeft(path, reverseProxyRoutePrefix)
	proxy.ServeHTTP(resp, req)
}

func proxyMid(router *Router, proxy *httputil.ReverseProxy, url *url.URL, reverseProxyRoutePrefix string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.TrimSuffix(r.Host, port)
			if v, ok := proxies.Get(host); ok {
				if vv, ok := v.(*Router); ok {
					for _, mid := range vv.middlewares {
						mid(v).ServeHTTP(w, r)
					}
				}
				v.ServeHTTP(w, r)
			} else {
				h.ServeHTTP(w, r)
			}
		})
	}
}

func (router *Router) ReverseProxy(host, toURL string) (newRouter *Router) {
	urll, err := url.Parse(toURL)
	if klog.CheckError(err) {
		return
	}
	if strings.Contains(host, "*") {
		klog.Printf("rd%s contain wildcard symbol '*', not allowed\n")
		return
	}
	if in := strings.Index(host, ":"); in > -1 {
		klog.Printf("ylPort is ignored in Host, you can remove '%s'\n", host[in:])
		host = host[:in]
	}
	router.proxyFor = host
	proxy := httputil.NewSingleHostReverseProxy(urll)
	if !proxyUsed {
		proxyUsed = true
		if len(router.middlewares) > 0 {
			router.middlewares = append([]func(http.Handler) http.Handler{proxyMid(router, proxy, urll, host)}, router.middlewares...)
		} else {
			router.middlewares = append(router.middlewares, proxyMid(router, proxy, urll, host))
		}
	}
	newRouter = New()
	_ = proxies.Set(host, newRouter)

	newRouter.Get("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	newRouter.Post("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	newRouter.Patch("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	newRouter.Put("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	newRouter.Delete("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	newRouter.Options("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	newRouter.Head("/*anyrp", func(c *Context) {
		proxyHandler(c.Request, c.ResponseWriter, proxy, urll, host)
	})
	return newRouter
}
