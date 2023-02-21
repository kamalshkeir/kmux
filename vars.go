package kmux

import (
	"context"
	"embed"
	"net/http"
	"time"
)

var (
	MEDIA_DIR       = "media"
	HOST            = ""
	PORT            = ""
	ADDRESS         = "localhost:9313"
	DOMAIN          = ""
	SUBDOMAINS      = []string{}
	Templates       embed.FS
	Static          embed.FS
	TemplateEmbeded = false
	StaticEmbeded   = false
	midwrs          = []func(http.Handler) http.Handler{}
	methNothAllowed = http.StatusText(http.StatusMethodNotAllowed)
	// server
	ReadTimeout      = 5 * time.Second
	WriteTimeout     = 20 * time.Second
	IdleTimeout      = 20 * time.Second
	FuncCorsSameSite = func(c *Context, rt *Route) bool {
		return true
	}
	FuncOnServerShutdown = func(srv *http.Server) error {
		return nil
	}
	// context
	MultipartSize          = 10 << 20
	beforeRenderHtml       = map[string]func(reqCtx context.Context, data *map[string]any){}
	beforeRenderHtmlSetted = false
	// docs
	DocsOutJson           = "."
	DocsEntryFile         = "kmuxdocs/kmuxdocs.go"
	OnDocsGenerationReady = func() {}
	withDocs              = false
	swagFound             = false
	generateSwaggerJson   = false
	generateGoComments    = true
	docsPatterns          = []*Route{}
	// ctx cookies
	COOKIES_Expires  = 24 * 7 * time.Hour
	COOKIES_SameSite = http.SameSiteStrictMode
	COOKIES_HttpOnly = true
	COOKIES_Secure   = false
)
