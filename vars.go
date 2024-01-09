package kmux

import (
	"context"
	"embed"
	"net/http"
	"text/template"
	"time"

	"github.com/kamalshkeir/kmap"
)

var (
	MEDIA_DIR       = "media"
	HOST            = ""
	PORT            = ""
	IsTLS           = false
	ADDRESS         = ""
	DOMAIN          = ""
	SUBDOMAINS      = []string{}
	Templates       embed.FS
	Static          embed.FS
	TemplateEmbeded = false
	StaticEmbeded   = false
	methNothAllowed = http.StatusText(http.StatusMethodNotAllowed)
	// server
	ReadTimeout          = 5 * time.Second
	WriteTimeout         = 20 * time.Second
	IdleTimeout          = 20 * time.Second
	FuncOnServerShutdown = func(srv *http.Server) error {
		return nil
	}
	// context
	MultipartSize          = 10 << 20
	beforeRenderHtml       = kmap.New[string, func(reqCtx context.Context, data *map[string]any)](false)
	rawTemplates           = kmap.New[string, *template.Template](false)
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
	COOKIES_SECURE   = true
)
