# Kmux minimalistic radix router, very fast and efficient, without path conflicts multiple params

# Install
```sh
go get -u github.com/kamalshkeir/kmux@v1.11.7
```

```go
package main

import (
	"github.com/kamalshkeir/klog"
	"github.com/kamalshkeir/kmux"
)

func main() {
	app := kmux.New().WithDocs(true) // enable /docs 

    // use global middlewares
    app.Use(kmux.Gzip(),kmux.Cors("*"),kmux.Recovery(),kmux.Limiter(),kmux.Logs())

    // Group
    anyGroup := app.Group("/any") // or grp := app.Group("any")

  
    anyGroup.Get("/api/:table", func(c *kmux.Context) {
		c.Text("ok "+c.Param("table"))
	})

	// wild card param
    app.Get("/test/*param", func(c *kmux.Context) {
		c.Text(c.Param("param"))
	})

    app.Get("/",kmux.BasicAuth(IndexHandler,"username","password"))
	app.Post("/somePost", posting , "localhost:3333") // allow cors only for this handler http://127.0.0.1:3333 if global not set
	app.Put("/somePut", putting)
	app.Patch("/somePatch", patching)
	app.Delete("/someDelete", deleting)
	app.Head("/someDelete", head)
	app.Options("/someDelete", options)

    // Websockets
    app.Ws("/ws/test",func(c *kmux.WsContext) {
		rand := utils.GenerateRandomString(5)
		c.AddClient(rand) // add connection to broadcast list

		// listen for messages coming from 1 user
		for {
			// receive Json
			mapStringAny,err := c.ReceiveJson()
			if err != nil {
				// on error you can remove client from broadcastList and break the loop
				c.RemoveRequester(rand)
				break
			}

			// send Json to current user
			err = c.Json(map[string]any{
				"Hello":"World",
			})

			// send Text to current user
			err = c.Text("any data string")

			// broadcast to all connected users
			c.Broadcast(map[string]any{
				"you can send":"struct insetead of maps here",
			})

			// broadcast to all connected users except current user, the one who send the last message
			c.BroadcastExceptCaller(map[string]any{
				"you can send":"struct insetead of maps here",
			})

		}
	})

    // Server Sent Events
    app.Sse("/sse/logs", func(c *kmux.Context) {
		for i := 0; i < 10;i++ {
			c.Stream("working..."+strconv.Itoa(i))
			time.Sleep(time.Second)
		}
	})

	app.Run("localhost:9313")
}
```

```go
// BeforeRenderHtml executed before every html c.Html, you can use c.Request.Context().Value(key).(type.User) for example and add data to templates globaly
func BeforeRenderHtml(uniqueName string, fn func(reqCtx context.Context, data *map[string]any))
```


## Context

```go
func (c *Context) Status(code int) *Context
func (c *Context) ParamsMap() map[string]string
func (c *Context) Param(paramName string) string
func (c *Context) AddHeader(key, value string)
func (c *Context) SetHeader(key, value string)
func (c *Context) SetStatus(statusCode int)
func (c *Context) QueryParam(name string) string
func (c *Context) Json(data any)
func (c *Context) JsonIndent(data any)
func (c *Context) ContextValue(key ...ContextKey) (any, bool)
func (c *Context) Text(body string)
func (c *Context) TextHtml(body string)
func (c *Context) Html(template_name string, data map[string]any) // it add .Request in all templates
func (c *Context) Stream(response string) // SSE
// BodyJson get json body from request and return map
// USAGE : data := c.BodyJson(r)
func (c *Context) BodyJson() map[string]any
func (c *Context) BodyText() string
// Redirect redirect the client to the specified path with a custom code
func (c *Context) Redirect(path string)
// ServeFile serve a file from handler
func (c *Context) ServeFile(content_type, path_to_file string)
// ServeEmbededFile serve an embeded file from handler
func (c *Context) ServeEmbededFile(content_type string, embed_file []byte)
func (c *Context) ParseMultipartForm(size ...int64) (formData url.Values, formFiles map[string][]*multipart.FileHeader)
// UploadFile upload received_filename into folder_out and return url,fileByte,error
func (*Context) SaveFile(fileheader *multipart.FileHeader, path string) error
func (c *Context) UploadFile(received_filename, folder_out string, acceptedFormats ...string) (string, []byte, error)
func (c *Context) UploadFiles(received_filenames []string, folder_out string, acceptedFormats ...string) ([]string, [][]byte, error)
// DELETE FILE
func (c *Context) DeleteFile(path string) error
// Download download data_bytes(content) asFilename(test.json,data.csv,...) to the client
func (c *Context) Download(data_bytes []byte, asFilename string)
func (c *Context) GetUserIP() string

```


### Cookies
```go
func (c *Context) SetCookie(key, value string)
func (c *Context) GetCookie(key string) (string, error)
func (c *Context) DeleteCookie(key string)
```

### Templates and statics

```go
func (r *Router) Embed(staticDir *embed.FS, templateDir *embed.FS)
func (router *Router) NewFuncMap(funcName string, function any)
func (router *Router) LocalStatics(dirPath, webPath string)
func (router *Router) EmbededStatics(embeded embed.FS, pathLocalDir, webPath string)
func (router *Router) LocalTemplates(pathToDir string) error
func (router *Router) EmbededTemplates(template_embed embed.FS, rootDir string) error
```

### SSE
```go
package main

import (
	"fmt"
	"net/http"

	"github.com/kamalshkeir/kmux"
)

func main() {
	app := kmux.New()
	app.Get("/", func(c *kmux.Context) {
		c.Html("index.html", nil)
	})
	app.LocalTemplates("temps")

	msgChan := make(chan string)
	app.Sse("/test/:param", func(c *kmux.Context) {
		fmt.Println(c.Param("param"))
		notify := c.ResponseWriter.(http.CloseNotifier).CloseNotify()
		for {
			select {
			case v := <-msgChan:
				err := c.Stream(v)
				if err != nil {
					return
				}
			case <-notify:
				return
			}
		}
	})

	// when someone hit this endpoint we publish to SSE using msgChan
	app.Get("/pub/sse", func(c *kmux.Context) {
		go func() {
			msgChan <- "hello stream"
		}()
		c.Text("sse")
	})

	app.Run(":9313")
}
```