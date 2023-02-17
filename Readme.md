# Kmux minimalistic regex router

# Install
```sh
go get -u github.com/kamalshkeir/kmux@v1.8.5
```

```go
package main

import (
	"github.com/kamalshkeir/klog"
	"github.com/kamalshkeir/kmux"
)

func main() {
	app := kmux.New()

    // use global middlewares
    app.Use(kmux.Gzip(),kmux.Recovery(),kmux.Limiter(),kmux.Logs())

    // Group
    anyGroup := app.Group("/any") // or grp := app.Group("any")

    // handle '/any' and '/any/option1' and '/any/option2'
    anyGroup.GET("/(option1|option2)?", func(c *kmux.Context) {
		c.Text("ok ")
	})
    // handle only '/any/option1' and '/any/option2' but not /any
	anyGroup.GET("/(option1|option2)", func(c *kmux.Context) {
		c.Text("ok ")
	})

    // '/test' '/2332' will work
    app.GET("/:param", func(c *kmux.Context) {
		c.Text(c.Param("param"))
	})
    app.GET("/param:str", func(c *kmux.Context) {
		c.Text(c.Param("param"))
	})
    // '/4' will work, '/test' will not
    app.GET("/param:int", func(c *kmux.Context) {
		c.Text(c.Param("param"))
	})
    // '/test' and '/test-1' will work 
    app.GET("/param:slug", func(c *kmux.Context) {
        c.Json(kmux.M{
            "param":c.Param("param"),
        })
	})

    app.GET("/",kmux.BasicAuth(IndexHandler,"username","password"))
	app.POST("/somePost", posting)
	app.PUT("/somePut", putting)
	app.PATCH("/somePatch", patching)
	app.DELETE("/someDelete", deleting)
	app.HEAD("/someDelete", head)
	app.OPTIONS("/someDelete", options)

    // Websockets
    app.WS("/ws/test",func(c *kmux.WsContext) {
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
			err = c.Json(kmux.M{
				"Hello":"World",
			})

			// send Text to current user
			err = c.Text("any data string")

			// broadcast to all connected users
			c.Broadcast(kmux.M{
				"you can send":"struct insetead of maps here",
			})

			// broadcast to all connected users except current user, the one who send the last message
			c.BroadcastExceptCaller(map[string]any{
				"you can send":"struct insetead of maps here",
			})

		}
	})

    // Server Sent Events
    app.SSE("/sse/logs", func(c *kmux.Context) {
		c.Stream("working...")
	})

	klog.Printfs("http://localhost:9313\n")
	app.Run("localhost:9313")
}
```

```go
// BeforeRenderHtml executed before every html c.Html, you can use reqCtx.Value(key).(type.User) for example and add data to templates globaly
func BeforeRenderHtml(fn func(reqCtx context.Context, data *map[string]any))
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
func (c *Context) Text(body string)
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
func (router *Router) EmbededStatics(pathLocalDir string, embeded embed.FS, webPath string)
func (router *Router) LocalTemplates(pathToDir string) error
func (router *Router) EmbededTemplates(template_embed embed.FS, rootDir string) error
```