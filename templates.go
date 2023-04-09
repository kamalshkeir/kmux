package kmux

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/segmentio/encoding/json"

	"github.com/kamalshkeir/klog"
)

var allTemplates = template.New("")

func (router *Router) LocalStatics(dirPath, webPath string, handlerMiddlewares ...func(handler Handler) Handler) {
	dirPath = filepath.ToSlash(dirPath)
	if webPath[0] != '/' {
		webPath = "/" + webPath
	}
	webPath = strings.TrimSuffix(webPath, "/")
	handler := func(c *Context) {
		http.StripPrefix(webPath, http.FileServer(http.Dir(dirPath))).ServeHTTP(c.ResponseWriter, c.Request)
	}
	for _, mid := range handlerMiddlewares {
		handler = mid(handler)
	}
	router.Get(webPath+"/*path", handler)
}

func (router *Router) EmbededStatics(embeded embed.FS, pathLocalDir, webPath string, handlerMiddlewares ...func(handler Handler) Handler) {
	pathLocalDir = filepath.ToSlash(pathLocalDir)
	if webPath[0] != '/' {
		webPath = "/" + webPath
	}
	webPath = strings.TrimSuffix(webPath, "/")
	toembed_dir, err := fs.Sub(embeded, pathLocalDir)
	if err != nil {
		klog.Printf("rdServeEmbededDir error= %v\n", err)
		return
	}
	toembed_root := http.FileServer(http.FS(toembed_dir))
	handler := func(c *Context) {
		http.StripPrefix(webPath, toembed_root).ServeHTTP(c.ResponseWriter, c.Request)
	}
	for _, mid := range handlerMiddlewares {
		handler = mid(handler)
	}
	router.Get(webPath+"/*path", handler)
}

func (router *Router) LocalTemplates(pathToDir string) error {
	cleanRoot := filepath.ToSlash(pathToDir)
	pfx := len(cleanRoot) + 1

	err := filepath.Walk(cleanRoot, func(path string, info os.FileInfo, e1 error) error {
		if !info.IsDir() && strings.HasSuffix(path, ".html") {
			if e1 != nil {
				return e1
			}

			b, e2 := os.ReadFile(path)
			if e2 != nil {
				return e2
			}
			name := filepath.ToSlash(path[pfx:])
			t := allTemplates.New(name).Funcs(functions)
			_, e2 = t.Parse(string(b))
			if e2 != nil {
				return e2
			}
		}

		return nil
	})

	return err
}

func (router *Router) EmbededTemplates(template_embed embed.FS, rootDir string) error {
	cleanRoot := filepath.ToSlash(rootDir)
	pfx := len(cleanRoot) + 1

	err := fs.WalkDir(template_embed, cleanRoot, func(path string, info fs.DirEntry, e1 error) error {
		if klog.CheckError(e1) {
			return e1
		}
		if !info.IsDir() && strings.HasSuffix(path, ".html") {
			b, e2 := template_embed.ReadFile(path)
			if klog.CheckError(e2) {
				return e2
			}

			name := filepath.ToSlash(path[pfx:])
			t := allTemplates.New(name).Funcs(functions)
			_, e3 := t.Parse(string(b))
			if klog.CheckError(e3) {
				return e2
			}
		}

		return nil
	})

	return err
}

func (router *Router) ServeLocalFile(file, endpoint, contentType string) {
	router.Get(endpoint, func(c *Context) {
		c.ServeFile(contentType, file)
	})
}

func (router *Router) ServeEmbededFile(file []byte, endpoint, contentType string) {
	router.Get(endpoint, func(c *Context) {
		c.ServeEmbededFile(contentType, file)
	})
}

func (router *Router) NewFuncMap(funcName string, function any) {
	if _, ok := functions[funcName]; ok {
		klog.Printf("rdunable to add %s,already exist !\n", funcName)
	} else {
		functions[funcName] = function
	}
}

/* FUNC MAPS */
var functions = template.FuncMap{
	"contains": func(str string, substrings ...string) bool {
		for _, substr := range substrings {
			if strings.Contains(strings.ToLower(str), substr) {
				return true
			}
		}
		return false
	},
	"startWith": func(str string, substrings ...string) bool {
		for _, substr := range substrings {
			if strings.HasPrefix(strings.ToLower(str), substr) {
				return true
			}
		}
		return false
	},
	"finishWith": func(str string, substrings ...string) bool {
		for _, substr := range substrings {
			if strings.HasSuffix(strings.ToLower(str), substr) {
				return true
			}
		}
		return false
	},
	"jsonIndented": func(data any) string {
		d, err := json.MarshalIndent(data, "", "\t")
		if err != nil {
			d = []byte("cannot marshal data")
		}
		return string(d)
	},
	"generateUUID": func() template.HTML {
		uuid, _ := GenerateUUID()
		return template.HTML(uuid)
	},
	"add": func(a int, b int) int {
		return a + b
	},
	"safe": func(str string) template.HTML {
		return template.HTML(str)
	},
	"jsTime": func(t any) string {
		valueToReturn := ""
		switch v := t.(type) {
		case time.Time:
			if !v.IsZero() {
				valueToReturn = v.Format("2006-01-02T15:04")
			} else {
				valueToReturn = time.Now().Format("2006-01-02T15:04")
			}
		case int:
			valueToReturn = time.Unix(int64(v), 0).Format("2006-01-02T15:04")
		case uint:
			valueToReturn = time.Unix(int64(v), 0).Format("2006-01-02T15:04")
		case int64:
			valueToReturn = time.Unix(v, 0).Format("2006-01-02T15:04")
		case string:
			if len(v) >= len("2006-01-02T15:04") && strings.Contains(v[:13], "T") {
				p, err := time.Parse("2006-01-02T15:04", v)
				if klog.CheckError(err) {
					valueToReturn = time.Now().Format("2006-01-02T15:04")
				} else {
					valueToReturn = p.Format("2006-01-02T15:04")
				}
			} else {
				if len(v) >= 16 {
					p, err := time.Parse("2006-01-02 15:04", v[:16])
					if klog.CheckError(err) {
						valueToReturn = time.Now().Format("2006-01-02T15:04")
					} else {
						valueToReturn = p.Format("2006-01-02T15:04")
					}
				}
			}
		default:
			if v != nil {
				klog.Printf("rdtype of %v %T is not handled,type is: %v\n", t, v, v)
			}
			valueToReturn = ""
		}
		return valueToReturn
	},
	"date": func(t any) string {
		dString := "02 Jan 2006"
		valueToReturn := ""
		switch v := t.(type) {
		case time.Time:
			if !v.IsZero() {
				valueToReturn = v.Format(dString)
			} else {
				valueToReturn = time.Now().Format(dString)
			}
		case string:
			if len(v) >= len(dString) && strings.Contains(v[:13], "T") {
				p, err := time.Parse(dString, v)
				if klog.CheckError(err) {
					valueToReturn = time.Now().Format(dString)
				} else {
					valueToReturn = p.Format(dString)
				}
			} else {
				if len(v) >= 16 {
					p, err := time.Parse(dString, v[:16])
					if klog.CheckError(err) {
						valueToReturn = time.Now().Format(dString)
					} else {
						valueToReturn = p.Format(dString)
					}
				}
			}
		default:
			if v != nil {
				klog.Printf("rdtype of %v is not handled,type is: %v\n", t, v)
			}
			valueToReturn = ""
		}
		return valueToReturn
	},
	"slug": func(str string) string {
		if len(str) == 0 {
			return ""
		}
		res, err := ToSlug(str)
		if err != nil {
			return ""
		}
		return res
	},
	"truncate": func(str any, size int) any {
		switch v := str.(type) {
		case string:
			if len(v) > size {
				return v[:size] + "..."
			} else {
				return v
			}
		default:
			return v
		}
	},
	"csrf_token": func(r *http.Request) template.HTML {
		csrf, _ := r.Cookie("csrf_token")
		if csrf != nil {
			return template.HTML(fmt.Sprintf("   <input type=\"hidden\" id=\"csrf_token\" value=\"%s\">   ", csrf.Value))
		} else {
			return template.HTML("")
		}
	},
}
