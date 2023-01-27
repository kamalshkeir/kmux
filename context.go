package kmux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/kamalshkeir/klog"
)

var (
	MultipartSize          = 10 << 20
	beforeRenderHtml       = map[string]func(reqCtx context.Context, data *map[string]any){}
	beforeRenderHtmlSetted = false
)

type M map[string]any
type ContextKey string

// BeforeRenderHtml executed before every html render, you can use reqCtx.Value(key).(type.User) for example and add data to templates globaly
func BeforeRenderHtml(uniqueName string, fn func(reqCtx context.Context, data *map[string]any)) {
	beforeRenderHtml[uniqueName] = fn
	beforeRenderHtmlSetted = true
}

// Context is a wrapper of responseWriter, request, and params map
type Context struct {
	http.ResponseWriter
	*http.Request
	CtxParamsMap map[string]string
	status       int
}

// Status set status to context, will not be writed to header
func (c *Context) Status(code int) *Context {
	c.status = code
	return c
}

func (c *Context) ParamsMap() map[string]string {
	return c.CtxParamsMap
}

func (c *Context) Param(paramName string) string {
	if v, ok := c.CtxParamsMap[paramName]; ok {
		return v
	} else {
		return ""
	}
}

// AddHeader Add append a header value to key if exist
func (c *Context) AddHeader(key, value string) {
	c.ResponseWriter.Header().Add(key, value)
}

// SetHeader Set the header value to the new value, old removed
func (c *Context) SetHeader(key, value string) {
	c.ResponseWriter.Header().Set(key, value)
}

// SetHeader Set the header value to the new value, old removed
func (c *Context) SetStatus(statusCode int) {
	c.status = statusCode
	c.WriteHeader(statusCode)
}

// QueryParam get query param
func (c *Context) QueryParam(name string) string {
	return c.Request.URL.Query().Get(name)
}

// Json return json to the client
func (c *Context) Json(data any) {
	c.SetHeader("Content-Type", "application/json")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)
	enc := json.NewEncoder(c.ResponseWriter)
	err := enc.Encode(data)
	klog.CheckError(err)
}

// JsonIndent return json indented to the client
func (c *Context) JsonIndent(data any) {
	c.SetHeader("Content-Type", "application/json")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)
	enc := json.NewEncoder(c.ResponseWriter)
	enc.SetIndent("", "\t")
	err := enc.Encode(data)
	klog.CheckError(err)
}

// Text return text with custom code to the client
func (c *Context) Text(body string) {
	c.SetHeader("Content-Type", "text/plain")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)
	_, err := c.ResponseWriter.Write([]byte(body))
	klog.CheckError(err)
}

// Html return template_name with data to the client
func (c *Context) Html(template_name string, data map[string]any) {
	var buff bytes.Buffer
	if data == nil {
		data = make(map[string]any)
	}
	data["Request"] = c.Request
	if beforeRenderHtmlSetted {
		for _, v := range beforeRenderHtml {
			v(c.Request.Context(), &data)
		}
	}

	err := allTemplates.ExecuteTemplate(&buff, template_name, data)
	if klog.CheckError(err) {
		c.status = http.StatusInternalServerError
		http.Error(c.ResponseWriter, fmt.Sprintf("could not render %s : %v", template_name, err), c.status)
		return
	}

	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)

	_, err = buff.WriteTo(c.ResponseWriter)
	klog.CheckError(err)
}

func (c *Context) IsAuthenticated() bool {
	const key ContextKey = "user"
	if user := c.Request.Context().Value(key); user != nil {
		return true
	} else {
		return false
	}
}

func (c *Context) User() (any, bool) {
	const key ContextKey = "user"
	user := c.Request.Context().Value(key)
	if user != nil {
		return user, true
	} else {
		return nil, false
	}
}

// Stream send SSE Streaming Response
func (c *Context) Stream(response string) {
	c.SetHeader("Content-Type", "text/event-stream")
	b := strings.Builder{}
	b.WriteString("data: ")
	b.WriteString(response)
	b.WriteString("\n\n")
	_, err := c.ResponseWriter.Write([]byte(b.String()))
	klog.CheckError(err)
}

// BodyJson get json body from request and return map
// USAGE : data := c.BodyJson(r)
func (c *Context) BodyJson() map[string]any {
	defer c.Request.Body.Close()
	d := map[string]any{}
	dec := json.NewDecoder(c.Request.Body)
	if err := dec.Decode(&d); err == io.EOF {
		//empty body
		klog.Printf("rdempty body EOF\n")
		return nil
	} else if err != nil {
		klog.Printf("rderror BodyJson: %v \n", err)
		return nil
	} else {
		return d
	}
}

func (c *Context) BodyText() string {
	defer c.Request.Body.Close()
	b, err := io.ReadAll(c.Request.Body)
	if klog.CheckError(err) {
		return ""
	}
	return string(b)
}

// Redirect redirect the client to the specified path with a custom code
func (c *Context) Redirect(path string) {
	if c.status == 0 {
		c.status = http.StatusTemporaryRedirect
	}
	http.Redirect(c.ResponseWriter, c.Request, path, c.status)
}

// ServeFile serve a file from handler
func (c *Context) ServeFile(content_type, path_to_file string) {
	c.SetHeader("Content-Type", content_type)
	http.ServeFile(c.ResponseWriter, c.Request, path_to_file)
}

// ServeEmbededFile serve an embeded file from handler
func (c *Context) ServeEmbededFile(content_type string, embed_file []byte) {
	c.SetHeader("Content-Type", content_type)
	_, err := c.ResponseWriter.Write(embed_file)
	klog.CheckError(err)
}

func (c *Context) ParseMultipartForm(size ...int64) (formData url.Values, formFiles map[string][]*multipart.FileHeader) {
	s := int64(32 << 20)
	if len(size) > 0 {
		s = size[0]
	}
	r := c.Request
	parseErr := r.ParseMultipartForm(s)
	if parseErr != nil {
		klog.Printf("rdParseMultipartForm error = %v\n", parseErr)
	}
	defer func() {
		err := r.MultipartForm.RemoveAll()
		klog.CheckError(err)
	}()
	formData = r.Form
	formFiles = r.MultipartForm.File
	return formData, formFiles
}

// UploadFile upload received_filename into folder_out and return url,fileByte,error
func (c *Context) UploadFile(received_filename, folder_out string, acceptedFormats ...string) (string, []byte, error) {
	_, formFiles := c.ParseMultipartForm()
	url := ""
	data := []byte{}
	for inputName, files := range formFiles {
		var buff bytes.Buffer
		if received_filename == inputName {
			f := files[0]
			file, err := f.Open()
			if klog.CheckError(err) {
				return "", nil, err
			}
			defer file.Close()
			// copy the uploaded file to the buffer
			if _, err := io.Copy(&buff, file); err != nil {
				return "", nil, err
			}

			data_string := buff.String()

			// make DIRS if not exist
			err = os.MkdirAll(MEDIA_DIR+"/"+folder_out+"/", 0664)
			if err != nil {
				return "", nil, err
			}
			// make file
			if len(acceptedFormats) == 0 {
				acceptedFormats = []string{"jpg", "jpeg", "png", "json"}
			}
			if StringContains(f.Filename, acceptedFormats...) {
				dst, err := os.Create(MEDIA_DIR + "/" + folder_out + "/" + f.Filename)
				if err != nil {
					return "", nil, err
				}
				defer dst.Close()
				dst.Write([]byte(data_string))

				url = MEDIA_DIR + "/" + folder_out + "/" + f.Filename
				data = []byte(data_string)
			} else {
				klog.Printf("%s not handled \n", f.Filename)
				return "", nil, fmt.Errorf("expecting filename to finish to be %v", acceptedFormats)
			}
		}

	}
	return url, data, nil
}

func (c *Context) UploadFiles(received_filenames []string, folder_out string, acceptedFormats ...string) ([]string, [][]byte, error) {
	_, formFiles := c.ParseMultipartForm()
	urls := []string{}
	datas := [][]byte{}
	for inputName, files := range formFiles {
		var buff bytes.Buffer
		if len(files) > 0 && SliceContains(received_filenames, inputName) {
			for _, f := range files {
				file, err := f.Open()
				if klog.CheckError(err) {
					return nil, nil, err
				}
				defer file.Close()
				// copy the uploaded file to the buffer
				if _, err := io.Copy(&buff, file); err != nil {
					return nil, nil, err
				}

				data_string := buff.String()

				// make DIRS if not exist
				err = os.MkdirAll(MEDIA_DIR+"/"+folder_out+"/", 0664)
				if err != nil {
					return nil, nil, err
				}
				// make file
				if len(acceptedFormats) == 0 {
					acceptedFormats = []string{"jpg", "jpeg", "png", "json"}
				}
				if StringContains(f.Filename, acceptedFormats...) {
					dst, err := os.Create(MEDIA_DIR + "/" + folder_out + "/" + f.Filename)
					if err != nil {
						return nil, nil, err
					}
					defer dst.Close()
					dst.Write([]byte(data_string))

					url := MEDIA_DIR + "/" + folder_out + "/" + f.Filename
					urls = append(urls, url)
					datas = append(datas, []byte(data_string))
				} else {
					klog.Printf("%s not handled \n", f.Filename)
					return nil, nil, fmt.Errorf("expecting filename to finish to be %v", acceptedFormats)
				}
			}
		}

	}
	return urls, datas, nil
}

// DELETE FILE
func (c *Context) DeleteFile(path string) error {
	err := os.Remove("." + path)
	if err != nil {
		return err
	} else {
		return nil
	}
}

// Download download data_bytes(content) asFilename(test.json,data.csv,...) to the client
func (c *Context) Download(data_bytes []byte, asFilename string) {
	bytesReader := bytes.NewReader(data_bytes)
	c.SetHeader("Content-Disposition", "attachment; filename="+strconv.Quote(asFilename))
	c.SetHeader("Content-Type", c.Request.Header.Get("Content-Type"))
	io.Copy(c.ResponseWriter, bytesReader)
}

func (c *Context) GetUserIP() string {
	IPAddress := c.Request.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = c.Request.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = c.Request.RemoteAddr
	}
	return IPAddress
}
