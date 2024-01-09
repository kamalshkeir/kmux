package kmux

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/kamalshkeir/kencoding/json"

	"github.com/kamalshkeir/klog"
)

// BeforeRenderHtml executed before every html render, you can use reqCtx.Value(key).(type.User) for example and add data to templates globaly
func BeforeRenderHtml(uniqueName string, fn func(reqCtx context.Context, data *map[string]any)) {
	beforeRenderHtml[uniqueName] = fn
	beforeRenderHtmlSetted = true
}

type ContextKey string

type Context struct {
	http.ResponseWriter
	*http.Request
	CtxParams Params
	status    int
}

// Context return request context
func (c *Context) Context() context.Context {
	return c.Request.Context()
}

// Status set status to context, will not be writed to header
func (c *Context) Status(code int) *Context {
	c.status = code
	return c
}

func (c *Context) ParamsMap() map[string]string {
	m := map[string]string{}
	for _, v := range c.CtxParams {
		m[v.Key] = v.Value
	}
	return m
}

func (c *Context) Param(paramName string) string {
	for _, v := range c.CtxParams {
		if v.Key == paramName {
			return v.Value
		}
	}
	return ""
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
	by, err := json.Marshal(data)
	if !klog.CheckError(err) {
		_, err = c.ResponseWriter.Write(by)
		klog.CheckError(err)
	}
}

// JsonIndent return json indented to the client
func (c *Context) JsonIndent(data any) {
	c.SetHeader("Content-Type", "application/json")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)
	by, err := json.MarshalIndent(data, "", " \t")
	if !klog.CheckError(err) {
		_, err = c.ResponseWriter.Write(by)
		klog.CheckError(err)
	}
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
		klog.Printfs("rdcould not render %s : %v", template_name, err)
		http.Error(c.ResponseWriter, fmt.Sprintf("could not render %s : %v", template_name, err), c.status)
		return
	}

	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)

	_, err = buff.WriteTo(c.ResponseWriter)
	if klog.CheckError(err) {
		return
	}
}

// RawHtml render rawTemplate with data using go engine
func (c *Context) RawHtml(rawTemplate string, data map[string]any) error {
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
	t, err := rawTemplates.Parse(rawTemplate)
	if klog.CheckError(err) {
		return err
	}

	if err := t.Execute(&buff, data); klog.CheckError(err) {
		return err
	}

	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	if c.status == 0 {
		c.status = 200
	}
	c.WriteHeader(c.status)
	_, err = buff.WriteTo(c.ResponseWriter)
	if klog.CheckError(err) {
		return err
	}
	return nil
}

func (c *Context) IsAuthenticated(key ...string) bool {
	var k string
	if len(key) > 0 {
		k = key[0]
	} else {
		k = "user"
	}
	if user, _ := c.GetKey(k); user != nil {
		return true
	} else {
		return false
	}
}

// User is alias of c.Keys but have key default to 'user'
func (c *Context) User(key ...string) (any, bool) {
	var k string
	if len(key) > 0 {
		k = key[0]
	} else {
		k = "user"
	}
	return c.GetKey(k)
}

// GetKey return request context value for given key
func (c *Context) GetKey(key string) (any, bool) {
	v := c.Request.Context().Value(ContextKey(key))
	if v != nil {
		return v, true
	} else {
		return nil, false
	}
}

func (c *Context) SetKey(key string, value any) {
	ctx := context.WithValue(c.Request.Context(), ContextKey(key), value)
	c.Request = c.Request.WithContext(ctx)
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

// Stream send SSE Streaming Response
func (c *Context) Stream(response string) error {
	defer c.Flush()
	_, err := c.ResponseWriter.Write([]byte("data: " + response + "\n\n"))
	if klog.CheckError(err) {
		return err
	}
	return nil
}

func (c *Context) Flush() bool {
	f, ok := c.ResponseWriter.(http.Flusher)
	if ok {
		f.Flush()
	}
	return ok
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

// scan body to struct, default json
func (c *Context) BindBody(strctPointer any, isXML ...bool) error {
	defer c.Request.Body.Close()
	if len(isXML) > 0 && isXML[0] {
		dec := xml.NewDecoder(c.Request.Body)
		if err := dec.Decode(strctPointer); klog.CheckError(err) {
			return err
		}
	} else {
		dec := json.NewDecoder(c.Request.Body)
		if err := dec.Decode(strctPointer); klog.CheckError(err) {
			return err
		}
	}
	return nil
}

func (c *Context) BodyText() string {
	defer c.Request.Body.Close()
	b, err := io.ReadAll(c.Request.Body)
	if klog.CheckError(err) {
		return ""
	}
	return string(b)
}

// Redirect redirect the client to the specified path with a custom code, default status 307
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

// SaveFile save file to path
func (c *Context) SaveFile(fileheader *multipart.FileHeader, path string) error {
	return SaveMultipartFile(fileheader, path)
}

// Error send json error
func (c *Context) Error(code int, message string) {
	c.Status(code).Json(map[string]any{
		"error":  message,
		"status": code,
	})
}

// SaveMultipartFile Save MultipartFile
func SaveMultipartFile(fh *multipart.FileHeader, path string) (err error) {
	var (
		f  multipart.File
		ff *os.File
	)
	f, err = fh.Open()
	if err != nil {
		return
	}

	var ok bool
	if ff, ok = f.(*os.File); ok {
		if err = f.Close(); err != nil {
			return
		}
		if os.Rename(ff.Name(), path) == nil {
			return nil
		}

		// Reopen f for the code below.
		if f, err = fh.Open(); err != nil {
			return
		}
	}

	defer func() {
		e := f.Close()
		if err == nil {
			err = e
		}
	}()

	if ff, err = os.Create(path); err != nil {
		return
	}
	defer func() {
		e := ff.Close()
		if err == nil {
			err = e
		}
	}()
	_, err = copyZeroAlloc(ff, f)
	return
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
			err = os.MkdirAll(MEDIA_DIR+"/"+folder_out+"/", 0770)
			if err != nil {
				return "", nil, err
			}
			if len(acceptedFormats) == 0 || StringContains(f.Filename, acceptedFormats...) {
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
				err = os.MkdirAll(MEDIA_DIR+"/"+folder_out+"/", 0770)
				if err != nil {
					return nil, nil, err
				}
				if len(acceptedFormats) == 0 || StringContains(f.Filename, acceptedFormats...) {
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
					return nil, nil, fmt.Errorf("file type not supported, accepted extensions: %v", acceptedFormats)
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
