package kmux

import (
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kamalshkeir/klog"
)

var DocsGeneralDefaults = DocsGeneralInfo{
	Title:          "Korm Api Documentation",
	Version:        "1.0.0",
	Host:           "localhost:9313",
	BasePath:       "/",
	Description:    "Swagger Api Documentation for Korm",
	TermsOfService: "http://swagger.io/terms/",
	ContactName:    "API Support",
	ContactUrl:     "https://kamalshkeir.dev",
	ContactEmail:   "support@email.com",
	LicenseName:    "Apache 2.0",
	LicenseUrl:     "http://www.apache.org/licenses/LICENSE-2.0.html",
}

type DocsGeneralInfo struct {
	Title          string
	Version        string
	Host           string
	BasePath       string
	Description    string
	TermsOfService string
	ContactName    string
	ContactUrl     string
	ContactEmail   string
	LicenseName    string
	LicenseUrl     string
}

type DocsRoute struct {
	Method           string
	Summary          string
	Description      string
	Tags             string
	Accept           string
	Produce          string
	Response         string
	FailureResponses []string
	Params           []string
	Pattern          string
	Triggered        bool
}

type DocsIn struct {
	Name        string
	In          string
	Type        string
	Required    bool
	Description string
}
type DocsOut struct {
	StatusCode        string
	TypeObjectOrArray string
	TypePath          string
	Value             string
	Extra             string
}

// WithDocs check and install swagger, and generate json and go docs at the end , after the server run, you can use kmux.OnDocsGenerationReady()
// genGoDocs default to true if genJsonDocs
func (router *Router) WithDocs(genJsonDocs bool, genGoDocs ...bool) *Router {
	withDocs = true
	generateSwaggerJson = genJsonDocs
	if len(genGoDocs) > 0 && !genGoDocs[0] {
		generateGoComments = false
	}
	if !swagFound && genJsonDocs {
		err := CheckAndInstallSwagger()
		if klog.CheckError(err) {
			return router
		}
	}
	return router
}

func (r *Route) Summary(summary string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	r.Docs.Summary = summary
	r.Docs.Triggered = true
	return r
}
func (r *Route) Description(description string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	r.Docs.Description = description
	r.Docs.Triggered = true
	return r
}
func (r *Route) Tags(tags ...string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	r.Docs.Tags = strings.Join(tags, ", ")
	r.Docs.Triggered = true
	return r
}

// Accept set docs accept, default 'json'
func (r *Route) Accept(accept string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	r.Docs.Accept = accept
	r.Docs.Triggered = true
	return r
}

// Produce set docs produce, default 'json'
func (r *Route) Produce(produce string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	r.Docs.Produce = produce
	r.Docs.Triggered = true
	return r
}

// In must be like "name  in  typePath  required  'desc'" or you can use kmux.DocsIn.String() method
func (r *Route) In(docsParam ...string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	for i := range docsParam {
		docsParam[i] = strings.ReplaceAll(docsParam[i], "'", "\"")
	}
	r.Docs.Params = docsParam
	r.Docs.Triggered = true
	return r
}

// Out must be like "200  {object}/{array}/{string}  app1.Account/string  'okifstring'" or you can use kmux.DocsOut.String() method
func (r *Route) Out(sucessResponse string, failureResponses ...string) *Route {
	if r.Docs == nil {
		klog.Printf("missing app.WithDocs before\n")
		return r
	}
	r.Docs.Response = strings.ReplaceAll(sucessResponse, "'", "\"")
	for i := range failureResponses {
		failureResponses[i] = strings.ReplaceAll(failureResponses[i], "'", "\"")
	}
	r.Docs.FailureResponses = failureResponses
	r.Docs.Triggered = true
	return r
}

func CheckAndInstallSwagger() error {
	if _, err := exec.LookPath("swag"); err != nil {
		cmd := exec.Command("go", "install", "github.com/swaggo/swag/cmd/swag@latest")
		err := cmd.Run()
		if err != nil {
			return err
		}
	}
	swagFound = true
	return nil
}

func GenerateJsonDocs(entryDocsFile ...string) {
	if !generateGoComments {
		DocsEntryFile = "main.go"
	}
	if len(entryDocsFile) > 0 {
		DocsEntryFile = entryDocsFile[0]
	}
	cmd := exec.Command("swag", "init", "-o", DocsOutJson, "-g", DocsEntryFile, "--outputTypes", "json")
	err := cmd.Run()
	if err != nil {
		klog.Printfs("rdcould not generate swagger.json %s : %s\n", err.Error(), "swag init -o "+DocsOutJson+" -g "+DocsEntryFile+" --outputTypes json")
	}
}

func GenerateGoDocsComments(pkgName ...string) {
	pkg := "kmuxdocs"
	if len(pkgName) > 0 {
		pkg = pkgName[0]
	}
	// create directories if they don't exist
	os.MkdirAll(DocsEntryFile[:len(DocsEntryFile)-len("/"+filepath.Base(DocsEntryFile))], 0755)
	sp := strings.Split(DocsEntryFile, "/")
	typesFolder := strings.Replace(DocsEntryFile, sp[len(sp)-1], "types.go", 1)
	if _, err := os.Stat(typesFolder); err != nil {
		file, err := os.Create(typesFolder)
		if err != nil {
			klog.Printf("rd%v\n", err)
			return
		}
		defer file.Close()
		_, err = file.WriteString(fmt.Sprintf(kmuxdocsTypes, "`json:\"is_admin\"`", "`json:\"created_at\"`"))
		klog.CheckError(err)
	}
	file, err := os.Create(DocsEntryFile)
	if err != nil {
		klog.Printf("rd%v\n", err)
		return
	}
	defer file.Close()
	file.WriteString("package " + pkg + "\n\n")
	general := `// @title           {{.Title}}
// @version         {{.Version}}
// @description     {{.Description}}
// @termsOfService  {{.TermsOfService}}	
// @contact.name   {{.ContactName}}
// @contact.url    {{.ContactUrl}}
// @contact.email  {{.ContactEmail}}	
// @license.name  {{.LicenseName}}
// @license.url   {{.LicenseUrl}}
// @host      {{.Host}}
// @BasePath  {{.BasePath}}
// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/

`
	tmplGen, err := template.New("generaldocs").Parse(general)
	if err != nil {
		fmt.Println("error generate kmxu docs:", err)
		return
	}

	err = tmplGen.Execute(file, DocsGeneralDefaults)
	if err != nil {
		fmt.Println("error generate kmux general defaults:", err)
		return
	}

	// routes

	tmpl, err := template.New("docsroute").Parse(`// @Summary      {{.Docs.Summary}}
// @Description  {{.Docs.Description}}
// @Tags         {{.Docs.Tags}}
// @Accept       {{.Docs.Accept}}
// @Produce      {{.Docs.Produce}}
`)
	if err != nil {
		fmt.Println("error generate kmux docs:", err)
		return
	}

	for _, route := range docsPatterns {
		if err := tmpl.Execute(file, route); err != nil {
			fmt.Println("error generate kmux docs on execute:", err)
			return
		}

		if strings.Contains(route.Docs.Pattern, ":") {
			sp := strings.Split(route.Docs.Pattern, "/")
			for i := range sp {
				if strings.Contains(sp[i], ":") {
					if sp[i][0] == ':' {
						sp[i] = "{" + sp[i][1:] + "}"
					} else {
						spp := strings.Split(sp[i], ":")
						sp[i] = "{" + spp[0] + "}"
					}
					route.Docs.Pattern = strings.Join(sp, "/")
				}
			}
		}

		if len(route.Docs.Params) > 0 {
			for _, p := range route.Docs.Params {
				file.WriteString("// @Param       " + p + "\n")
			}
		}
		if route.Docs.Response != "" {
			file.WriteString("// @Success      " + route.Docs.Response + "\n")
		} else {
			file.WriteString("// @Success      200 {string} string \"ok\"\n")
		}
		if len(route.Docs.FailureResponses) > 0 {
			for _, res := range route.Docs.FailureResponses {
				file.WriteString("// @Failure      " + res + "\n")
			}
		}
		file.WriteString("// @Router       " + route.Docs.Pattern + "  [" + route.Docs.Method + "]\n")
		file.WriteString("func _(){}\n\n")
	}
}

func (dp DocsIn) String() string {
	if dp.Name != "" {
		dp.Name = strings.ReplaceAll(dp.Name, " ", "")
	} else {
		dp.Name = "notset"
	}
	if dp.Type == "" {
		dp.Type = "notset"
	}
	return dp.Name + " " + dp.In + " " + dp.Type + " " + strconv.FormatBool(dp.Required) + " \"" + dp.Description + "\" "
}

func (dr DocsOut) String() string {
	st := dr.StatusCode + " {" + dr.TypeObjectOrArray + "} " + dr.TypePath
	if dr.Value != "" {
		st += " " + dr.Value
	}
	if dr.Extra != "" {
		st += " " + dr.Extra
	}
	return strings.ReplaceAll(st, "'", "\"")
}

var kmuxdocsTypes = `package kmuxdocs

import "time"

type DocsSuccess struct {
	Success string
}

type DocsError struct {
	Error string
}

type DocsUser struct {
	Id        int        
	Uuid      string     
	Email     string     
	Password  string     
	IsAdmin   bool        %s
	Image     string     
	CreatedAt *time.Time  %s
}
`
