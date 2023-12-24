package kmux

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamalshkeir/klog"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// GetEmbeded get embeded files and make them global
func (r *Router) Embed(staticDir *embed.FS, templateDir *embed.FS) {
	if staticDir != nil && templateDir != nil {
		StaticEmbeded = true
		TemplateEmbeded = true
		Static = *staticDir
		Templates = *templateDir
	} else {
		fmt.Println("Embed: cannot embed static and templates:", staticDir, templateDir)
	}
}

func StringContains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func SliceContains[T comparable](elems []T, vs ...T) bool {
	for _, s := range elems {
		for _, v := range vs {
			if v == s {
				return true
			}
		}
	}
	return false
}

// UUID

func GenerateUUID() (string, error) {
	var uuid [16]byte
	_, err := io.ReadFull(rand.Reader, uuid[:])
	if err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
	var buf [36]byte
	encodeHex(buf[:], uuid)
	return string(buf[:]), nil
}

func encodeHex(dst []byte, uuid [16]byte) {
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
}

// Graceful Shutdown
func (router *Router) gracefulShutdown() {
	err := Graceful(func() error {
		// Shutdown server
		timeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := FuncOnServerShutdown(router.Server)
		if err != nil {
			return err
		}
		err = router.Server.Shutdown(timeout)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		os.Exit(1)
	}
}

func Graceful(f func() error) error {
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)
	<-s
	return f()
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

func (router *Router) createServerCerts(domainName string, subDomains ...string) (*autocert.Manager, *tls.Config) {
	uniqueDomains := []string{}
	domainsToCertify := map[string]bool{}
	// add domainName
	err := checkDomain(domainName)
	if err == nil {
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
		klog.Printfs("grAuto certified domains: %v\n", uniqueDomains)
		return m, tlsConfig
	}
	return nil, nil
}

// initAutoServer init the server with midws with tlsConfig
func (router *Router) initAutoServer(tlsconf *tls.Config) {
	var h http.Handler
	if len(router.middlewares) > 0 {
		for i := range router.middlewares {
			if i == 0 {
				h = router.middlewares[0](router)
			} else {
				h = router.middlewares[i](h)
			}
		}
	} else {
		h = router
	}
	// Setup Server
	server := http.Server{
		Addr:         port,
		Handler:      h,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
		TLSConfig:    tlsconf,
	}
	router.Server = &server
}

func GetPrivateIp() string {
	pIp := getOutboundIP()
	if pIp == "" {
		pIp = resolveHostIp()
		if pIp == "" {
			pIp = getLocalPrivateIps()[0]
		}
	}
	return pIp
}

func resolveHostIp() string {
	netInterfaceAddresses, err := net.InterfaceAddrs()

	if err != nil {
		return ""
	}

	for _, netInterfaceAddress := range netInterfaceAddresses {
		networkIp, ok := netInterfaceAddress.(*net.IPNet)
		if ok && !networkIp.IP.IsLoopback() && networkIp.IP.To4() != nil {
			ip := networkIp.IP.String()
			return ip
		}
	}

	return ""
}

func getLocalPrivateIps() []string {
	ips := []string{}
	host, _ := os.Hostname()
	addrs, _ := net.LookupIP(host)
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ips = append(ips, ipv4.String())
		}
	}
	return ips
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if localAddr.IP.To4().IsPrivate() {
		return localAddr.IP.String()
	}
	return ""
}

func ToSlug(s string) (string, error) {
	str := []byte(strings.ToLower(s))

	// convert all spaces to dash
	regE := regexp.MustCompile("[[:space:]]")
	str = regE.ReplaceAll(str, []byte("-"))

	// remove all blanks such as tab
	regE = regexp.MustCompile("[[:blank:]]")
	str = regE.ReplaceAll(str, []byte(""))

	// remove all punctuations with the exception of dash

	regE = regexp.MustCompile("[!/:-@[-`{-~]")
	str = regE.ReplaceAll(str, []byte(""))

	regE = regexp.MustCompile("/[^\x20-\x7F]/")
	str = regE.ReplaceAll(str, []byte(""))

	regE = regexp.MustCompile("`&(amp;)?#?[a-z0-9]+;`i")
	str = regE.ReplaceAll(str, []byte("-"))

	regE = regexp.MustCompile("`&([a-z])(acute|uml|circ|grave|ring|cedil|slash|tilde|caron|lig|quot|rsquo);`i")
	str = regE.ReplaceAll(str, []byte("\\1"))

	regE = regexp.MustCompile("`[^a-z0-9]`i")
	str = regE.ReplaceAll(str, []byte("-"))

	regE = regexp.MustCompile("`[-]+`")
	str = regE.ReplaceAll(str, []byte("-"))

	strReplaced := strings.Replace(string(str), "&", "", -1)
	strReplaced = strings.Replace(strReplaced, `"`, "", -1)
	strReplaced = strings.Replace(strReplaced, "&", "-", -1)
	strReplaced = strings.Replace(strReplaced, "--", "-", -1)

	if strings.HasPrefix(strReplaced, "-") || strings.HasPrefix(strReplaced, "--") {
		strReplaced = strings.TrimPrefix(strReplaced, "-")
		strReplaced = strings.TrimPrefix(strReplaced, "--")
	}

	if strings.HasSuffix(strReplaced, "-") || strings.HasSuffix(strReplaced, "--") {
		strReplaced = strings.TrimSuffix(strReplaced, "-")
		strReplaced = strings.TrimSuffix(strReplaced, "--")
	}

	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	slug, _, err := transform.String(t, strReplaced)

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(slug), nil
}

func (router *Router) initServer(addr string) {
	if addr != ADDRESS {
		ADDRESS = addr
	}
	var h http.Handler
	if len(router.middlewares) > 0 {
		for i := range router.middlewares {
			if i == 0 {
				h = router.middlewares[0](router)
			} else {
				h = router.middlewares[i](h)
			}
		}
	} else {
		h = router
	}

	server := http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}
	router.Server = &server
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func longestCommonPrefix(a, b string) int {
	i := 0
	max := min(len(a), len(b))
	for i < max && a[i] == b[i] {
		i++
	}
	return i
}

// checkNameAndWildcard check the name for invalid characters.
// Returns -1 as index, if no wildcard was found.
func checkNameAndWildcard(path string) (wilcard string, i int, valid bool) {
	for start, c := range []byte(path) {
		if c != ':' && c != '*' {
			continue
		}

		valid = true
		for end, c := range []byte(path[start+1:]) {
			switch c {
			case '/':
				return path[start : start+1+end], start, valid
			case ':', '*':
				valid = false
			}
		}
		return path[start:], start, valid
	}
	return "", -1, false
}

func countParams(path string) uint16 {
	var n uint
	for i := range []byte(path) {
		switch path[i] {
		case ':', '*':
			n++
		}
	}
	return uint16(n)
}

type nodeType uint8

const (
	static nodeType = iota
	root
	param
	catchAll
)

type node struct {
	path      string
	indices   string
	wildChild bool
	nodeTypeV nodeType
	prio      uint32
	children  []*node
	handler   Handler
	wshandler WsHandler
	origines  []string
}

func (n *node) increasePrio(pos int) int {
	cs := n.children
	cs[pos].prio++
	prio := cs[pos].prio

	newPos := pos
	for ; newPos > 0 && cs[newPos-1].prio < prio; newPos-- {
		cs[newPos-1], cs[newPos] = cs[newPos], cs[newPos-1]
	}

	if newPos != pos {
		n.indices = n.indices[:newPos] + n.indices[pos:pos+1] + n.indices[newPos:pos] + n.indices[pos+1:]
	}

	return newPos
}

func (n *node) addRoute(path string, handle Handler, wshandle WsHandler, allowed []string) {
	for i := range allowed {
		allowed[i] = strings.ReplaceAll(allowed[i], "localhost", "127.0.0.1")
		if allowed[i] == "*" {
			continue
		}
		if !strings.HasPrefix(allowed[i], "http") {
			allowed[i] = "http://" + allowed[i]
		}
	}
	fullPath := path
	n.prio++

	// Empty tree
	if n.path == "" && n.indices == "" {
		n.insertChild(path, fullPath, handle, wshandle, allowed)
		n.nodeTypeV = root
		return
	}

walk:
	for {
		i := longestCommonPrefix(path, n.path)

		// Split edge
		if i < len(n.path) {
			child := node{
				path:      n.path[i:],
				wildChild: n.wildChild,
				nodeTypeV: static,
				indices:   n.indices,
				children:  n.children,
				handler:   n.handler,
				prio:      n.prio - 1,
			}

			n.children = []*node{&child}
			n.indices = string([]byte{n.path[i]})
			n.path = path[:i]
			n.handler = nil
			n.wildChild = false
		}

		// Make new node a child of this node
		if i < len(path) {
			path = path[i:]

			if n.wildChild {
				n = n.children[0]
				n.prio++

				// Check if the wildcard matches
				if len(path) >= len(n.path) && n.path == path[:len(n.path)] &&
					// Adding a child to a catchAll is not possible
					n.nodeTypeV != catchAll &&
					// Check for longer wildcard, e.g. :name and :names
					(len(n.path) >= len(path) || path[len(n.path)] == '/') {
					continue walk
				} else {
					// Wildcard conflict
					pathSeg := path
					if n.nodeTypeV != catchAll {
						pathSeg = strings.SplitN(pathSeg, "/", 2)[0]
					}
					prefix := fullPath[:strings.Index(fullPath, pathSeg)] + n.path
					klog.Printfs("rd'%s' in new path '%s' conflicts with existing wildcard '%s' in existing prefix '%s'\n", pathSeg, fullPath, n.path, prefix)
					return
				}
			}

			idxc := path[0]

			// '/' after param
			if n.nodeTypeV == param && idxc == '/' && len(n.children) == 1 {
				n = n.children[0]
				n.prio++
				continue walk
			}

			// Check if a child with the next path byte exists
			for i, c := range []byte(n.indices) {
				if c == idxc {
					i = n.increasePrio(i)
					n = n.children[i]
					continue walk
				}
			}

			// Otherwise insert it
			if idxc != ':' && idxc != '*' {
				// []byte for proper unicode char conversion, see #65
				n.indices += string([]byte{idxc})
				child := &node{}
				n.children = append(n.children, child)
				n.increasePrio(len(n.indices) - 1)
				n = child
			}
			n.insertChild(path, fullPath, handle, wshandle, allowed)
			return
		}

		// Otherwise add handle to current node
		if n.handler != nil {
			klog.Printfs("rda handle is already registered for path '%s'\n", fullPath)
			return
		}
		n.handler = handle
		n.wshandler = wshandle
		return
	}
}

func (n *node) insertChild(path, fullPath string, handle Handler, wshandler WsHandler, allowed []string) {
	for {
		// Find prefix until first wildcard
		wildcard, i, valid := checkNameAndWildcard(path)
		if i < 0 { // No wilcard found
			break
		}
		// The wildcard name must not contain ':' and '*'
		if !valid {
			klog.Printfs("rdonly one wildcard per path segment is allowed, has: '%s' in path '%s'\n", wildcard, fullPath)
			return
		}

		// Check if the wildcard has a name
		if len(wildcard) < 2 {
			klog.Printfs("rdwildcards must be named with a non-empty name in path '%s'\n", fullPath)
			return
		}

		// Check if this node has existing children which would be
		// unreachable if we insert the wildcard here
		if len(n.children) > 0 && len(wildcard) < 2 {
			klog.Printfs("rdwildcard segment '%s' conflicts with existing children in path '%s'\n", wildcard, n.children[0].path)
			return
		}

		// param
		if wildcard[0] == ':' {
			if i > 0 {
				// Insert prefix before the current wildcard
				n.path = path[:i]
				path = path[i:]
			}

			n.wildChild = true
			child := &node{
				nodeTypeV: param,
				path:      wildcard,
			}
			n.children = []*node{child}
			n = child
			n.prio++

			// If the path doesn't end with the wildcard, then there
			// will be another non-wildcard subpath starting with '/'
			if len(wildcard) < len(path) {
				path = path[len(wildcard):]
				child := &node{
					prio: 1,
				}
				n.children = []*node{child}
				n = child
				continue
			}

			// Otherwise we're done. Insert the handle in the new leaf
			if handle != nil {
				n.handler = handle
			} else if wshandler != nil {
				n.wshandler = wshandler
			}
			n.origines = allowed

			return
		}

		// catchAll
		if i+len(wildcard) != len(path) {
			klog.Printf("rdcatch-all routes are only allowed at the end of the path in path %s\n", fullPath)
			return
		}

		if len(n.path) > 0 && n.path[len(n.path)-1] == '/' {
			klog.Printf("rdcatch-all conflicts with existing handle for the path segment root in path %s\n", fullPath)
			return
		}

		// Currently fixed width 1 for '/'
		i--
		if path[i] != '/' {
			klog.Printf("rdno / before catch-all in path %s\n", fullPath)
			return
		}

		n.path = path[:i]

		// First node: catchAll node with empty path
		child := &node{
			wildChild: true,
			nodeTypeV: catchAll,
		}
		n.children = []*node{child}
		n.indices = string('/')
		n = child
		n.prio++
		// Second node: node holding the variable
		child = &node{
			origines:  allowed,
			path:      path[i:],
			nodeTypeV: catchAll,
			handler:   handle,
			wshandler: wshandler,
			prio:      1,
		}
		n.children = []*node{child}

		return
	}

	// If no wildcard was found, simply insert the path and handle
	n.origines = allowed
	n.path = path
	n.handler = handle
	n.wshandler = wshandler
}

func (n *node) search(path string, params func() *Params) (handle Handler, wshandle WsHandler, ps *Params, origines []string, tsr bool) {
walk: // Outer loop for walking the tree
	for {
		prefix := n.path
		if len(path) > len(prefix) {
			if path[:len(prefix)] == prefix {
				path = path[len(prefix):]

				// If this node does not have a wildcard (param or catchAll)
				// child, we can just look up the next child node and continue
				// to walk down the tree
				if !n.wildChild {
					idxc := path[0]
					for i, c := range []byte(n.indices) {
						if c == idxc {
							n = n.children[i]
							continue walk
						}
					}
					// Nothing found.
					// We can recommend to redirect to the same URL without a
					// trailing slash if a leaf exists for that path.
					origines = n.origines
					tsr = (path == "/" && (n.handler != nil || n.wshandler != nil))
					return
				}

				// Handle wildcard child
				n = n.children[0]
				switch n.nodeTypeV {
				case param:
					// Find param end (either '/' or path end)
					end := 0
					for end < len(path) && path[end] != '/' {
						end++
					}

					// Save param value
					if params != nil {
						if ps == nil {
							ps = params()
						}
						// Expand slice within preallocated capacity
						i := len(*ps)
						*ps = (*ps)[:i+1]
						(*ps)[i] = Param{
							Key:   n.path[1:],
							Value: path[:end],
						}
					}
					origines = n.origines
					// go deeper
					if end < len(path) {
						if len(n.children) > 0 {
							path = path[end:]
							n = n.children[0]
							continue walk
						}

						// no deeper
						tsr = (len(path) == end+1)
						return
					}
					if handle = n.handler; handle != nil {
						return
					} else if wshandle = n.wshandler; wshandle != nil {
						return
					} else if len(n.children) == 1 {
						// No handle found. Check if a handle for this path + a
						// trailing slash exists for TSR recommendation
						n = n.children[0]
						tsr = (n.path == "/" && (n.handler != nil || n.wshandler != nil)) || (n.path == "" && n.indices == "/")
					}
					return

				case catchAll:
					// Save param value
					if params != nil {
						if ps == nil {
							ps = params()
						}
						// Expand slice within preallocated capacity
						i := len(*ps)
						*ps = (*ps)[:i+1]

						(*ps)[i] = Param{
							Key:   n.path[2:],
							Value: strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/"),
						}
					}
					origines = n.origines
					handle = n.handler
					wshandle = n.wshandler
					return

				default:
					klog.Printf("rdinvalid node type\n")
					return
				}
			}
		} else if path == prefix {
			// We should have reached the node containing the handle.
			// Check if this node has a handle registered.
			origines = n.origines
			if handle = n.handler; handle != nil {
				return
			} else if wshandle = n.wshandler; wshandle != nil {
				return
			}

			// If there is no handle for this route, but this route has a
			// wildcard child, there must be a handle for this path with an
			// additional trailing slash
			if path == "/" && n.wildChild && n.nodeTypeV != root {
				tsr = true
				return
			}

			if path == "/" && n.nodeTypeV == static {
				tsr = true
				return
			}

			// No handle found. Check if a handle for this path + a
			// trailing slash exists for trailing slash recommendation
			for i, c := range []byte(n.indices) {
				if c == '/' {
					n = n.children[i]
					tsr = (len(n.path) == 1 && (n.handler != nil || n.wshandler != nil)) ||
						(n.nodeTypeV == catchAll && n.children[0].handler != nil) ||
						(n.nodeTypeV == catchAll && n.children[0].wshandler != nil)
					return
				}
			}
			return
		}
		// Nothing found. We can recommend to redirect to the same URL with an
		// extra trailing slash if a leaf exists for that path
		tsr = (path == "/") ||
			(len(prefix) == len(path)+1 && prefix[len(path)] == '/' &&
				path == prefix[:len(prefix)-1] && (n.handler != nil || n.wshandler != nil))
		return
	}
}

func (n *node) findInsensitivePath(path string, fixTSH bool) (fixedPath string, found bool) {
	const stackBufSize = 128

	buf := make([]byte, 0, stackBufSize)
	if l := len(path) + 1; l > stackBufSize {
		buf = make([]byte, 0, l)
	}

	ciPath := n.findCaseInsensitivePathRec(
		path,
		buf,
		[4]byte{},
		fixTSH,
	)

	return string(ciPath), ciPath != nil
}
