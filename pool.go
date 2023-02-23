package kmux

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/kamalshkeir/klog"
)

type Param struct {
	Key   string
	Value string
}

type Params []Param

func (ps Params) Get(name string) string {
	for _, p := range ps {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

var ParamsKey ContextKey

func ParamsFromContext(ctx context.Context) Params {
	p, _ := ctx.Value(ParamsKey).(Params)
	return p
}

var MatchedRoutePathParam = "$matchedRoutePath"

func (ps Params) MatchedRoutePath() string {
	return ps.Get(MatchedRoutePathParam)
}

func (r *Router) getPoolParams() *Params {
	ps, _ := r.paramsPool.Get().(*Params)
	if ps != nil {
		*ps = (*ps)[0:0] // reset slice
	}
	return ps
}

func (r *Router) putPoolParams(ps *Params) {
	if ps != nil {
		r.paramsPool.Put(ps)
	}
}

func (r *Router) saveRouteIfMatch(path string, handle Handler) Handler {
	return func(c *Context) {
		ps := ParamsFromContext(c.Request.Context())
		if len(ps) == 0 {
			psp := r.getPoolParams()
			ps = (*psp)[0:1]
			ps[0] = Param{Key: MatchedRoutePathParam, Value: path}
			ctx := Context{
				status:         200,
				ResponseWriter: c.ResponseWriter,
				Request:        c.Request,
				CtxParams:      ps,
			}
			handle(&ctx)
			r.putPoolParams(psp)
		} else {
			ps = append(ps, Param{Key: MatchedRoutePathParam, Value: path})
			ctx := Context{
				status:         200,
				ResponseWriter: c.ResponseWriter,
				Request:        c.Request,
				CtxParams:      ps,
			}
			handle(&ctx)
		}
	}
}

func AdaptPath(p string) string {
	const stackBufSize = 128

	// Turn empty string into "/"
	if p == "" {
		return "/"
	}

	// Reasonably sized buffer on stack to avoid allocations in the common case.
	// If a larger buffer is required, it gets allocated dynamically.
	buf := make([]byte, 0, stackBufSize)

	n := len(p)

	// Invariants:
	//      reading from path; r is index of next byte to process.
	//      writing to buf; w is index of next byte to write.

	// path must start with '/'
	r := 1
	w := 1

	if p[0] != '/' {
		r = 0

		if n+1 > stackBufSize {
			buf = make([]byte, n+1)
		} else {
			buf = buf[:n+1]
		}
		buf[0] = '/'
	}

	trailing := n > 1 && p[n-1] == '/'

	// A bit more clunky without a 'lazybuf' like the path package, but the loop
	// gets completely inlined (bufApp calls).
	// So in contrast to the path package this loop has no expensive function
	// calls (except make, if needed).

	for r < n {
		switch {
		case p[r] == '/':
			// empty path element, trailing slash is added after the end
			r++

		case p[r] == '.' && r+1 == n:
			trailing = true
			r++

		case p[r] == '.' && p[r+1] == '/':
			// . element
			r += 2

		case p[r] == '.' && p[r+1] == '.' && (r+2 == n || p[r+2] == '/'):
			// .. element: remove to last /
			r += 3

			if w > 1 {
				// can backtrack
				w--

				if len(buf) == 0 {
					for w > 1 && p[w] != '/' {
						w--
					}
				} else {
					for w > 1 && buf[w] != '/' {
						w--
					}
				}
			}

		default:
			// Real path element.
			// Add slash if needed
			if w > 1 {
				bufApp(&buf, p, w, '/')
				w++
			}

			// Copy element
			for r < n && p[r] != '/' {
				bufApp(&buf, p, w, p[r])
				w++
				r++
			}
		}
	}

	// Re-append trailing slash
	if trailing && w > 1 {
		bufApp(&buf, p, w, '/')
		w++
	}

	// If the original string was not modified (or only shortened at the end),
	// return the respective substring of the original string.
	// Otherwise return a new string from the buffer.
	if len(buf) == 0 {
		return p[:w]
	}
	return string(buf[:w])
}

// Internal helper to lazily create a buffer if necessary.
// Calls to this function get inlined.
func bufApp(buf *[]byte, s string, w int, c byte) {
	b := *buf
	if len(b) == 0 {
		// No modification of the original string so far.
		// If the next character is the same as in the original string, we do
		// not yet have to allocate a buffer.
		if s[w] == c {
			return
		}

		// Otherwise use either the stack buffer, if it is large enough, or
		// allocate a new buffer on the heap, and copy all previous characters.
		if l := len(s); l > cap(b) {
			*buf = make([]byte, len(s))
		} else {
			*buf = (*buf)[:l]
		}
		b = *buf

		copy(b, s[:w])
	}
	b[w] = c
}

// Shift bytes in array by n bytes left
func shiftNRuneBytes(rb [4]byte, n int) [4]byte {
	switch n {
	case 0:
		return rb
	case 1:
		return [4]byte{rb[1], rb[2], rb[3], 0}
	case 2:
		return [4]byte{rb[2], rb[3]}
	case 3:
		return [4]byte{rb[3]}
	default:
		return [4]byte{}
	}
}

// Recursive case-insensitive lookup function used by n.findCaseInsensitivePath
func (n *node) findCaseInsensitivePathRec(path string, ciPath []byte, rb [4]byte, fixTrailingSlash bool) []byte {
	npLen := len(n.path)

walk: // Outer loop for walking the tree
	for len(path) >= npLen && (npLen == 0 || strings.EqualFold(path[1:npLen], n.path[1:])) {
		// Add common prefix to result
		oldPath := path
		path = path[npLen:]
		ciPath = append(ciPath, n.path...)

		if len(path) > 0 {
			// If this node does not have a wildcard (param or catchAll) child,
			// we can just look up the next child node and continue to walk down
			// the tree
			if !n.wildChild {
				// Skip rune bytes already processed
				rb = shiftNRuneBytes(rb, npLen)

				if rb[0] != 0 {
					// Old rune not finished
					idxc := rb[0]
					for i, c := range []byte(n.indices) {
						if c == idxc {
							// continue with child node
							n = n.children[i]
							npLen = len(n.path)
							continue walk
						}
					}
				} else {
					// Process a new rune
					var rv rune

					// Find rune start.
					// Runes are up to 4 byte long,
					// -4 would definitely be another rune.
					var off int
					for max := min(npLen, 3); off < max; off++ {
						if i := npLen - off; utf8.RuneStart(oldPath[i]) {
							// read rune from cached path
							rv, _ = utf8.DecodeRuneInString(oldPath[i:])
							break
						}
					}

					// Calculate lowercase bytes of current rune
					lo := unicode.ToLower(rv)
					utf8.EncodeRune(rb[:], lo)

					// Skip already processed bytes
					rb = shiftNRuneBytes(rb, off)

					idxc := rb[0]
					for i, c := range []byte(n.indices) {
						// Lowercase matches
						if c == idxc {
							// must use a recursive approach since both the
							// uppercase byte and the lowercase byte might exist
							// as an index
							if out := n.children[i].findCaseInsensitivePathRec(
								path, ciPath, rb, fixTrailingSlash,
							); out != nil {
								return out
							}
							break
						}
					}

					// If we found no match, the same for the uppercase rune,
					// if it differs
					if up := unicode.ToUpper(rv); up != lo {
						utf8.EncodeRune(rb[:], up)
						rb = shiftNRuneBytes(rb, off)

						idxc := rb[0]
						for i, c := range []byte(n.indices) {
							// Uppercase matches
							if c == idxc {
								// Continue with child node
								n = n.children[i]
								npLen = len(n.path)
								continue walk
							}
						}
					}
				}

				// Nothing found. We can recommend to redirect to the same URL
				// without a trailing slash if a leaf exists for that path
				if fixTrailingSlash && path == "/" && n.handler != nil {
					return ciPath
				}
				return nil
			}

			n = n.children[0]
			switch n.nodeTypeV {
			case param:
				// Find param end (either '/' or path end)
				end := 0
				for end < len(path) && path[end] != '/' {
					end++
				}

				// Add param value to case insensitive path
				ciPath = append(ciPath, path[:end]...)

				// We need to go deeper!
				if end < len(path) {
					if len(n.children) > 0 {
						// Continue with child node
						n = n.children[0]
						npLen = len(n.path)
						path = path[end:]
						continue
					}

					// ... but we can't
					if fixTrailingSlash && len(path) == end+1 {
						return ciPath
					}
					return nil
				}

				if n.handler != nil {
					return ciPath
				} else if fixTrailingSlash && len(n.children) == 1 {
					// No handle found. Check if a handle for this path + a
					// trailing slash exists
					n = n.children[0]
					if n.path == "/" && n.handler != nil {
						return append(ciPath, '/')
					}
				}
				return nil

			case catchAll:
				return append(ciPath, path...)

			default:
				klog.Printf("rdinvalid node type\n")
				return nil
			}
		} else {
			// We should have reached the node containing the handle.
			// Check if this node has a handle registered.
			if n.handler != nil {
				return ciPath
			}

			// No handle found.
			// Try to fix the path by adding a trailing slash
			if fixTrailingSlash {
				for i, c := range []byte(n.indices) {
					if c == '/' {
						n = n.children[i]
						if (len(n.path) == 1 && n.handler != nil) ||
							(n.nodeTypeV == catchAll && n.children[0].handler != nil) {
							return append(ciPath, '/')
						}
						return nil
					}
				}
			}
			return nil
		}
	}

	// Nothing found.
	// Try to fix the path by adding / removing a trailing slash
	if fixTrailingSlash {
		if path == "/" {
			return ciPath
		}
		if len(path)+1 == npLen && n.path[len(path)] == '/' &&
			strings.EqualFold(path[1:], n.path[1:len(path)]) && n.handler != nil {
			return append(ciPath, n.path...)
		}
	}
	return nil
}

func (r *Router) recv(w http.ResponseWriter, req *http.Request) {
	if rcv := recover(); rcv != nil {
		r.PanicHandler(w, req, rcv)
	}
}

func (r *Router) AllowedMethods(path, reqMethod string) (allow string) {
	allowed := r.getAllowedMethods(path, reqMethod)

	if len(allowed) > 0 {
		sort.Slice(allowed, func(i, j int) bool { return allowed[i] < allowed[j] })
		allowed = append(allowed, http.MethodOptions)
		return strings.Join(allowed, ", ")
	}

	return allow
}

func (r *Router) getAllowedMethods(path, reqMethod string) []string {
	var allowed []string
	if path == "*" {
		if reqMethod == "" {
			for method := range r.trees {
				if method != http.MethodOptions {
					allowed = append(allowed, method)
				}
			}
		}
	} else {
		for method := range r.trees {
			if method == reqMethod || method == http.MethodOptions {
				continue
			}

			handle, wshandle, _, _, _ := r.trees[method].search(path, nil)
			if handle != nil || wshandle != nil {
				allowed = append(allowed, method)
			}
		}
	}
	return allowed
}

func (r *Router) Lookup(method, path string) (Handler, WsHandler, Params, bool) {
	if root := r.trees[method]; root != nil {
		handle, wshandle, ps, _, tsr := root.search(path, r.getPoolParams)
		if handle == nil && wshandle == nil {
			r.putPoolParams(ps)
			return nil, nil, nil, tsr
		}
		if ps == nil {
			return handle, wshandle, nil, tsr
		}
		return handle, wshandle, *ps, tsr
	}
	return nil, nil, nil, false
}

var copyBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

func copyZeroAlloc(w io.Writer, r io.Reader) (int64, error) {
	vbuf := copyBufPool.Get()
	buf := vbuf.([]byte)
	n, err := io.CopyBuffer(w, r, buf)
	copyBufPool.Put(vbuf)
	return n, err
}
