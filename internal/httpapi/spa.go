package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	webui "github.com/tauliang/authscope-ope/web"
)

// spaHandler serves the embedded web UI: static assets by path, with
// every other non-API path falling back to index.html for client-side
// routing. When the binary was built without the embedweb tag there are
// no assets to serve and the handler answers 503.
func spaHandler() http.HandlerFunc {
	fsys, ok := webui.FS()
	if !ok {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "web_ui_not_embedded",
			})
		}
	}
	fileServer := http.FileServer(http.FS(fsys))
	return func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		// Serve a real asset when the bundle has one; otherwise fall
		// back to index.html so client-side routes resolve.
		if p != "/" {
			if fi, err := fs.Stat(fsys, strings.TrimPrefix(p, "/")); err == nil && !fi.IsDir() {
				if strings.HasSuffix(p, "/index.html") || p == "/index.html" {
					w.Header().Set("Cache-Control", "no-cache")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/index.html"
		fileServer.ServeHTTP(w, r)
	}
}
