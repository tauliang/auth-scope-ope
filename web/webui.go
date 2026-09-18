// Package webui exposes the built web UI assets embedded in the Go
// binary. The assets are only embedded when building with the
// "embedweb" tag (the Docker build does this after building the web
// bundle); without the tag FS reports unavailable and the server
// answers the UI routes with 503. Go tests compile and run either way,
// including when web/dist does not exist.
package webui

import "io/fs"

// FS returns the built web UI assets rooted at the bundle directory,
// and whether assets were embedded in this binary. The embedded()
// implementation is selected by build tag: embed_embedweb.go embeds
// web/dist, embed_noembedweb.go provides nothing.
func FS() (fs.FS, bool) {
	fsys := embedded()
	if fsys == nil {
		return nil, false
	}
	sub, err := fs.Sub(fsys, "dist")
	if err != nil {
		return nil, false
	}
	return sub, true
}
