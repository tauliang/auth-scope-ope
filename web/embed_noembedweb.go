//go:build !embedweb

package webui

import "io/fs"

// Without the embedweb tag no assets are embedded: the binary serves
// the API only, and the UI routes answer 503.
func embedded() fs.FS { return nil }
