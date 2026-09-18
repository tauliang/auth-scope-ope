//go:build embedweb

package webui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var distFS embed.FS

func embedded() fs.FS { return distFS }
