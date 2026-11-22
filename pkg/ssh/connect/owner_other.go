//go:build !unix

package connect

import "io/fs"

// dirOwner reports that ownership is not visible on this platform, so no
// XDG_RUNTIME_DIR is trusted and a default work dir falls back to the
// short base.
func dirOwner(fs.FileInfo) (int, bool) {
	return 0, false
}
