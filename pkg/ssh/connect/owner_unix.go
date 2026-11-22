//go:build unix

package connect

import (
	"io/fs"
	"syscall"
)

// dirOwner returns the owner UID of info, and false when the platform
// does not expose it.
func dirOwner(info fs.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
