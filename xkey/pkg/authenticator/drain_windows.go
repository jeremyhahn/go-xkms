// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"log/slog"
	"os"

	"golang.org/x/sys/windows"
)

// drainFile discards any input already buffered on f. Windows has no
// non-blocking console reads, so the console input buffer is flushed
// instead; a non-console handle (a pipe or file) has nothing to flush.
func drainFile(f *os.File) {
	if err := windows.FlushConsoleInputBuffer(windows.Handle(f.Fd())); err != nil {
		slog.Debug("authenticator: failed to flush console input", "error", err)
	}
}
