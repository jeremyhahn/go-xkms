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

package api

import (
	"log/slog"
	"net/http"
)

// CloseResponseBody closes resp's body and logs a failure at debug level.
//
// It is meant for the deferred close of an HTTP client response whose body
// has already been (or is about to be) read to completion by the caller: by
// the time this runs, the request's outcome is already decided, so a close
// error changes nothing about what the caller returns. The rest, quic and
// mcp adapters share this helper rather than each repeating the same
// discard-and-log closure at every call site.
func CloseResponseBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		slog.Debug("api: failed to close response body", slog.String("error", err.Error()))
	}
}
