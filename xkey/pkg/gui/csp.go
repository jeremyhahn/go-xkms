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

package gui

import (
	"net/http"

	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// ContentSecurityPolicy is applied to every response the Wails asset server
// serves for the main application window.
//
// This is deliberately narrower than a full application CSP (script-src,
// style-src, connect-src, img-src and friends are left unset, i.e.
// unrestricted): the app's Svelte build uses inline style attributes
// throughout, xterm.js (the SSH console) and Vite's dev server may need
// worker/eval affordances, and none of that could be exercised against a
// running GUI from this change's environment to confirm a stricter policy
// would not break them. What is verified and directly addresses go-xkms#1274
// is the frame policy: the only <iframe> in the app is the API Explorer
// response preview (APIExplorer.svelte), which renders untrusted fetched
// HTML via srcdoc -- an about:srcdoc document -- and nothing else in the
// app opens a nested browsing context of any kind.
//
//   - frame-src 'self' about: data: -- permits the srcdoc preview
//     (about:srcdoc) and blocks every other frame source outright; combined
//     with the iframe's own sandbox policy (see
//     xkey/frontend/src/lib/utils/sandboxPolicy.ts) this is defense in
//     depth, not the primary control.
//   - object-src 'none' -- the app never uses <object>/<embed>/<applet>.
//   - base-uri 'self' -- the app never uses <base>; this prevents a markup
//     injection from retargeting relative asset URLs.
const ContentSecurityPolicy = "frame-src 'self' about: data:; object-src 'none'; base-uri 'self'"

// cspMiddleware sets ContentSecurityPolicy on every response served by the
// Wails asset server, then delegates to next.
func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// cspAssetServerMiddleware adapts cspMiddleware to assetserver.Middleware.
var cspAssetServerMiddleware assetserver.Middleware = cspMiddleware
