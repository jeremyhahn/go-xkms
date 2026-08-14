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

package webui

import (
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	corewebui "github.com/jeremyhahn/go-xkms/pkg/webui"
)

// SPAOption configures optional SPA serving behavior. It is the canonical
// pkg/webui Option; this alias keeps the historical name working for
// existing callers of the gorilla/mux adapter.
type SPAOption = corewebui.Option

// WithAPIBaseURL injects a script tag into index.html that sets
// window.__API_BASE_URL__ so the frontend can discover the API prefix.
func WithAPIBaseURL(baseURL string) SPAOption {
	return corewebui.WithAPIBaseURL(baseURL)
}

// RegisterSPA mounts an SPA at the given pathPrefix on the router. The assets
// parameter should be the root embed.FS; RegisterSPA extracts the "dist"
// subdirectory automatically. The pathPrefix must include trailing slash
// (e.g. "/ui/client/"). File serving is delegated to the canonical SPA
// handler in pkg/webui.
func RegisterSPA(router *mux.Router, assets fs.FS, pathPrefix string, logger *slog.Logger, opts ...SPAOption) error {
	distFS, err := fs.Sub(assets, "dist")
	if err != nil {
		return &ErrAssetLoad{Detail: err.Error()}
	}

	spaHandler, err := corewebui.NewHandler(distFS, logger, opts...)
	if err != nil {
		return &ErrAssetLoad{Detail: err.Error()}
	}

	router.PathPrefix(pathPrefix).Handler(
		http.StripPrefix(pathPrefix, spaHandler),
	)

	logger.Info("registered SPA web UI", slog.String("path", pathPrefix))
	return nil
}

// RegisterRoutes mounts the admin SPA under /ui/admin/ on the given router.
func RegisterRoutes(router *mux.Router, adminAssets fs.FS, logger *slog.Logger) error {
	return RegisterSPA(router, adminAssets, "/ui/admin/", logger)
}
