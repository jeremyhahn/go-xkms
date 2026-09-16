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

//go:build gui

// Package admin implements the Wails v2 desktop application for the Trusted CA
// admin GUI. The REST API is mounted in-process as the Wails AssetServer
// Handler, alongside the Svelte frontend it serves, so the application opens no
// network listener at all: the webview reaches every route same-origin through
// fetch("/api/v1/..."), and the tenant, user, role and CA operations behind
// those routes are unreachable from anywhere else on the machine.
package admin

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	adminapi "github.com/jeremyhahn/go-xkms/pkg/acme/gui/admin/api"
	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// sameOriginAPIBase is the API base URL handed to the frontend. The API shares
// the webview's origin, so the base is empty and every path the frontend
// builds ("/api/v1/...") is relative to the window's own origin.
const sameOriginAPIBase = ""

// App is the Wails desktop application for the Trusted CA admin GUI.
type App struct {
	ctx     context.Context
	config  *GUIConfig
	client  trustedca.Client
	logger  *slog.Logger
	running atomic.Bool
}

// NewApp creates a new admin GUI application.
func NewApp(cfg *GUIConfig, client trustedca.Client, logger *slog.Logger) *App {
	return &App{
		config: cfg,
		client: client,
		logger: logger,
	}
}

// Run launches the Wails desktop window. It blocks until the window is closed.
func (a *App) Run(assets fs.FS) error {
	if !a.running.CompareAndSwap(false, true) {
		return &ErrServerStart{Detail: "application already running"}
	}
	defer a.running.Store(false)

	return wails.Run(a.wailsOptions(assets))
}

// wailsOptions builds the Wails application options, including the AssetServer
// that serves the frontend and the REST API from the same origin.
func (a *App) wailsOptions(assets fs.FS) *options.App {
	return &options.App{
		Title:         a.config.Title,
		Width:         a.config.Width,
		Height:        a.config.Height,
		MinWidth:      a.config.MinWidth,
		MinHeight:     a.config.MinHeight,
		DisableResize: false,
		Frameless:     false,
		OnStartup:     a.startup,
		Bind:          []interface{}{a},
		Linux: &linux.Options{
			ProgramName: "cactl",
		},
		AssetServer: &assetserver.Options{
			// A GET request is served from Assets first and falls back to
			// Handler when the file does not exist; every non-GET request goes
			// straight to Handler. So the SPA keeps loading from Assets and
			// /api/v1 lands on the router, with no listener under either.
			Assets:  assets,
			Handler: a.apiHandler(),
		},
	}
}

// apiHandler builds the REST API the webview calls. It is reachable only
// through the AssetServer, in-process, which is why the router is built for
// the in-process transport (see pkg/acme/gui/guard).
func (a *App) apiHandler() http.Handler {
	return adminapi.NewRouter(a.client, a.logger, adminapi.WithInProcessTransport())
}

// GetApiBaseUrl is the single Wails binding exposed to the frontend. The API
// is served by the same AssetServer as the frontend itself, so the base is the
// empty string: the Svelte transport prefixes nothing and fetches
// "/api/v1/..." against the window's own origin.
func (a *App) GetApiBaseUrl() string {
	return sameOriginAPIBase
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}
