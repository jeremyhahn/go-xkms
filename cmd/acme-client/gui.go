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

package main

import (
	"io/fs"
	"os"
	"runtime"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	clientgui "github.com/jeremyhahn/go-xkms/pkg/acme/gui/client"
	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/webui"
)

// hasDisplay reports whether a graphical display environment is available.
// On Linux it checks for X11 (DISPLAY) or Wayland (WAYLAND_DISPLAY) session
// variables. On macOS and Windows a display is assumed to be present.
func hasDisplay() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	default:
		return false
	}
}

// runGUI launches the desktop GUI application with the ACME client service
// and, when configured, the SDK client for workflow-based operations.
func runGUI() error {
	cfg := buildServiceConfig()
	logger := service.InitLogger(cfg.Logging)
	svc, err := service.NewService(cfg, logger)
	if err != nil {
		return err
	}

	guiCfg := clientgui.DefaultGUIConfig()
	app := clientgui.NewApp(guiCfg, svc, nil, cfg, logger)

	assets, err := fs.Sub(webui.ClientAssets, "dist")
	if err != nil {
		return err
	}

	return app.Run(assets)
}
