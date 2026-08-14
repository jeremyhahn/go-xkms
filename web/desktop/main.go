// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Command xkms-console is the Wails desktop shell for the xKMS web console.
//
// It runs the same SPA as the daemon-hosted UI in two modes:
//
//   - remote:     manage a remote xkmsd (XKMS_SERVER_URL or a saved bookmark).
//   - standalone: boot the engine in-process on a loopback-only REST listener
//     with a per-launch bearer token (the "MS Access" model) — a single
//     desktop binary that is a complete local KMS with no separate daemon.
//
// The actual window is created by Wails, which needs cgo + WebKit and is
// therefore behind the "desktop" build tag (see gui_enabled.go). A binary
// built without that tag compiles and runs the connection logic but reports
// that GUI support is absent, mirroring xkey's build-tag split.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server/loopback"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	conn, cleanup, err := resolveConnection(context.Background(), logger)
	if err != nil {
		logger.Error("failed to establish connection", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	if err := runGUI(conn, logger); err != nil {
		logger.Error("desktop GUI exited with error", "error", err)
		os.Exit(1)
	}
}

// resolveConnection determines how the SPA should reach an engine and returns
// the Connection plus a cleanup func (which stops the loopback engine in
// standalone mode).
func resolveConnection(ctx context.Context, logger *slog.Logger) (Connection, func(), error) {
	mode := Mode(os.Getenv("XKMS_DESKTOP_MODE"))
	if mode == "" {
		// Default to remote when a server URL is set, else standalone.
		if os.Getenv("XKMS_SERVER_URL") != "" {
			mode = ModeRemote
		} else {
			mode = ModeStandalone
		}
	}

	switch mode {
	case ModeRemote:
		baseURL := os.Getenv("XKMS_SERVER_URL")
		if baseURL == "" {
			// Fall back to the first saved bookmark.
			marks, err := loadBookmarks()
			if err != nil {
				return Connection{}, func() {}, err
			}
			if len(marks) > 0 {
				baseURL = marks[0].BaseURL
			}
		}
		if baseURL == "" {
			return Connection{}, func() {}, &ConfigError{Reason: "remote mode requires XKMS_SERVER_URL or a saved bookmark"}
		}
		logger.Info("desktop remote mode", "base_url", baseURL)
		return Connection{Mode: ModeRemote, BaseURL: baseURL}, func() {}, nil

	case ModeStandalone:
		cfgPath := os.Getenv("XKMS_CONFIG")
		if cfgPath == "" {
			cfgPath = "/etc/xkms/xkmsd.yaml"
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return Connection{}, func() {}, &ConfigError{Reason: "load standalone config", Err: err}
		}
		inst, err := loopback.Launch(ctx, loopback.Options{Config: cfg, Logger: logger})
		if err != nil {
			return Connection{}, func() {}, err
		}
		logger.Info("desktop standalone mode", "base_url", inst.BaseURL)
		cleanup := func() {
			if cErr := inst.Close(context.Background()); cErr != nil {
				logger.Warn("loopback engine shutdown error", "error", cErr)
			}
		}
		return Connection{Mode: ModeStandalone, BaseURL: inst.BaseURL, Token: inst.Token}, cleanup, nil

	default:
		return Connection{}, func() {}, &ConfigError{Reason: "unknown XKMS_DESKTOP_MODE: " + string(mode)}
	}
}
