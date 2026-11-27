// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestBuildRESTConfig_UsesDaemonLogger is PR #2296's Codex P2: the REST
// server (and the WebAuthn handler's 500 cause logs it carries) must log
// through xkmsd's configured logger, not slog.Default().
func TestBuildRESTConfig_UsesDaemonLogger(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{RESTPort: 8443})
	var buf bytes.Buffer
	srv.logger = slog.New(slog.NewTextHandler(&buf, nil))

	restCfg, err := srv.buildRESTConfig()
	require.NoError(t, err)
	require.Same(t, srv.logger, restCfg.Logger)

	restCfg.Logger.Error("webauthn failure")
	require.Contains(t, buf.String(), "webauthn failure")
}
