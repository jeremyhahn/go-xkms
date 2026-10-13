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

package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// touchDaemonHandler answers touch and type-password requests with a fixed
// response and records the password name it was asked to type.
type touchDaemonHandler struct {
	resp     *ipc.Response
	lastName string
}

func (h *touchDaemonHandler) HandleTouch() (*ipc.Response, error) {
	return h.resp, nil
}

func (h *touchDaemonHandler) HandleTypePassword(name string) (*ipc.Response, error) {
	h.lastName = name
	return h.resp, nil
}

func (h *touchDaemonHandler) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

// runTouchAgainstDaemon serves handler on a private socket and runs the
// touch command against it with the given --password value.
func runTouchAgainstDaemon(t *testing.T, handler *touchDaemonHandler, password string) (string, error) {
	t.Helper()

	sockPath := filepath.Join(privateTempDir(t), "xkey-ipc.sock")
	srv, err := ipc.NewServer(sockPath, handler, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = srv.Close() })

	cmd := &cobra.Command{}
	cmd.Flags().String("password", password, "")
	cmd.Flags().String("socket", sockPath, "")
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = runTouch(cmd, nil)
	return out.String(), err
}

func TestRunTouch_ReportsDaemonAction(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		password string
		want     string
	}{
		{name: "user presence approved", action: ipc.ActionApprovedUP, want: "User presence approved\n"},
		{name: "password typed", action: ipc.ActionTypedPassword, password: "github", want: "Password typed\n"},
		{name: "nothing pending", action: ipc.ActionNoPending, want: "No pending request\n"},
		{name: "other action", action: ipc.ActionDaemonReady, want: "OK: daemon_ready\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &touchDaemonHandler{resp: ipc.OKResponse(tt.action)}

			out, err := runTouchAgainstDaemon(t, handler, tt.password)
			require.NoError(t, err)
			require.Equal(t, tt.want, out)
			require.Equal(t, tt.password, handler.lastName)
		})
	}
}

func TestRunTouch_DaemonReportsError(t *testing.T) {
	handler := &touchDaemonHandler{resp: ipc.ErrorResponse("no such entry")}

	out, err := runTouchAgainstDaemon(t, handler, "missing")
	require.ErrorIs(t, err, ErrTouchFailed)
	require.ErrorContains(t, err, "no such entry")
	require.Empty(t, out)
	require.Equal(t, "missing", handler.lastName)
}
