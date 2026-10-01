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

package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// bridgeIPCHandler is the app's IPC handler as far as the vault bridge
// goes: guiIPCHandler.HandleVaultUnlockKeyFactor's delegation.
type bridgeIPCHandler struct {
	svc *StaticPasswordService
	ctx context.Context
}

func (h bridgeIPCHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionNoPending), nil
}
func (h bridgeIPCHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return nil, ipc.ErrHandlerFailed
}
func (h bridgeIPCHandler) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}
func (h bridgeIPCHandler) HandleVaultUnlockKeyFactor(origin string, fingerprints []string) (*ipc.VaultResult, error) {
	if err := h.svc.BrowserUnlockWithKeyFactor(h.ctx, origin, fingerprints); err != nil {
		return nil, err
	}
	return &ipc.VaultResult{Unlocked: true}, nil
}

// extension is the browser extension's end of the native messaging
// channel: it speaks the encrypted protocol to a real native host, which
// relays to a real IPC server in front of the password service.
type extension struct {
	t      *testing.T
	crypto *nativemsg.SessionCrypto
	in     *os.File
	out    *os.File
}

func connectExtension(t *testing.T, handler ipc.Handler) *extension {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	socket := filepath.Join(dir, "x.sock")
	srv, err := ipc.NewServer(socket, handler, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)

	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	host := nativemsg.NewHostWithIO(socket, slog.New(slog.DiscardHandler), stdinR, stdoutW, nil)
	done := make(chan error, 1)
	go func() { done <- host.Run(ctx) }()
	t.Cleanup(func() {
		_ = stdinW.Close()
		<-done
		cancel()
		_ = srv.Close()
		for _, f := range []*os.File{stdinR, stdoutR, stdoutW} {
			_ = f.Close()
		}
	})

	sc, pub, err := nativemsg.NewSessionCrypto()
	require.NoError(t, err)
	require.NoError(t, nativemsg.WriteMessage(stdinW, &nativemsg.NativeMessage{Type: nativemsg.MsgTypeHandshake, PubKey: base64.StdEncoding.EncodeToString(pub)}))
	ok, err := nativemsg.ReadMessage(stdoutR)
	require.NoError(t, err)
	require.Equal(t, nativemsg.MsgTypeHandshakeOK, ok.Type)
	hostPub, err := base64.StdEncoding.DecodeString(ok.PubKey)
	require.NoError(t, err)
	require.NoError(t, sc.CompleteHandshake(hostPub))
	return &extension{t: t, crypto: sc, in: stdinW, out: stdoutR}
}

// unlock sends the vault request the extension's background makes for a
// console page at origin.
func (e *extension) unlock(origin string, fingerprints []string) ipc.Response {
	e.t.Helper()
	msg, err := json.Marshal(&ipc.Message{Type: ipc.MessageTypeVault, Vault: &ipc.VaultPayload{
		Action: ipc.ActionVaultUnlockKeyFactor, Origin: origin, Fingerprints: fingerprints,
	}})
	require.NoError(e.t, err)
	nonce, ct, err := e.crypto.Encrypt(msg)
	require.NoError(e.t, err)
	require.NoError(e.t, nativemsg.WriteMessage(e.in, &nativemsg.NativeMessage{
		Type: nativemsg.MsgTypeEncrypted, Nonce: nonce, Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}))
	reply, err := nativemsg.ReadMessage(e.out)
	require.NoError(e.t, err)
	raw, err := base64.StdEncoding.DecodeString(reply.Ciphertext)
	require.NoError(e.t, err)
	plain, err := e.crypto.Decrypt(reply.Nonce, raw)
	require.NoError(e.t, err)
	var resp ipc.Response
	require.NoError(e.t, json.Unmarshal(plain, &resp))
	return resp
}

// TestBrowserBridge_EndToEndThroughTheNativeHost runs the whole bridge:
// extension -> encrypted native messaging -> native host -> IPC -> the
// password service -> the vault. The approved request unlocks the vault and
// the extension receives only "unlocked"; a request from another origin is
// refused before the user is asked.
func TestBrowserBridge_EndToEndThroughTheNativeHost(t *testing.T) {
	b := newBrowserBridge(t)
	b.answer = func(id string) { assert.NoError(t, b.svc.ApproveBrowserVaultRequest(id)) }
	ext := connectExtension(t, bridgeIPCHandler{svc: b.svc, ctx: b.ctx})

	refused := ext.unlock("https://evil.example.org", []string{b.fingerprint})
	assert.Equal(t, ipc.StatusError, refused.Status)
	assert.Contains(t, refused.Error, "not the console")
	assert.Empty(t, b.requests, "the user is never asked about another origin")

	resp := ext.unlock("https://kms.example.com", []string{b.fingerprint})
	require.Equal(t, ipc.StatusOK, resp.Status, resp.Error)
	require.NotNil(t, resp.Vault)
	assert.True(t, resp.Vault.Unlocked)
	assert.True(t, b.status(t).Unlocked)

	// The reply carries no secret, only the outcome.
	payload, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.JSONEq(t, `{"status":"ok","vault":{"unlocked":true}}`, string(payload))
}
