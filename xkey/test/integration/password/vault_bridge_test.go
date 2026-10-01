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

//go:build integration && passwordvault

package password

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// extensionOrigin is the browser extension's origin, the one the browser
// names the native host with.
const extensionOrigin = "chrome-extension://xkeyvaultintegrationtest/"

// bridgeBackend is the xKey key backend the factor's key is in.
const bridgeBackend = "software"

// xkeyApp is the xKey app as far as the browser bridge goes: its password
// service on the user's vault, approving every unlock request the way the
// user would in the app, behind its IPC server.
type xkeyApp struct {
	svc      *services.StaticPasswordService
	ctx      context.Context
	mu       sync.Mutex
	requests []events.VaultBrowserUnlockRequestPayload
	codes    chan string
}

func (a *xkeyApp) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionNoPending), nil
}
func (a *xkeyApp) HandleTypePassword(string) (*ipc.Response, error) {
	return nil, ipc.ErrHandlerFailed
}
func (a *xkeyApp) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

// HandleVaultUnlockKeyFactor is the app's delegation of the bridge's vault
// request to the password service.
func (a *xkeyApp) HandleVaultUnlockKeyFactor(origin string, fingerprints []string) (*ipc.VaultResult, error) {
	if err := a.svc.BrowserUnlockWithKeyFactor(a.ctx, origin, fingerprints); err != nil {
		return nil, err
	}
	return &ipc.VaultResult{Unlocked: true}, nil
}

// HandlePairingNotifyCode shows the pairing code -- here, hands it to the
// extension.
func (a *xkeyApp) HandlePairingNotifyCode(code, _, _ string) error {
	a.codes <- code
	return nil
}
func (a *xkeyApp) HandlePairingCompleted(string) error { return nil }

// unlockRequests returns the unlock requests the user was asked about.
func (a *xkeyApp) unlockRequests() []events.VaultBrowserUnlockRequestPayload {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]events.VaultBrowserUnlockRequestPayload(nil), a.requests...)
}

// newXKeyApp opens the user's vault in the xKey password service, with a
// certificate key in an xKey key backend enrolled as a factor, and locks
// the vault again. It returns the app and the factor's key fingerprint.
func newXKeyApp(t *testing.T, u *vaultUser) (*xkeyApp, string) {
	t.Helper()
	ctx := context.Background()
	cert, err := tls.LoadX509KeyPair(u.cert, u.key)
	require.NoError(t, err)
	roots, err := vault.server.RootCAs()
	require.NoError(t, err)
	client, err := xkms.NewWithOptions(
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(vault.server.URL),
		xkms.WithTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
	)
	require.NoError(t, err)
	require.NoError(t, client.Connect(ctx))
	t.Cleanup(func() { _ = client.Close() })

	app := &xkeyApp{ctx: ctx, codes: make(chan string, 1)}
	app.svc = services.NewStaticPasswordService(staticpw.NewStore(xkms.NewStorageMemory()))
	app.svc.SetContext(ctx)
	app.svc.SetClient(client)
	app.svc.SetEventEmitter(func(evt events.Event) {
		p, ok := evt.Payload.(events.VaultBrowserUnlockRequestPayload)
		if !ok {
			return
		}
		app.mu.Lock()
		app.requests = append(app.requests, p)
		app.mu.Unlock()
		go func() { assert.NoError(t, app.svc.ApproveBrowserVaultRequest(p.ID)) }()
	})

	registerCertificateKey(t, "laptop-key")
	res, err := app.svc.EnrollKeyFactor(vaulttoken.FactorCertificate, bridgeBackend, "laptop-key", "", "laptop")
	require.NoError(t, err)
	require.NotEmpty(t, res.RecoveryCode, "the first factor initializes the vault")
	u.lock(t)
	return app, res.Factor.KeyFingerprint
}

// registerCertificateKey starts xKey's key backends, as the app does, and
// creates an EC P-256 key keyID with its certificate in the software one.
func registerCertificateKey(t *testing.T, keyID string) {
	t.Helper()
	ctx := context.Background()
	xkms.Reset()
	require.NoError(t, xkms.AutoInitialize(&xkms.AutoConfig{Datastore: xkms.NewStorageMemory(), DefaultBackend: bridgeBackend}))
	t.Cleanup(xkms.Reset)
	b, err := xkms.GetBackend(bridgeBackend)
	require.NoError(t, err)
	attrs := &xkms.KeyAttributes{
		CN: keyID, KeyType: xkms.KeyTypeEncryption, StoreType: b.Type(),
		KeyAlgorithm: x509.ECDSA, ECCAttributes: &xkms.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err = b.GenerateECDSA(ctx, attrs)
	require.NoError(t, err)
	signer, err := b.Signer(ctx, attrs)
	require.NoError(t, err)
	require.NoError(t, b.SaveCert(ctx, keyID, selfSignedCert(t, signer, keyID)))
}

// selfSignedCert is a self-signed certificate for signer's key.
func selfSignedCert(t *testing.T, signer crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// extension is the browser extension's end of native messaging: the real
// xkey native host ("xkey extension host"), launched as the browser
// launches it, relaying to the app's IPC server.
type extension struct {
	t      *testing.T
	crypto *nativemsg.SessionCrypto
	in     io.WriteCloser
	out    io.Reader
}

// connectExtension starts the native host against app's IPC server and
// pairs the extension with xKey: the host shows a code in the app, and the
// extension submits it, as the user types it.
func connectExtension(t *testing.T, app *xkeyApp) *extension {
	t.Helper()
	home := t.TempDir()
	runDir, err := os.MkdirTemp("", "xkb-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	require.NoError(t, os.Chmod(runDir, 0o700))
	socket := filepath.Join(runDir, "x.sock")
	server, err := ipc.NewServer(socket, app, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go server.Serve(ctx)
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})

	host := exec.Command(vault.xkey, "extension", "host", extensionOrigin)
	host.Env = append(os.Environ(), "HOME="+home, "XKEY_HOME="+home, "XKEY_DATA_DIR="+filepath.Join(home, "data"), ipc.EnvSocketPath+"="+socket)
	in, err := host.StdinPipe()
	require.NoError(t, err)
	out, err := host.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, host.Start())
	t.Cleanup(func() {
		_ = in.Close()
		_ = host.Wait()
	})

	identityPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	identity := base64.StdEncoding.EncodeToString(identityPub)
	sc, pub, err := nativemsg.NewSessionCrypto()
	require.NoError(t, err)
	require.NoError(t, nativemsg.WriteMessage(in, &nativemsg.NativeMessage{
		Type: nativemsg.MsgTypeHandshake, PubKey: base64.StdEncoding.EncodeToString(pub),
		IdentityKey: identity, Origin: extensionOrigin,
	}))
	pair, err := nativemsg.ReadMessage(out)
	require.NoError(t, err)
	require.Equal(t, nativemsg.MsgTypeHandshakePair, pair.Type, "a new extension is paired first: %+v", pair)
	hostPub, err := base64.StdEncoding.DecodeString(pair.PubKey)
	require.NoError(t, err)
	require.NoError(t, sc.CompleteHandshake(hostPub))

	var code string
	select {
	case code = <-app.codes:
	case <-time.After(30 * time.Second):
		require.Fail(t, "xKey was never shown a pairing code")
	}
	require.NoError(t, nativemsg.WriteMessage(in, &nativemsg.NativeMessage{
		Type: nativemsg.MsgTypePairingConfirm, Code: code, IdentityKey: identity,
	}))
	ok, err := nativemsg.ReadMessage(out)
	require.NoError(t, err)
	require.Equal(t, nativemsg.MsgTypePairingOK, ok.Type, "pairing: %+v", ok)
	return &extension{t: t, crypto: sc, in: in, out: out}
}

// unlock sends the vault request the extension's background makes for a
// console page at origin, and returns xKey's reply.
func (e *extension) unlock(origin string, fingerprints []string) (ipc.Response, string) {
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
	require.Equal(e.t, nativemsg.MsgTypeEncrypted, reply.Type, "reply: %+v", reply)
	raw, err := base64.StdEncoding.DecodeString(reply.Ciphertext)
	require.NoError(e.t, err)
	plain, err := e.crypto.Decrypt(reply.Nonce, raw)
	require.NoError(e.t, err)
	var resp ipc.Response
	require.NoError(e.t, json.Unmarshal(plain, &resp))
	return resp, string(plain)
}

// TestVault_BrowserBridge unlocks the vault from the web console through
// the xKey browser bridge, end to end: the extension, paired with xKey,
// speaks encrypted native messaging to the real native host, which relays
// over IPC to the xKey app; the app checks the page's origin against the
// server's relying party, asks the user, and unlocks the vault on the real
// server with the key factor itself. A page of another origin is refused
// before the user is asked, and the reply carries no secret.
func TestVault_BrowserBridge(t *testing.T) {
	u := newUser(t, "vault-bridge")
	app, fingerprint := newXKeyApp(t, u)
	ext := connectExtension(t, app)

	t.Run("wrong origin", func(t *testing.T) {
		resp, _ := ext.unlock("https://evil.example.org", []string{fingerprint})
		assert.Equal(t, ipc.StatusError, resp.Status)
		assert.Contains(t, resp.Error, "not the console")
		assert.Empty(t, app.unlockRequests(), "the user is never asked about another origin")
		u.requireLocked(t)
	})
	t.Run("console origin", func(t *testing.T) {
		resp, plain := ext.unlock(vault.server.URL, []string{fingerprint})
		require.Equal(t, ipc.StatusOK, resp.Status, resp.Error)
		require.NotNil(t, resp.Vault)
		assert.True(t, resp.Vault.Unlocked)
		assert.JSONEq(t, `{"status":"ok","vault":{"unlocked":true}}`, plain, "the reply carries no secret")
		requests := app.unlockRequests()
		require.Len(t, requests, 1, "the user approved the request in xKey")
		assert.Equal(t, vault.server.URL, requests[0].Origin)
		u.requireUnlocked(t)
	})
}
