// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package console

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"golang.org/x/crypto/ssh"
)

// Target is a resolved console connection. The host application (xkey loopback
// server, the xkms REST transport, go-trusted-platform) builds it from an
// authenticated request — host/port/user plus a resolved signer (software or
// hardware) and the host-key pin store.
type Target struct {
	Host   string
	Port   int
	User   string
	Signer ssh.Signer

	// Signers are additional candidate signers offered alongside Signer
	// during public-key authentication, in order (see
	// DialRequest.Signers). At least one of Signer/Signers must be set.
	Signers []ssh.Signer

	KnownHosts   known_hosts.Store
	HostKeyScope scope.Scope
	HostKeyOwner string
	Config       Config

	// HostKeyPolicy selects how an unpinned host key is handled:
	//
	//   - "" or "yes": strict — no client prompt, Dial hard-fails
	//     immediately on any unpinned host (today's behavior).
	//   - "ask": the client is sent a "hostkey" confirm frame and the
	//     handler blocks (bounded by WithHostKeyConfirmTimeout) for a
	//     "hostkey-response" reply before accepting or rejecting.
	//   - "accept-new": the client is sent a "hostkey" notify frame
	//     (fire-and-forget, no reply expected) and the key is accepted.
	HostKeyPolicy string

	// KnownHostsExtraFiles are additional OpenSSH known_hosts files
	// consulted (and, on first contact, appended to) per
	// DialRequest.KnownHostsExtraFiles.
	KnownHostsExtraFiles []string

	// KnownHostsSkipStore mirrors DialRequest.KnownHostsSkipStore: the
	// "system"-only known-hosts policy, where KnownHosts is neither
	// consulted nor written.
	KnownHostsSkipStore bool
}

// Resolver authenticates/authorizes a console request and maps it to a Target.
// It is the single seam every host app implements; the bridge itself is
// transport-agnostic and app-agnostic.
type Resolver interface {
	ResolveTarget(r *http.Request) (*Target, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(r *http.Request) (*Target, error)

// ResolveTarget calls f.
func (f ResolverFunc) ResolveTarget(r *http.Request) (*Target, error) { return f(r) }

// controlMessage is the JSON control frame exchanged as a WebSocket TEXT
// message. Binary WebSocket messages carry raw terminal bytes (stdin one way,
// stdout the other); text messages carry control (resize / error).
type controlMessage struct {
	Type    string `json:"type"`           // "resize" | "error" | "exit"
	Rows    int    `json:"rows,omitempty"` // for resize
	Cols    int    `json:"cols,omitempty"` // for resize
	Message string `json:"message,omitempty"`
}

// hostKeyMessage is the server→client host-key confirmation frame, sent as a
// WebSocket TEXT message when Target.HostKeyPolicy is "ask" (Mode "confirm")
// or "accept-new" (Mode "notify"). Known has no omitempty: it is a
// meaningful, always-present value (today it is always false — the frame is
// only sent for a host with no existing pin) so the frontend never has to
// distinguish "known:false" from an absent field.
type hostKeyMessage struct {
	Type        string `json:"type"` // always "hostkey"
	Host        string `json:"host"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	Known       bool   `json:"known"`
	Mode        string `json:"mode"` // "confirm" | "notify"
}

// hostKeyResponse is the client→server reply to a "confirm" mode hostkey
// frame.
type hostKeyResponse struct {
	Type   string `json:"type"` // "hostkey-response"
	Accept bool   `json:"accept"`
}

// HandlerOption configures the WebSocket handler.
type HandlerOption func(*wsHandler)

// WithCheckOrigin sets the WebSocket Origin check (default: same-origin via the
// upgrader's default). Loopback servers pass a permissive check; web servers
// should validate Origin.
func WithCheckOrigin(fn func(r *http.Request) bool) HandlerOption {
	return func(h *wsHandler) { h.upgrader.CheckOrigin = fn }
}

// WithDialTimeout bounds the SSH dial. Default 15s.
func WithDialTimeout(d time.Duration) HandlerOption {
	return func(h *wsHandler) { h.dialTimeout = d }
}

// WithHostKeyConfirmTimeout bounds how long ServeHTTP waits for a
// "hostkey-response" reply when Target.HostKeyPolicy is "ask". Default 60s.
// Has no effect for "accept-new" (which never waits) or the strict default
// (which never prompts).
func WithHostKeyConfirmTimeout(d time.Duration) HandlerOption {
	return func(h *wsHandler) { h.hostKeyConfirmTimeout = d }
}

// NewWSHandler returns an http.Handler that upgrades to a WebSocket and bridges
// it to an interactive SSH console resolved from the request. It is reusable by
// any Go host: mount it on a loopback server (xkey desktop) or an authenticated
// route (the xkms REST transport / a consuming web app).
func NewWSHandler(resolver Resolver, opts ...HandlerOption) http.Handler {
	h := &wsHandler{
		resolver:              resolver,
		dialTimeout:           15 * time.Second,
		hostKeyConfirmTimeout: defaultHostKeyConfirmTimeout,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
		},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

type wsHandler struct {
	resolver              Resolver
	upgrader              websocket.Upgrader
	dialTimeout           time.Duration
	hostKeyConfirmTimeout time.Duration
}

// defaultHostKeyConfirmTimeout bounds an "ask" policy's wait for a
// "hostkey-response" reply when the caller does not override it via
// WithHostKeyConfirmTimeout.
const defaultHostKeyConfirmTimeout = 60 * time.Second

const (
	wsWriteWait  = 10 * time.Second
	wsPongWait   = 60 * time.Second
	wsPingPeriod = 50 * time.Second
	wsReadLimit  = 1 << 20
)

func (h *wsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Resolve (and authorize) BEFORE upgrading so failures return a normal
	// HTTP status the client can read.
	target, err := h.resolver.ResolveTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the response
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			slog.Debug("ssh/console: failed to close the WebSocket connection", "error", cerr)
		}
	}()

	// One write mutex serializes the hostkey-confirm frame (below, during
	// Dial) with the post-Dial error frame. bridge() owns its own write
	// mutex once it starts — Dial always completes (accept, reject, or
	// timeout) before bridge() begins reading/writing conn, so there is
	// never a second concurrent writer.
	var writeMu sync.Mutex

	dialCtx, cancel := context.WithTimeout(r.Context(), h.dialTimeout)
	cons, derr := Dial(dialCtx, DialRequest{
		Host:                 target.Host,
		Port:                 target.Port,
		User:                 target.User,
		Signer:               target.Signer,
		Signers:              target.Signers,
		KnownHosts:           target.KnownHosts,
		HostKeyScope:         target.HostKeyScope,
		HostKeyOwner:         target.HostKeyOwner,
		HostKeyConfirm:       h.buildHostKeyConfirm(target, conn, &writeMu),
		KnownHostsExtraFiles: target.KnownHostsExtraFiles,
		KnownHostsSkipStore:  target.KnownHostsSkipStore,
	}, target.Config)
	cancel()
	if derr != nil {
		writeControl(conn, &writeMu, controlMessage{Type: "error", Message: derr.Error()})
		return
	}
	defer func() {
		if cerr := cons.Close(); cerr != nil {
			slog.Debug("ssh/console: failed to close the bridged session", "error", cerr)
		}
	}()

	bridge(conn, cons)
}

// buildHostKeyConfirm returns the known_hosts.Confirmer wired to the
// "hostkey" / "hostkey-response" WebSocket frames for target.HostKeyPolicy.
// Returns nil for the strict default ("" or "yes"): DialRequest.
// HostKeyConfirm stays nil and Dial reproduces today's immediate-failure
// behavior for an unpinned host.
func (h *wsHandler) buildHostKeyConfirm(target *Target, conn *websocket.Conn, writeMu *sync.Mutex) known_hosts.Confirmer {
	switch target.HostKeyPolicy {
	case "ask":
		return func(_ context.Context, host string, key ssh.PublicKey) (bool, error) {
			msg := hostKeyMessage{
				Type:        "hostkey",
				Host:        host,
				KeyType:     key.Type(),
				Fingerprint: keys.Fingerprint(key),
				Known:       false,
				Mode:        "confirm",
			}
			if err := writeJSON(conn, writeMu, msg); err != nil {
				return false, err
			}
			return h.awaitHostKeyResponse(conn)
		}
	case "accept-new":
		return func(_ context.Context, host string, key ssh.PublicKey) (bool, error) {
			msg := hostKeyMessage{
				Type:        "hostkey",
				Host:        host,
				KeyType:     key.Type(),
				Fingerprint: keys.Fingerprint(key),
				Known:       false,
				Mode:        "notify",
			}
			// Fire-and-forget: a notify write failure must not block or
			// fail the accept-new policy. Still worth knowing about, so it
			// is logged rather than dropped.
			if werr := writeJSON(conn, writeMu, msg); werr != nil {
				slog.Warn("ssh/console: failed to send the accept-new hostkey notify frame", "host", host, "error", werr)
			}
			return true, nil
		}
	default: // "", "yes": strict — no prompt, no confirmer.
		return nil
	}
}

// awaitHostKeyResponse blocks reading conn until a "hostkey-response" TEXT
// frame arrives, the read deadline (h.hostKeyConfirmTimeout) elapses, or the
// connection errors. Non-text frames and text frames of any other type are
// ignored while waiting. The read deadline set here is always cleared
// before returning so bridge()'s read loop does not inherit a stale
// deadline.
func (h *wsHandler) awaitHostKeyResponse(conn *websocket.Conn) (bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(h.hostKeyConfirmTimeout)); err != nil {
		return false, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return false, err
		}
		if mt != websocket.TextMessage {
			continue
		}
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &probe) != nil || probe.Type != "hostkey-response" {
			continue // ignore unrelated control frames while waiting
		}
		var resp hostKeyResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return false, err
		}
		return resp.Accept, nil
	}
}

// bridge pumps bytes between the WebSocket and the console until either side
// closes. Binary WS messages are stdin; text WS messages are control (resize).
// Console output is sent as binary WS messages. A write mutex serializes the
// stdout pump and ping ticker (gorilla forbids concurrent writers).
func bridge(conn *websocket.Conn, cons Console) {
	var writeMu sync.Mutex
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	conn.SetReadLimit(wsReadLimit)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})

	// Console stdout → WebSocket.
	go func() {
		defer closeDone()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := cons.Read(buf)
			if n > 0 {
				writeMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
				werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n])
				writeMu.Unlock()
				if werr != nil {
					return
				}
			}
			if rerr != nil {
				writeControl(conn, &writeMu, controlMessage{Type: "exit"})
				return
			}
		}
	}()

	// Ping keepalive.
	go func() {
		ticker := time.NewTicker(wsPingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				writeMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
				err := conn.WriteMessage(websocket.PingMessage, nil)
				writeMu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()

	// WebSocket → console stdin / control.
	for {
		mt, data, rerr := conn.ReadMessage()
		if rerr != nil {
			break
		}
		switch mt {
		case websocket.BinaryMessage:
			if _, werr := cons.Write(data); werr != nil {
				goto stop
			}
		case websocket.TextMessage:
			var msg controlMessage
			if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" {
				// Best-effort: a rejected resize just leaves the remote PTY
				// at its previous size. Still worth knowing about, so it is
				// logged rather than dropped.
				if rerr := cons.Resize(msg.Rows, msg.Cols); rerr != nil {
					slog.Debug("ssh/console: remote rejected a PTY resize", "rows", msg.Rows, "cols", msg.Cols, "error", rerr)
				}
			}
		}
	}
stop:
	// No more keystrokes can arrive on this WebSocket, so signal EOF to the
	// remote shell and let it exit on its own terms before ServeHTTP's
	// deferred Close tears the session down. Console.Close used to send this
	// EOF implicitly; it now closes the session instead (that implicit EOF
	// raced in-flight writes), so the bridge sends it explicitly and the
	// remote-side semantics are unchanged.
	//
	// Best-effort: this runs on the way out with the WebSocket already gone,
	// so there is nobody left to report a failure to over the wire, and
	// Close still terminates the session unconditionally either way. Still
	// worth knowing about, so it is logged rather than dropped.
	if cerr := cons.CloseWrite(); cerr != nil {
		slog.Debug("ssh/console: CloseWrite failed while tearing down a bridged session", "error", cerr)
	}
	closeDone()
}

// writeControl sends a JSON control frame as a WebSocket TEXT message.
// Best-effort: every caller is itself reporting connection state (an error
// or an exit notice) to a peer that may already be gone, so there is no
// further action to take on a failed send here. Still worth knowing about,
// so it is logged rather than dropped.
func writeControl(conn *websocket.Conn, mu *sync.Mutex, msg controlMessage) {
	if err := writeJSON(conn, mu, msg); err != nil {
		slog.Debug("ssh/console: failed to send a control frame", "type", msg.Type, "error", err)
	}
}

// writeJSON marshals v and sends it as a WebSocket TEXT message, serialized
// against concurrent writers via mu (gorilla forbids concurrent writers on
// the same connection).
func writeJSON(conn *websocket.Conn, mu *sync.Mutex, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	return conn.WriteMessage(websocket.TextMessage, data)
}
