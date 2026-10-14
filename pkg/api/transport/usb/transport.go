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

// Package usb provides a USB Accessory Mode (AOA) transport implementation
// for the xkms SDK. It wraps the phone-level USBTransport in a Noise XX
// session and presents the SDK transport.Transport interface.
//
// This transport communicates directly with an Android phone over USB without
// requiring ADB. The phone acts as a USB accessory; the laptop acts as the
// USB host.
//
// The phone's USB responder speaks the same pairing protocol as its BLE and
// TCP responders: a pre-handshake identity exchange, a Noise XX handshake, and
// then JSON-RPC 2.0 messages encrypted under the resulting session. The
// transport therefore requires the pairing key material from a prior
// "xkey device pair" run; without it Connect fails rather than falling back to
// plaintext, which the phone would read as a malformed handshake.
package usb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

var (
	// ErrNotConnected is returned when the USB transport is not connected.
	ErrNotConnected = errors.New("usb transport: not connected")

	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")

	// ErrStreamNotSupported re-exports the package-level sentinel for SDK
	// consumers that classify errors by it (go-xkms#727: this transport has
	// no streaming operation left to return it from).
	ErrStreamNotSupported = transport.ErrStreamNotSupported

	// ErrNoiseNotConfigured is returned when the transport is asked to connect
	// without the pairing key material the Noise handshake needs.
	ErrNoiseNotConfigured = errors.New("usb transport: noise pairing keys not configured")

	// ErrRequestFailed is returned when the phone answers a request with a
	// JSON-RPC error.
	ErrRequestFailed = errors.New("usb transport: request failed")

	// ErrDirtyState is returned when Connect is called on a transport that
	// still holds session state from a previous connection — whether or not it
	// currently reports connected.
	//
	// Reconnecting in place would put handshake frames on the same bus as an
	// in-flight encrypted request and corrupt both streams. It would also
	// overwrite the previous static key and leak its locked pages: a request
	// that fails mid-flight clears connected but leaves the bus, session and
	// key in place, so "not connected" is not the same as "nothing to
	// release". Close first.
	ErrDirtyState = errors.New("usb transport: still holds session state from a previous connection; Close first")
)

// JSON-RPC method names for the password store and seal store operations
// this transport proxies to the phone's embedded xkmsd instance over the
// Noise-encrypted USB channel. Each name matches the XKMSServicer method it
// implements verbatim, the same convention the gRPC service definitions use
// (see pkg/api/grpc/proto/xkmsv1), so the wire contract stays consistent
// across every xkms transport rather than borrowing the unrelated "local.*"
// namespace xkey/pkg/pairing reserves for Android Keystore operations.
const (
	methodPasswordAdd         = "PasswordAdd"
	methodPasswordGet         = "PasswordGet"
	methodPasswordList        = "PasswordList"
	methodPasswordUpdate      = "PasswordUpdate"
	methodPasswordDelete      = "PasswordDelete"
	methodPasswordStoreUnlock = "PasswordStoreUnlock"
	methodPasswordStoreLock   = "PasswordStoreLock"
	methodPasswordStoreStatus = "PasswordStoreStatus"
	methodPasswordGenerate    = "PasswordGenerate"

	methodSealStorePut    = "SealStorePut"
	methodSealStoreGet    = "SealStoreGet"
	methodSealStoreDelete = "SealStoreDelete"
	methodSealStoreList   = "SealStoreList"
	methodSealStoreReseal = "SealStoreReseal"
	methodSealStoreStatus = "SealStoreStatus"
)

// NoiseConfig carries the pairing key material for the Noise XX handshake.
// It is produced by pairing with the phone ("xkey device pair"), which stores
// this host's static private key and the phone's static public key.
type NoiseConfig struct {
	// LocalStaticPrivateKey is this host's 32-byte Curve25519 private key.
	LocalStaticPrivateKey []byte

	// ExpectedRemoteStatic is the phone's Noise static public key. When set,
	// the handshake fails unless the phone presents this key.
	ExpectedRemoteStatic []byte

	// ExpectedDeviceFingerprint is the phone's attestation fingerprint. When
	// set, the identity exchange fails unless the phone reports it, and the
	// value is bound into the Noise prologue.
	ExpectedDeviceFingerprint []byte
}

// phoneTransport defines the operations needed from the phone USB layer.
// The method set is a superset of the pairing transport contract, so a value
// of this type can drive the shared Noise handshake.
type phoneTransport interface {
	Connect(ctx context.Context) error
	Close() error
	IsConnected() bool
	Send(ctx context.Context, message []byte) error
	Receive(ctx context.Context) ([]byte, error)
	SendAndReceive(ctx context.Context, message []byte) ([]byte, error)
}

// Transport implements the transport.Transport interface over USB AOA.
// It wraps a phone-level USBTransport with Noise XX encrypted messaging
// and exposes SDK-level Request/Response operations.
type Transport struct {
	config *transport.Config

	// noise is the transport's OWN copy of the pairing key material, with the
	// private scalar in protected memory. Guarded by lifecycleMu.
	noise *noiseMaterial

	phoneUSB  phoneTransport
	session   *pairing.NoiseSession
	connected bool
	log       *slog.Logger

	// localKey is the protected static key backing session. The session reads
	// its pages in place, so Connect keeps it here and Close releases it;
	// dropping it on the floor would leave a locked, unswappable page
	// resident for every connection the process ever makes.
	localKey *pairing.StaticKey

	// mu serializes requests. A Noise cipherstate advances a monotonic nonce
	// per message, so concurrent senders would put frames on the wire out of
	// nonce order and the phone would reject them. Close additionally
	// destroys the static key the session reads from, so it must not run
	// while a request is mid-encrypt.
	mu sync.Mutex

	// busMu guards phoneUSB ALONE, and exists so Close can reach the bus
	// without mu — which is precisely what a request stalled in
	// SendAndReceive is holding. Lock order where both are held: mu then
	// busMu, and busMu is never held across bus I/O.
	//
	// EVERY access to phoneUSB goes through busMu — the publish in Connect and
	// the reads in Healthy and Conn included. Publishing under mu while
	// clearing under busMu left the field guarded by two different mutexes,
	// which is to say guarded by neither: a Healthy or Conn call concurrent
	// with Close was an unsynchronised read against an unsynchronised write,
	// and could reach IsConnected on a bus being torn down underneath it.
	//
	// mu is not the answer for the readers either. Request holds mu across
	// phoneUSB.SendAndReceive, so a reader taking mu would queue behind the
	// whole I/O timeout of an unresponsive handset — the same hostage problem
	// Close avoids by using busMu in the first place.
	busMu sync.Mutex

	// lifecycleMu serializes Connect against Close and against another
	// Connect, and is held across the whole of each — bus setup, identity
	// exchange and handshake included, not just the publication at the end.
	//
	// Publishing under mu alone is not enough. A Close landing between a
	// successful handshake and its publication would tear the transport down
	// and Connect would then reinstate connected=true over a phoneUSB that
	// had already been closed, leaving the transport reporting a live
	// encrypted session on a dead bus. Two concurrent Connects would likewise
	// run two handshakes through the same phoneUSB.
	//
	// Lock order is always lifecycleMu then mu; Request takes mu alone.
	lifecycleMu sync.Mutex
}

// New creates a new USB transport with the given options. The transport must
// be given pairing keys with WithNoiseConfig before it can connect.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return &Transport{
		config: cfg,
		log:    slog.Default().With("component", "sdk_usb_transport"),
	}, nil
}

// NewWithConfig creates a new USB transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	return &Transport{
		config: cfg,
		log:    slog.Default().With("component", "sdk_usb_transport"),
	}, nil
}

// noiseMaterial is the transport's own copy of the pairing key material.
//
// The private key is held as a *pairing.StaticKey -- go-enclave-backed protected
// memory -- and NOT as a []byte. The transport has to keep its own copy so a
// caller cannot mutate the key under an in-flight handshake, but a copy taken
// with bytes.Clone would be a second plaintext scalar on the ordinary Go heap:
// abandoned unzeroized whenever the configuration is replaced, and outliving
// any wipe the caller performs on its own slice. The company protected-memory
// rule admits no plain []byte for key material, and a defensive copy is not an
// exception to it.
//
// The public key and the fingerprint are not secret and stay ordinary slices.
type noiseMaterial struct {
	// localKey is protected and owned by the transport. Replacing or clearing
	// the configuration destroys it.
	localKey *pairing.StaticKey

	// loadErr records a private key that could not be loaded. WithNoiseConfig
	// returns the transport so it can be chained onto a constructor and has no
	// error to return, so the failure is carried here and reported by Connect
	// rather than swallowed.
	loadErr error

	expectedRemoteStatic      []byte
	expectedDeviceFingerprint []byte
}

// destroy releases the protected pages behind the private key. Safe on a nil
// receiver and idempotent.
func (m *noiseMaterial) destroy() {
	if m == nil {
		return
	}
	m.localKey.Destroy()
	m.localKey = nil
}

// newNoiseMaterial copies cfg into the transport's own representation, moving
// the private scalar into protected memory. A nil config yields nil, which
// Connect reads as "no keys configured".
func newNoiseMaterial(cfg *NoiseConfig) *noiseMaterial {
	if cfg == nil {
		return nil
	}

	m := &noiseMaterial{
		expectedRemoteStatic:      bytes.Clone(cfg.ExpectedRemoteStatic),
		expectedDeviceFingerprint: bytes.Clone(cfg.ExpectedDeviceFingerprint),
	}

	if len(cfg.LocalStaticPrivateKey) == 0 {
		m.loadErr = ErrNoiseNotConfigured
		return m
	}

	key, err := pairing.LoadStaticKey(cfg.LocalStaticPrivateKey)
	if err != nil {
		m.loadErr = err
		return m
	}
	m.localKey = key
	return m
}

// WithNoiseConfig attaches the pairing key material used by Connect. It
// returns the transport so it can be chained onto a constructor.
//
// The chaining ergonomics make this read as setup-only, but it is exported and
// nothing stops a caller invoking it later — during a key rotation, say, while
// a Connect is in flight. It therefore publishes under lifecycleMu, the same
// lock Connect holds for the whole handshake, and stores a deep copy: retaining
// the caller's pointer would let the key material change under a handshake that
// had already begun, producing a session built from half the old key and half
// the new.
func (t *Transport) WithNoiseConfig(cfg *NoiseConfig) *Transport {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()

	// Release the pages behind the key being displaced. Dropping the reference
	// instead would strand a locked, unswappable page for the life of the
	// process on every rotation.
	previous := t.noise
	t.noise = newNoiseMaterial(cfg)
	previous.destroy()

	return t
}

// Connect opens the USB AOA channel, performs the identity exchange, and runs
// the Noise XX handshake. It fails without touching the bus when no pairing
// keys are configured.
func (t *Transport) Connect(ctx context.Context) error {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()

	// Refuse a reconnect rather than handshaking over residual state. Testing
	// t.connected alone is not enough: Request clears it on a send failure
	// while leaving the bus, session and key intact, and Connect would then
	// hand the old key's pages to the garbage collector unfreed and handshake
	// over a half-dead transport.
	t.mu.Lock()
	dirty := t.connected || t.session != nil || t.localKey != nil
	t.mu.Unlock()
	if dirty {
		return ErrDirtyState
	}

	// One snapshot for the whole handshake. lifecycleMu already excludes a
	// concurrent WithNoiseConfig, and reading the pointer once means a future
	// edit that releases the lock mid-connect still cannot splice two
	// configurations into one session.
	noise := t.noise
	if noise == nil || noise.localKey == nil {
		if noise != nil && noise.loadErr != nil && !errors.Is(noise.loadErr, ErrNoiseNotConfigured) {
			return &errs.Detail{Err: ErrNoiseNotConfigured, Detail: fmt.Sprintf("%v", noise.loadErr)}
		}
		return ErrNoiseNotConfigured
	}

	// Connect takes its OWN protected copy rather than handing the session the
	// configured key. The configuration outlives any single connection --
	// Close tears a connection down and the transport can connect again -- so
	// the session must not destroy a key the configuration still owns. The
	// source scalar goes from protected memory straight back into protected
	// memory, never touching the Go heap in between.
	localKey, err := pairing.CloneStaticKey(noise.localKey)
	if err != nil {
		return &errs.Detail{Err: ErrNoiseNotConfigured, Detail: fmt.Sprintf("%v", err)}
	}
	// Until the handshake succeeds this key belongs to Connect, and every
	// failure path below has to release it.
	connected := false
	defer func() {
		if !connected {
			localKey.Destroy()
		}
	}()

	if t.phoneUSB == nil {
		usbCfg := phone.DefaultUSBTransportConfig()
		if t.config.Timeout > 0 {
			usbCfg.OperationTimeout = t.config.Timeout
		}
		usbCfg.Logger = t.log

		usb, err := phone.NewUSBTransport(usbCfg)
		if err != nil {
			return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
		}
		// Published under busMu, the single lock guarding this field.
		t.busMu.Lock()
		t.phoneUSB = usb
		t.busMu.Unlock()
	}

	if err := t.phoneUSB.Connect(ctx); err != nil {
		// Discard it: a bus transport that failed to connect may be partially
		// open, and Connect only builds a fresh one when the field is nil. The
		// dirty-state check above does not look at phoneUSB, so a retained
		// failed instance would be silently reused by every retry — the same
		// defect Close had, on the other path into it.
		t.discardPhoneUSB()
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: noise.expectedRemoteStatic,
		IsInitiator:          true,
	})
	if err != nil {
		t.discardPhoneUSB()
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("noise session: %v", err)}
	}

	// The identity exchange runs on every connection: the phone's stream
	// responder always expects it, and it binds the phone's attestation
	// fingerprint into the prologue.
	if err := pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
		Transport:                 t.phoneUSB,
		Session:                   session,
		Logger:                    t.log,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: noise.expectedDeviceFingerprint,
	}); err != nil {
		t.discardPhoneUSB()
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("noise handshake: %v", err)}
	}

	// Publication under mu so a concurrent Request never observes a
	// half-swapped transport. Close cannot be in flight here: it waits on
	// lifecycleMu, which this call holds until it returns.
	t.mu.Lock()
	defer t.mu.Unlock()

	// Nothing to displace: any residual session or key was rejected above, so
	// this is always a fresh transport.
	t.localKey = localKey
	t.session = session
	t.connected = true
	connected = true
	t.log.Info("SDK USB transport connected")
	return nil
}

// Close closes the USB connection and releases resources.
func (t *Transport) Close() error {
	// lifecycleMu first, so a Connect in flight either finishes publishing or
	// has not started; without it Close could tear down state that Connect
	// then reinstates over a closed bus.
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()

	// CLOSE THE BUS BEFORE CONTENDING FOR mu, because mu is exactly what a
	// stalled request is holding.
	//
	// Request holds mu across phoneUSB.SendAndReceive so the session cannot be
	// freed mid-encrypt — necessary, and it makes mu unavailable for as long as
	// the device takes to answer. A Close that waits for mu first therefore
	// waits out the whole I/O timeout behind an unresponsive handset, and a bus
	// implementation that ignores its context waits forever. Shutdown would be
	// hostage to the device it is trying to shut down.
	//
	// Closing the bus is the thing that ends that wait: the blocked
	// SendAndReceive fails, Request returns, mu is released, and this call
	// proceeds to free the key under the lock exactly as before. The ordering
	// is the entire fix — no drain and no second lock, because mu still proves
	// no request is inside the session when the pages are freed.
	t.busMu.Lock()
	usb := t.phoneUSB
	t.phoneUSB = nil
	t.busMu.Unlock()

	var closeErr error
	if usb != nil {
		closeErr = usb.Close()
	}

	// mu now: whatever request was in flight has been unblocked by the close
	// above and released it.
	t.mu.Lock()
	defer t.mu.Unlock()

	t.connected = false
	t.session = nil

	// No request can be in flight while we hold mu, so nothing is still
	// reading the key's protected pages.
	t.localKey.Destroy()
	t.localKey = nil

	// Drop the bus transport as well as closing it.
	//
	// The production USB transport treats Close as terminal: a closed
	// instance never reconnects. Connect only builds a new one when phoneUSB
	// is nil, so leaving a closed instance installed made ErrDirtyState's own
	// advice — close, then reconnect — impossible to follow. Close cleared
	// the session state, so the dirty check passed, and every subsequent
	// Connect handshaked over a dead bus, permanently. The lifecycle tests
	// did not catch it because their fake is reusable.
	//
	// The reference goes even when Close reports an error: a transport that
	// failed to close is not one to hand the next Connect. Both the close and
	// the reference drop now happen above, before mu is taken, so this returns
	// what that close reported.
	return closeErr
}

// discardPhoneUSB closes the bus transport and drops the reference so the
// next Connect builds a fresh one. It must not be called with t.mu held.
//
// Connect's own failure paths need this for the same reason Close does: a
// closed-but-installed transport is one the next Connect will reuse and
// cannot revive.
func (t *Transport) discardPhoneUSB() {
	t.busMu.Lock()
	usb := t.phoneUSB
	t.phoneUSB = nil
	t.busMu.Unlock()

	if usb == nil {
		return
	}
	if err := usb.Close(); err != nil {
		t.log.Debug("failed to close the discarded USB bus transport", "error", err)
	}
}

// phoneBus returns the current bus transport, or nil, under busMu. The pointer
// is copied out and the lock released before the caller touches the bus, so
// busMu is never held across bus I/O.
func (t *Transport) phoneBus() phoneTransport {
	t.busMu.Lock()
	defer t.busMu.Unlock()

	return t.phoneUSB
}

// Healthy checks if the USB connection is active.
//
// The two fields it reads live under different locks — connected under mu,
// phoneUSB under busMu — so it takes them in the documented order and holds
// neither across IsConnected, which talks to the device.
func (t *Transport) Healthy(_ context.Context) bool {
	t.mu.Lock()
	connected := t.connected
	t.mu.Unlock()

	if !connected {
		return false
	}

	usb := t.phoneBus()
	return usb != nil && usb.IsConnected()
}

// Conn returns the underlying phone USB transport.
func (t *Transport) Conn() interface{} {
	return t.phoneBus()
}

// Request performs a unary request/response operation over the encrypted USB
// channel. The method parameter becomes the JSON-RPC method name and req its
// params; the JSON-RPC result is unmarshalled into resp.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	plaintext, err := pairing.EncodeRequest(pairing.NewRequest(method, req))
	if err != nil {
		return &errs.Detail{Err: transport.ErrInvalidRequest, Detail: fmt.Sprintf("failed to marshal request: %v", err)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Checked under the lock, not before it: Close clears these fields and
	// frees the session's key, so a check taken outside could be stale by the
	// time Encrypt reads the session.
	t.busMu.Lock()
	bus := t.phoneUSB
	t.busMu.Unlock()

	if !t.connected || bus == nil || t.session == nil {
		return ErrNotConnected
	}

	ciphertext, err := t.session.Encrypt(plaintext)
	if err != nil {
		return &errs.Detail{Err: transport.ErrInvalidRequest, Detail: fmt.Sprintf("failed to encrypt request: %v", err)}
	}

	// The snapshot, not the field: Close nils the field under busMu to end a
	// stalled request, and this call must still be operating on the bus it
	// started against.
	responseCiphertext, err := bus.SendAndReceive(ctx, ciphertext)
	if err != nil {
		t.connected = false
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	responsePlaintext, err := t.session.Decrypt(responseCiphertext)
	if err != nil {
		return &errs.Detail{Err: transport.ErrInvalidResponse, Detail: fmt.Sprintf("failed to decrypt response: %v", err)}
	}

	rpcResp, err := pairing.DecodeResponse(responsePlaintext)
	if err != nil {
		return &errs.Detail{Err: transport.ErrInvalidResponse, Detail: fmt.Sprintf("failed to decode response: %v", err)}
	}
	if rpcResp.Error != nil {
		return &errs.Detail{
			Err:    ErrRequestFailed,
			Detail: fmt.Sprintf("[%d] %s", rpcResp.Error.Code, rpcResp.Error.Message),
		}
	}

	if resp != nil {
		if err := json.Unmarshal(rpcResp.Result, resp); err != nil {
			return &errs.Detail{Err: transport.ErrInvalidResponse, Detail: fmt.Sprintf("failed to unmarshal response: %v", err)}
		}
	}

	return nil
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	var resp transport.PasswordAddResponse
	if err := t.Request(ctx, methodPasswordAdd, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	var resp transport.PasswordGetResponse
	if err := t.Request(ctx, methodPasswordGet, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	var resp transport.PasswordListResponse
	if err := t.Request(ctx, methodPasswordList, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	return t.Request(ctx, methodPasswordUpdate, req, nil)
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return t.Request(ctx, methodPasswordDelete, req, nil)
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return t.Request(ctx, methodPasswordStoreUnlock, req, nil)
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	return t.Request(ctx, methodPasswordStoreLock, nil, nil)
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	var resp transport.PasswordStoreStatusResponse
	if err := t.Request(ctx, methodPasswordStoreStatus, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return ErrNotSupported
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	var resp transport.PasswordGenerateResponse
	if err := t.Request(ctx, methodPasswordGenerate, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Platform Store Operations

// SealStorePut stores a secret in the platform store.
func (t *Transport) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return t.Request(ctx, methodSealStorePut, req, nil)
}

// SealStoreGet retrieves a secret from the platform store.
func (t *Transport) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	var resp transport.SealStoreGetResponse
	if err := t.Request(ctx, methodSealStoreGet, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SealStoreDelete deletes a secret from the platform store.
func (t *Transport) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return t.Request(ctx, methodSealStoreDelete, req, nil)
}

// SealStoreList lists all stored secret names.
func (t *Transport) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	var resp transport.SealStoreListResponse
	if err := t.Request(ctx, methodSealStoreList, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SealStoreReseal reseals a secret with the current sealing key.
func (t *Transport) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return t.Request(ctx, methodSealStoreReseal, req, nil)
}

// SealStoreStatus returns the platform store status.
func (t *Transport) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	var resp transport.SealStoreStatusResponse
	if err := t.Request(ctx, methodSealStoreStatus, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TPM Policy Operations
//
// The USB transport's counterparty is the xkey Android companion app (a
// Noise-encrypted JSON-RPC peer, not xkmsd), and it exposes no TPM: the
// TPM policy surface is unavailable over this transport for that structural
// reason, as the Password/SealStore/Escrow administrative surface is. Serving
// it would need a phone-side (xkey Android) change, outside this repository.

// TPMPolicyCreate creates a named TPM policy. It is not available over USB.
func (t *Transport) TPMPolicyCreate(_ context.Context, _ *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, ErrNotSupported
}

// TPMPolicyGet returns a named TPM policy. It is not available over USB.
func (t *Transport) TPMPolicyGet(_ context.Context, _ *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, ErrNotSupported
}

// TPMPolicyList returns a tenant's TPM policies. It is not available over USB.
func (t *Transport) TPMPolicyList(_ context.Context, _ *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, ErrNotSupported
}

// TPMPolicyUpdate re-captures and re-approves a TPM policy. It is not available over USB.
func (t *Transport) TPMPolicyUpdate(_ context.Context, _ *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, ErrNotSupported
}

// TPMPolicyRevoke withdraws a TPM policy's approval. It is not available over USB.
func (t *Transport) TPMPolicyRevoke(_ context.Context, _ *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, ErrNotSupported
}

// TPMPolicyVerify compares a TPM policy's PCR values with the live ones. It is not available over USB.
func (t *Transport) TPMPolicyVerify(_ context.Context, _ *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, ErrNotSupported
}

// TPMPolicyDelete deletes a TPM policy no object is assigned to. It is not available over USB.
func (t *Transport) TPMPolicyDelete(_ context.Context, _ *transport.TPMPolicyDeleteRequest) error {
	return ErrNotSupported
}

// TPMPolicyObjects lists the objects assigned to a TPM policy. It is not available over USB.
func (t *Transport) TPMPolicyObjects(_ context.Context, _ *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, ErrNotSupported
}

// TPMPolicySetAutoUnseal sets or clears a TPM policy's auto-unseal mark. It is not available over USB.
func (t *Transport) TPMPolicySetAutoUnseal(_ context.Context, _ *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, ErrNotSupported
}

// TPMPolicySetDescription replaces a TPM policy's description. It is not available over USB.
func (t *Transport) TPMPolicySetDescription(_ context.Context, _ *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, ErrNotSupported
}

// TPMObjectPolicy returns the TPM policy a key or sealed object was created under. It is not available over USB.
func (t *Transport) TPMObjectPolicy(_ context.Context, _ *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, ErrNotSupported
}

// TPMPolicyRotateAuthority rotates a tenant's TPM policy authority. It is not available over USB.
func (t *Transport) TPMPolicyRotateAuthority(_ context.Context, _ *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, ErrNotSupported
}

// GetTenantTPMMode returns a tenant's TPM mode. It is not available over USB.
func (t *Transport) GetTenantTPMMode(_ context.Context, _ string) (*transport.TenantTPMModeResponse, error) {
	return nil, ErrNotSupported
}

// SetTenantTPMMode changes a tenant's TPM mode. It is not available over USB.
func (t *Transport) SetTenantTPMMode(_ context.Context, _ *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, ErrNotSupported
}

// TenantVTPMStatus reports a tenant's virtual TPM. It is not available over USB.
func (t *Transport) TenantVTPMStatus(_ context.Context, _ string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, ErrNotSupported
}

// TenantVTPMStart starts a tenant's virtual TPM. It is not available over USB.
func (t *Transport) TenantVTPMStart(_ context.Context, _ string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, ErrNotSupported
}

// TenantVTPMStop stops a tenant's virtual TPM. It is not available over USB.
func (t *Transport) TenantVTPMStop(_ context.Context, _ string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, ErrNotSupported
}

// OIDC Credential Operations
//
// The xkey Android companion app holds no server-side OIDC credentials: the
// API is unavailable over this transport for the structural reason the TPM
// policy surface is. Serving it would need a phone-side (xkey Android)
// change, outside this repository.

// OIDCCredentialCreate creates a server-side OIDC credential. It is not available over USB.
func (t *Transport) OIDCCredentialCreate(_ context.Context, _ *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialImport imports tokens into an OIDC credential. It is not available over USB.
func (t *Transport) OIDCCredentialImport(_ context.Context, _ *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialGet returns an OIDC credential's public view. It is not available over USB.
func (t *Transport) OIDCCredentialGet(_ context.Context, _ *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialList returns the OIDC credentials of a tenant the caller can see. It is not available over USB.
func (t *Transport) OIDCCredentialList(_ context.Context, _ *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialDelete deletes an OIDC credential. It is not available over USB.
func (t *Transport) OIDCCredentialDelete(_ context.Context, _ *transport.OIDCCredentialRef) error {
	return ErrNotSupported
}

// OIDCCredentialRefresh refreshes an OIDC credential now. It is not available over USB.
func (t *Transport) OIDCCredentialRefresh(_ context.Context, _ *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialGetAccessToken returns a current access token of an OIDC credential. It is not available over USB.
func (t *Transport) OIDCCredentialGetAccessToken(_ context.Context, _ *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialDeviceStart starts a device login for an OIDC credential. It is not available over USB.
func (t *Transport) OIDCCredentialDeviceStart(_ context.Context, _ *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, ErrNotSupported
}

// OIDCCredentialDevicePoll polls an OIDC credential's device login once. It is not available over USB.
func (t *Transport) OIDCCredentialDevicePoll(_ context.Context, _ *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, ErrNotSupported
}
