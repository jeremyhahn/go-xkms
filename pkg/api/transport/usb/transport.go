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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

var (
	// ErrNotConnected is returned when the USB transport is not connected.
	ErrNotConnected = errors.New("usb transport: not connected")

	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = errors.New("operation not supported by this protocol")

	// ErrStreamNotSupported is returned when streaming is requested.
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
	config    *transport.Config
	noise     *NoiseConfig
	phoneUSB  phoneTransport
	session   *phone.NoiseSession
	connected bool
	log       *slog.Logger

	// localKey is the protected static key backing session. The session reads
	// its pages in place, so Connect keeps it here and Close releases it;
	// dropping it on the floor would leave a locked, unswappable page
	// resident for every connection the process ever makes.
	localKey *phone.StaticKey

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

// WithNoiseConfig attaches the pairing key material used by Connect. It
// returns the transport so it can be chained onto a constructor.
func (t *Transport) WithNoiseConfig(cfg *NoiseConfig) *Transport {
	t.noise = cfg
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

	if t.noise == nil || len(t.noise.LocalStaticPrivateKey) == 0 {
		return ErrNoiseNotConfigured
	}

	localKey, err := phone.LoadStaticKey(t.noise.LocalStaticPrivateKey)
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

	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: t.noise.ExpectedRemoteStatic,
		IsInitiator:          true,
	})
	if err != nil {
		t.discardPhoneUSB()
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("noise session: %v", err)}
	}

	// The identity exchange runs on every connection: the phone's stream
	// responder always expects it, and it binds the phone's attestation
	// fingerprint into the prologue.
	if err := phone.PerformHandshake(ctx, &phone.HandshakeConfig{
		Transport:                 t.phoneUSB,
		Session:                   session,
		Logger:                    t.log,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: t.noise.ExpectedDeviceFingerprint,
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

	if usb != nil {
		_ = usb.Close()
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
	plaintext, err := phone.EncodeRequest(phone.NewRequest(method, req))
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

	rpcResp, err := phone.DecodeResponse(responsePlaintext)
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

// RequestStream returns ErrStreamNotSupported since USB AOA does not
// support bidirectional streaming.
func (t *Transport) RequestStream(_ context.Context, _ string, _ interface{}) (transport.Stream, error) {
	return nil, ErrStreamNotSupported
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(_ context.Context, _ *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, ErrNotSupported
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(_ context.Context, _ *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, ErrNotSupported
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(_ context.Context, _ *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, ErrNotSupported
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(_ context.Context, _ *transport.PasswordUpdateRequest) error {
	return ErrNotSupported
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(_ context.Context, _ *transport.PasswordDeleteRequest) error {
	return ErrNotSupported
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(_ context.Context, _ *transport.PasswordStoreUnlockRequest) error {
	return ErrNotSupported
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(_ context.Context) error {
	return ErrNotSupported
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, ErrNotSupported
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return ErrNotSupported
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(_ context.Context, _ *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, ErrNotSupported
}

// Platform Store Operations

// SealStorePut stores a secret in the platform store.
func (t *Transport) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	return ErrNotSupported
}

// SealStoreGet retrieves a secret from the platform store.
func (t *Transport) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, ErrNotSupported
}

// SealStoreDelete deletes a secret from the platform store.
func (t *Transport) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	return ErrNotSupported
}

// SealStoreList lists all stored secret names.
func (t *Transport) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return nil, ErrNotSupported
}

// SealStoreReseal reseals a secret with the current sealing key.
func (t *Transport) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	return ErrNotSupported
}

// SealStoreStatus returns the platform store status.
func (t *Transport) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, ErrNotSupported
}

// Policy Operations

// PolicyCreate creates a new PCR policy.
func (t *Transport) PolicyCreate(_ context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, ErrNotSupported
}

// PolicyGet retrieves a policy by name.
func (t *Transport) PolicyGet(_ context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, ErrNotSupported
}

// PolicyList lists all policies.
func (t *Transport) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return nil, ErrNotSupported
}

// PolicyDelete deletes a policy.
func (t *Transport) PolicyDelete(_ context.Context, _ *transport.PolicyDeleteRequest) error {
	return ErrNotSupported
}

// PolicyRefresh refreshes a policy with current PCR values.
func (t *Transport) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, ErrNotSupported
}

// PolicyVerify verifies a policy against current PCR values.
func (t *Transport) PolicyVerify(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, ErrNotSupported
}

// PolicyExport exports a policy.
func (t *Transport) PolicyExport(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, ErrNotSupported
}
