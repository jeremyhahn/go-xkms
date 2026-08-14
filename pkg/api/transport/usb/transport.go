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

	// mu serializes requests. A Noise cipherstate advances a monotonic nonce
	// per message, so concurrent senders would put frames on the wire out of
	// nonce order and the phone would reject them.
	mu sync.Mutex
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
	if t.noise == nil || len(t.noise.LocalStaticPrivateKey) == 0 {
		return ErrNoiseNotConfigured
	}

	localKey, err := phone.LoadStaticKey(t.noise.LocalStaticPrivateKey)
	if err != nil {
		return &errs.Detail{Err: ErrNoiseNotConfigured, Detail: fmt.Sprintf("%v", err)}
	}

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
		t.phoneUSB = usb
	}

	if err := t.phoneUSB.Connect(ctx); err != nil {
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("%v", err)}
	}

	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: t.noise.ExpectedRemoteStatic,
		IsInitiator:          true,
	})
	if err != nil {
		_ = t.phoneUSB.Close()
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
		_ = t.phoneUSB.Close()
		return &errs.Detail{Err: transport.ErrConnectionFailed, Detail: fmt.Sprintf("noise handshake: %v", err)}
	}

	t.session = session
	t.connected = true
	t.log.Info("SDK USB transport connected")
	return nil
}

// Close closes the USB connection and releases resources.
func (t *Transport) Close() error {
	t.connected = false
	t.session = nil
	if t.phoneUSB != nil {
		if err := t.phoneUSB.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Healthy checks if the USB connection is active.
func (t *Transport) Healthy(_ context.Context) bool {
	return t.connected && t.phoneUSB != nil && t.phoneUSB.IsConnected()
}

// Conn returns the underlying phone USB transport.
func (t *Transport) Conn() interface{} {
	return t.phoneUSB
}

// Request performs a unary request/response operation over the encrypted USB
// channel. The method parameter becomes the JSON-RPC method name and req its
// params; the JSON-RPC result is unmarshalled into resp.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	if !t.connected || t.phoneUSB == nil || t.session == nil {
		return ErrNotConnected
	}

	plaintext, err := phone.EncodeRequest(phone.NewRequest(method, req))
	if err != nil {
		return &errs.Detail{Err: transport.ErrInvalidRequest, Detail: fmt.Sprintf("failed to marshal request: %v", err)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	ciphertext, err := t.session.Encrypt(plaintext)
	if err != nil {
		return &errs.Detail{Err: transport.ErrInvalidRequest, Detail: fmt.Sprintf("failed to encrypt request: %v", err)}
	}

	responseCiphertext, err := t.phoneUSB.SendAndReceive(ctx, ciphertext)
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
