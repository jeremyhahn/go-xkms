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
// for the xkms SDK. It wraps the phone-level USBTransport and Noise XX
// session to present the SDK transport.Transport interface.
//
// This transport communicates directly with an Android phone over USB without
// requiring ADB. The phone acts as a USB accessory; the laptop acts as the
// USB host.
package usb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

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
)

// phoneTransport defines the operations needed from the phone USB layer.
type phoneTransport interface {
	Connect(ctx context.Context) error
	Close() error
	IsConnected() bool
	SendAndReceive(ctx context.Context, message []byte) ([]byte, error)
}

// Transport implements the transport.Transport interface over USB AOA.
// It wraps a phone-level USBTransport with Noise XX encrypted messaging
// and exposes SDK-level Request/Response operations.
type Transport struct {
	config    *transport.Config
	phoneUSB  phoneTransport
	connected bool
	log       *slog.Logger
}

// New creates a new USB transport with the given options.
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

// Connect establishes a USB AOA connection to the phone.
func (t *Transport) Connect(ctx context.Context) error {
	usbCfg := phone.DefaultUSBTransportConfig()
	if t.config.Timeout > 0 {
		usbCfg.OperationTimeout = t.config.Timeout
	}
	usbCfg.Logger = t.log

	usb, err := phone.NewUSBTransport(usbCfg)
	if err != nil {
		return fmt.Errorf("%w: %v", transport.ErrConnectionFailed, err)
	}

	if err := usb.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", transport.ErrConnectionFailed, err)
	}

	t.phoneUSB = usb
	t.connected = true
	t.log.Info("SDK USB transport connected")
	return nil
}

// Close closes the USB connection and releases resources.
func (t *Transport) Close() error {
	if t.phoneUSB != nil {
		if err := t.phoneUSB.Close(); err != nil {
			return err
		}
	}
	t.connected = false
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

// Request performs a unary request/response operation over USB.
// The method parameter is used as the JSON-RPC method name.
// The req parameter is marshalled to JSON and sent as the request payload.
// The resp parameter is unmarshalled from the JSON response payload.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	if !t.connected || t.phoneUSB == nil {
		return ErrNotConnected
	}

	// Marshal request to JSON-RPC format.
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal request: %v", transport.ErrInvalidRequest, err)
	}

	// Send and receive over USB transport.
	respBytes, err := t.phoneUSB.SendAndReceive(ctx, reqBytes)
	if err != nil {
		t.connected = false
		return fmt.Errorf("%w: %v", transport.ErrConnectionFailed, err)
	}

	// Unmarshal response.
	if resp != nil {
		if err := json.Unmarshal(respBytes, resp); err != nil {
			return fmt.Errorf("%w: failed to unmarshal response: %v", transport.ErrInvalidResponse, err)
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
