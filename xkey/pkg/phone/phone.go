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

// Package phone provides a FIDO2 key backend that communicates with
// Android phones via Bluetooth Low Energy (BLE) for hardware-backed
// key storage and cryptographic operations.
//
// The phone backend uses the Noise protocol (XX pattern) for secure
// communication and supports biometric verification on the phone
// before signing operations.
//
// Build with the "ble" tag to enable BLE support:
//
//	go build -tags ble
package phone

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// Backend type constant.
const (
	BackendTypePhone types.BackendType = types.BackendTypePhone
)

// BLE configuration constants.
const (
	// XKeyServiceUUIDString is the string representation of the xKey BLE service UUID.
	XKeyServiceUUIDString = "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0"

	// ControlPointUUIDString is the string representation of the control point characteristic UUID.
	ControlPointUUIDString = "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00001"

	// ResponseUUIDString is the string representation of the response characteristic UUID.
	ResponseUUIDString = "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00002"

	// StatusUUIDString is the string representation of the status characteristic UUID.
	StatusUUIDString = "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00003"

	// DefaultMTU is the default Maximum Transmission Unit for BLE GATT.
	DefaultMTU = 247

	// ScanTimeout is the default timeout for device scanning.
	ScanTimeout = 30 * time.Second

	// ConnectTimeout is the default timeout for connection establishment.
	ConnectTimeout = 10 * time.Second

	// OperationTimeout is the default timeout for operations (includes biometric wait).
	OperationTimeout = 60 * time.Second

	// prologueVersion is the version string appended to prologue computation.
	prologueVersion = "xkey-v1"
)

// PhoneKeyBackendConfig configures the phone key backend.
type PhoneKeyBackendConfig struct {
	// DeviceAddress is the BLE address of the phone to connect to.
	// If empty, will scan for xKey devices.
	DeviceAddress string

	// LocalStaticKey is the persistent local Noise static key.
	// If nil, a new key will be generated.
	LocalStaticKey *noise.DHKey

	// ExpectedRemoteStatic is the expected phone's static public key.
	// If set, connection will fail if the phone's key doesn't match.
	ExpectedRemoteStatic []byte

	// TrustNewDevices allows connecting to devices without a stored expected key.
	// When false (default), connections to unknown devices are rejected.
	// When true, any device can connect (for initial pairing).
	TrustNewDevices bool

	// ExpectedDeviceFingerprint is the expected Android device's attestation fingerprint.
	// This is used in the pre-handshake identity exchange to compute the prologue.
	// If set, the connection will fail if the phone returns a different fingerprint.
	// Should be the SHA-256 of the device's attestation root certificate.
	ExpectedDeviceFingerprint []byte

	// ScanTimeout is the timeout for scanning for devices.
	ScanTimeout time.Duration

	// ConnectTimeout is the timeout for establishing connection.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for individual operations.
	OperationTimeout time.Duration

	// MTU is the preferred BLE MTU.
	MTU int

	// Logger is the structured logger.
	Logger *slog.Logger

	// Notifier receives desktop notifications when biometric approval is pending.
	// If nil, no desktop notifications are shown.
	Notifier notify.Notifier

	// AuditLogger for security audit logging. If nil, no audit logging occurs.
	AuditLogger audit.Logger

	// DeviceName is the human-readable name of this device (for audit logging).
	DeviceName string
}

// DefaultPhoneKeyBackendConfig returns default configuration.
func DefaultPhoneKeyBackendConfig() *PhoneKeyBackendConfig {
	return &PhoneKeyBackendConfig{
		ScanTimeout:      ScanTimeout,
		ConnectTimeout:   ConnectTimeout,
		OperationTimeout: OperationTimeout,
		MTU:              DefaultMTU,
		Logger:           slog.Default(),
	}
}

// phoneKeyHandle holds a reference to a key on the phone.
type phoneKeyHandle struct {
	credentialID []byte
	algorithm    int
}

func (h *phoneKeyHandle) CredentialID() []byte {
	return h.credentialID
}

func (h *phoneKeyHandle) Algorithm() int {
	return h.algorithm
}

// BackendID returns the identifier of the backend that manages this key.
func (h *phoneKeyHandle) BackendID() types.BackendType {
	return BackendTypePhone
}

// PhoneKeyBackend implements FIDO2KeyBackend for phone-based key storage.
type PhoneKeyBackend struct {
	cfg *PhoneKeyBackendConfig
	log *slog.Logger

	mu          sync.RWMutex
	transport   Transport
	session     *NoiseSession
	handles     map[string]*phoneKeyHandle // hex(credentialID) -> handle
	router      *MessageRouter             // nil = unidirectional mode
	notifier    notify.Notifier
	auditLogger audit.Logger

	connected atomic.Bool
	closed    atomic.Bool
}

// computePrologue computes the Noise prologue for trusted device binding.
// The prologue binds the handshake to expected device fingerprints.
// Both sides must use the same prologue or the handshake fails.
// For new/unknown devices, returns nil to allow pairing.
//
// IMPORTANT: The key order is always initiator || responder to ensure both
// sides compute the same hash. Go is always the initiator, Android is always
// the responder. Since this function is called from the Go (initiator) side,
// local = initiator and remote = responder.
func computePrologue(localPublicKeyHex, expectedRemotePublicKeyHex string) []byte {
	if expectedRemotePublicKeyHex == "" {
		return nil // Empty prologue for new device pairing
	}

	// Build prologue: SHA-256(initiator_key || responder_key || version)
	// Go is initiator (local), Android is responder (remote)
	h := sha256.New()
	h.Write([]byte(localPublicKeyHex))          // initiator (Go)
	h.Write([]byte(expectedRemotePublicKeyHex)) // responder (Android)
	h.Write([]byte(prologueVersion))
	return h.Sum(nil)
}

// NewPhoneKeyBackend creates a new phone key backend using BLE transport.
// On platforms without BLE support (built without the "ble" tag), this
// returns ErrBLEUnavailable.
func NewPhoneKeyBackend(cfg *PhoneKeyBackendConfig) (*PhoneKeyBackend, error) {
	if cfg == nil {
		cfg = DefaultPhoneKeyBackendConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Create BLE transport
	transport, err := NewBLETransport(&BLETransportConfig{
		DeviceAddress:    cfg.DeviceAddress,
		ScanTimeout:      cfg.ScanTimeout,
		ConnectTimeout:   cfg.ConnectTimeout,
		OperationTimeout: cfg.OperationTimeout,
		MTU:              cfg.MTU,
		Logger:           cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	return newPhoneKeyBackend(cfg, transport)
}

// NewPhoneKeyBackendWithTransport creates a new phone key backend with a
// pre-configured transport. This allows using any Transport implementation
// (BLE, TCP, or custom) as the communication layer. The caller is responsible
// for establishing the transport-level connection before calling Connect()
// on non-BLE transports.
func NewPhoneKeyBackendWithTransport(cfg *PhoneKeyBackendConfig, transport Transport) (*PhoneKeyBackend, error) {
	if cfg == nil {
		cfg = DefaultPhoneKeyBackendConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if transport == nil {
		return nil, ErrNotConnected
	}

	return newPhoneKeyBackend(cfg, transport)
}

// newPhoneKeyBackend is the internal constructor shared by both public
// constructors. It initializes the Noise session and assembles the backend.
func newPhoneKeyBackend(cfg *PhoneKeyBackendConfig, transport Transport) (*PhoneKeyBackend, error) {
	// Validate trust settings: if no expected remote key and trust-new-devices is false,
	// reject the connection to prevent connecting to unknown devices.
	if len(cfg.ExpectedRemoteStatic) == 0 && !cfg.TrustNewDevices {
		transport.Close()
		return nil, ErrUntrustedDevice
	}

	// Create Noise session with empty prologue initially.
	// The prologue will be set during the pre-handshake identity exchange
	// in performHandshake, which sends our public key to Android and receives
	// the device's attestation fingerprint. This enables trusted device binding
	// for reconnections while allowing empty prologue for initial pairing.
	session, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey:       cfg.LocalStaticKey,
		ExpectedRemoteStatic: cfg.ExpectedRemoteStatic,
		IsInitiator:          true,
		Prologue:             nil, // Set during identity exchange
	})
	if err != nil {
		transport.Close()
		return nil, err
	}

	return &PhoneKeyBackend{
		cfg:         cfg,
		log:         cfg.Logger.With("component", "phone_backend"),
		transport:   transport,
		session:     session,
		handles:     make(map[string]*phoneKeyHandle),
		notifier:    cfg.Notifier,
		auditLogger: cfg.AuditLogger,
	}, nil
}

// Type returns the backend type.
func (b *PhoneKeyBackend) Type() types.BackendType {
	return BackendTypePhone
}

// Capabilities returns the backend capabilities.
func (b *PhoneKeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{COSEAlgES256, COSEAlgES384, COSEAlgES512},
		SupportsExport:          false, // Keys never leave the phone's secure element
		SupportsImport:          false, // Cannot import keys to phone
		SupportsAttestation:     false, // Phone provides its own attestation
		HardwareBacked:          true,  // Phone uses hardware secure element
		HandlesUserPresence:     true,  // Phone biometric IS the user presence check
		HandlesUserVerification: true,  // Phone biometric IS the user verification
		// The phone prompts for biometric during Sign/GenerateKey operations.
		// This serves as both user presence (UP) and user verification (UV).
		// No separate desktop notification needed - similar to YubiKey where
		// the touch is the only user interaction required.
	}
}

// Connect establishes a connection to the phone.
// For BLE transports, this includes scanning, connecting, and performing the
// Noise handshake with automatic retry logic for BlueZ D-Bus issues.
// For non-BLE transports (e.g., TCP), the transport should already be
// connected at the network level; Connect performs only the Noise handshake.
func (b *PhoneKeyBackend) Connect(ctx context.Context) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}
	if b.connected.Load() {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if the transport supports BLE-specific operations.
	bleTransport, isBLE := b.transport.(BLECapableTransport)
	if isBLE {
		return b.connectBLE(ctx, bleTransport)
	}

	// Non-BLE transport (e.g., TCP): the transport is already connected
	// at the network level. Perform only the Noise handshake.
	if err := b.performHandshake(ctx); err != nil {
		return err
	}

	b.connected.Store(true)
	b.log.Info("connected to phone via transport")

	// Log connection established
	if b.auditLogger != nil {
		b.auditLogger.LogConnectionEvent(
			audit.OpConnectionEstablished,
			b.cfg.DeviceAddress,
			b.cfg.DeviceName,
			map[string]any{
				"transport": "non-ble",
			},
		)
	}

	return nil
}

// connectBLE performs the BLE-specific connection flow including scanning,
// connecting, and Noise handshake with retry logic for BlueZ D-Bus issues.
func (b *PhoneKeyBackend) connectBLE(ctx context.Context, bleTransport BLECapableTransport) error {
	// Pre-emptive cleanup: remove stale BlueZ cache entries for the saved address.
	// The phone's public address (e.g., A4:75:B9:8D:78:DD) often has cached classic
	// Bluetooth SDP records that create broken D-Bus objects for BLE connections.
	// Removing it before scanning forces BlueZ to discover the phone at its clean
	// BLE RPA address instead.
	if b.cfg.DeviceAddress != "" {
		bleTransport.CleanStaleBlueZEntry(b.cfg.DeviceAddress)
	}

	// Retry loop for handling BlueZ D-Bus issues.
	// D-Bus stale object errors require removing the device and re-scanning,
	// so we allow up to 3 attempts (initial + 2 retries after stale removal).
	const maxRetries = 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			b.log.Info("retrying connection after BlueZ cleanup", "attempt", attempt)
		}

		address, err := b.scanForDevice(ctx, bleTransport)
		if err != nil {
			lastErr = err
			continue
		}

		// Connect to device
		// Pass the bonded address (from pairing config) so BlueZ can use IRK resolution
		// when Android has rotated its RPA to a different address
		if err := bleTransport.ConnectWithBondedAddress(ctx, address, b.cfg.DeviceAddress); err != nil {
			b.log.Warn("connection failed", "address", address, "error", err, "attempt", attempt)
			lastErr = err

			// ErrDBusStaleObject means the device was removed from BlueZ.
			// A fresh scan should find the device at a new address.
			if errors.Is(err, ErrDBusStaleObject) {
				b.log.Info("stale D-Bus object removed, will re-scan for device")
				if attempt < maxRetries {
					continue
				}
				return err
			}

			// Other errors: force-remove and retry with fresh scan
			// Force-remove to clear stale D-Bus state from failed connection
			if attempt < maxRetries {
				bleTransport.DisconnectAndRemove()
				b.log.Info("will retry with fresh scan after disconnect")
				continue
			}
			return err
		}

		// Perform Noise handshake (this verifies the phone's static key if ExpectedRemoteStatic is set)
		if err := b.performHandshake(ctx); err != nil {
			b.log.Warn("handshake failed", "address", address, "error", err, "attempt", attempt)

			// Use DisconnectAndRemove to force-remove the device from BlueZ.
			// This is critical: a timed-out BLE write goroutine can leave a pending
			// D-Bus operation that blocks all future writes with "In Progress".
			// Removing the device from BlueZ invalidates all cached GATT handles
			// and stale D-Bus state, allowing a fresh connection with clean objects.
			bleTransport.DisconnectAndRemove()
			lastErr = err

			if attempt < maxRetries {
				b.log.Info("will retry with fresh scan after handshake failure")
				continue
			}
			return err
		}

		// Success!
		b.connected.Store(true)
		b.log.Info("connected to phone", "address", address)

		// Log connection established
		if b.auditLogger != nil {
			b.auditLogger.LogConnectionEvent(
				audit.OpConnectionEstablished,
				address,
				b.cfg.DeviceName,
				map[string]any{
					"transport": "ble",
					"mtu":       b.cfg.MTU,
				},
			)
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return ErrConnectionFailed
}

// scanForDevice scans for a xKey device and returns its current BLE address.
func (b *PhoneKeyBackend) scanForDevice(ctx context.Context, bleTransport BLECapableTransport) (string, error) {
	// Android uses random resolvable private addresses that change periodically.
	// Always scan to find the current address, even if we have a saved address.
	// The Noise static key (ExpectedRemoteStatic) is used to verify identity.
	b.log.Debug("scanning for xKey devices")
	devices, err := bleTransport.Scan(ctx)
	if err != nil {
		// If scan fails but we have a saved address, try direct connection as fallback
		if b.cfg.DeviceAddress != "" {
			b.log.Warn("scan failed, trying direct connection to saved address",
				"address", b.cfg.DeviceAddress,
				"scan_error", err)
			return b.cfg.DeviceAddress, nil
		}
		return "", err
	}

	if len(devices) == 0 {
		// No devices found via scan, try saved address as fallback
		if b.cfg.DeviceAddress != "" {
			b.log.Warn("no devices found via scan, trying saved address",
				"address", b.cfg.DeviceAddress)
			return b.cfg.DeviceAddress, nil
		}
		return "", ErrDeviceNotFound
	}

	// Use the first found device (scan found it advertising the xKey service)
	address := devices[0].Address
	b.log.Info("found xKey device via scan",
		"address", address,
		"name", devices[0].LocalName)
	return address, nil
}

// performHandshake executes the Noise XX handshake using the centralized implementation.
// It includes a pre-handshake identity exchange to enable prologue binding for trusted
// device verification.
func (b *PhoneKeyBackend) performHandshake(ctx context.Context) error {
	cfg := &HandshakeConfig{
		Transport:           b.transport,
		Session:             b.session,
		Logger:              b.log,
		StripEnvelopeHeader: false, // Android sends raw Noise messages, no envelope
		EnvelopeHeaderSize:  0,
		// Identity exchange for prologue binding
		LocalStaticPublicKey:      b.session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: b.cfg.ExpectedDeviceFingerprint,
	}
	return PerformHandshake(ctx, cfg)
}

// EnableBidirectional starts bidirectional JSON-RPC routing using the
// provided request handler (typically a Bridge). This must be called
// after Connect() completes successfully. When enabled, SendRequest
// uses the MessageRouter instead of direct SendAndReceive.
func (b *PhoneKeyBackend) EnableBidirectional(handler RequestHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.router = NewMessageRouter(b.transport, b.session, handler, b.log)
	b.router.Start()
	b.log.Info("bidirectional message routing enabled")
}

// SendRequest sends an encrypted request and receives the decrypted response.
func (b *PhoneKeyBackend) SendRequest(ctx context.Context, req *Request) (*Response, error) {
	if !b.connected.Load() {
		b.log.Error("SendRequest called but not connected")
		return nil, ErrNotConnected
	}

	// If a MessageRouter is active, delegate to it for bidirectional routing.
	b.mu.RLock()
	router := b.router
	b.mu.RUnlock()
	if router != nil {
		return router.SendRequest(ctx, req)
	}

	b.log.Debug("SendRequest starting",
		"method", req.Method,
		"id", req.ID,
	)

	// Encode request
	plaintext, err := EncodeRequest(req)
	if err != nil {
		b.log.Error("failed to encode request", "error", err)
		return nil, ErrProtocolError
	}
	b.log.Debug("request encoded", "plaintext_len", len(plaintext))

	// Encrypt
	ciphertext, err := b.session.Encrypt(plaintext)
	if err != nil {
		b.log.Error("failed to encrypt request", "error", err)
		return nil, err
	}
	b.log.Debug("request encrypted", "ciphertext_len", len(ciphertext))

	// Send and receive
	b.log.Debug("sending request to phone...")
	responseCiphertext, err := b.transport.SendAndReceive(ctx, ciphertext)
	if err != nil {
		b.log.Error("SendAndReceive failed", "error", err)
		return nil, err
	}
	b.log.Debug("received response from phone", "ciphertext_len", len(responseCiphertext))

	// Decrypt
	responsePlaintext, err := b.session.Decrypt(responseCiphertext)
	if err != nil {
		b.log.Error("failed to decrypt response", "error", err)
		return nil, err
	}
	b.log.Debug("response decrypted", "plaintext_len", len(responsePlaintext))

	// Decode response
	resp, err := DecodeResponse(responsePlaintext)
	if err != nil {
		b.log.Error("failed to decode response", "error", err)
		return nil, ErrInvalidResponse
	}

	b.log.Debug("SendRequest completed",
		"method", req.Method,
		"has_error", resp.Error != nil,
	)

	return resp, nil
}

// GenerateCredentialKey creates a new key pair on the phone.
func (b *PhoneKeyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	if b.closed.Load() {
		return nil, nil, ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, nil, ErrInvalidCredentialID
	}

	// Validate algorithm
	if !b.isAlgorithmSupported(algorithm) {
		return nil, nil, ErrUnsupportedAlgorithm
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.OperationTimeout)
	defer cancel()

	// Ensure connected
	if !b.connected.Load() {
		if err := b.Connect(ctx); err != nil {
			return nil, nil, err
		}
	}

	// Send generate request
	// Always require biometric for key generation - this is a sensitive operation
	req := NewRequest(MethodGenerateKey, &GenerateKeyParams{
		CredentialID:             credentialID,
		Algorithm:                algorithm,
		UserVerificationRequired: true,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	if resp.Error != nil {
		b.log.Error("GenerateCredentialKey: phone returned error",
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message,
			"error_data", resp.Error.Data)
		return nil, nil, MapRPCError(resp.Error)
	}

	// Decode result
	result, err := DecodeResult[GenerateKeyResult](resp)
	if err != nil {
		return nil, nil, ErrInvalidResponse
	}

	// Create and store handle
	handle := &phoneKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
	}

	b.mu.Lock()
	b.handles[hex.EncodeToString(credentialID)] = handle
	b.mu.Unlock()

	b.log.Debug("key generation completed with biometric verification")
	return handle, result.PublicKeyCOSE, nil
}

// Sign creates a signature using a key on the phone.
// This always triggers biometric verification on the phone because Android Keystore
// with biometric binding requires biometric auth for every key use.
func (b *PhoneKeyBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	phoneHandle, ok := handle.(*phoneKeyHandle)
	if !ok {
		return nil, ErrInvalidKeyHandle
	}

	credIDHex := hex.EncodeToString(phoneHandle.credentialID)

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.OperationTimeout)
	defer cancel()

	// Ensure connected
	if !b.connected.Load() {
		b.log.Debug("Sign: not connected, attempting to connect")
		if err := b.Connect(ctx); err != nil {
			b.log.Error("Sign: connection failed", "error", err)
			return nil, err
		}
	}

	// Send sign request
	// Note: data is the hash to sign (authenticator data + client data hash)
	// UserVerificationRequired must always be true because Android Keystore
	// with biometric binding requires biometric auth for every key operation.
	// Attempting to sign without biometric will result in a crypto error.
	b.log.Debug("Sign: sending request to phone",
		"credential_id", credIDHex[:16],
		"data_hash_len", len(data))
	req := NewRequest(MethodSign, &SignParams{
		CredentialID:             phoneHandle.credentialID,
		DataHash:                 data,
		UserVerificationRequired: true,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		b.log.Error("Sign: request failed", "credential_id", credIDHex[:16], "error", err)
		return nil, err
	}

	if resp.Error != nil {
		b.log.Error("Sign: phone returned error",
			"credential_id", credIDHex[:16],
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message,
			"error_data", resp.Error.Data)
		return nil, MapRPCError(resp.Error)
	}

	// Decode result
	result, err := DecodeResult[SignResult](resp)
	if err != nil {
		b.log.Error("Sign: failed to decode result", "error", err)
		return nil, ErrInvalidResponse
	}

	b.log.Debug("Sign: completed with biometric verification",
		"credential_id", credIDHex[:16],
		"signature_len", len(result.Signature))
	return result.Signature, nil
}

// LoadKey verifies a key exists on the phone.
func (b *PhoneKeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if len(credentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}

	credIDHex := hex.EncodeToString(credentialID)

	// Check local cache first
	b.mu.RLock()
	if handle, ok := b.handles[credIDHex]; ok {
		b.mu.RUnlock()
		if handle.algorithm != algorithm {
			return nil, ErrUnsupportedAlgorithm
		}
		b.log.Debug("LoadKey: found in local cache", "credential_id", credIDHex[:16])
		return handle, nil
	}
	b.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.OperationTimeout)
	defer cancel()

	// Ensure connected
	if !b.connected.Load() {
		b.log.Debug("LoadKey: not connected, attempting to connect")
		if err := b.Connect(ctx); err != nil {
			b.log.Error("LoadKey: connection failed", "error", err)
			return nil, err
		}
	}

	// Send load request to verify key exists
	b.log.Debug("LoadKey: sending request to phone", "credential_id", credIDHex[:16])
	req := NewRequest(MethodLoadKey, &LoadKeyParams{
		CredentialID: credentialID,
		Algorithm:    algorithm,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		b.log.Error("LoadKey: request failed", "credential_id", credIDHex[:16], "error", err)
		return nil, err
	}

	if resp.Error != nil {
		b.log.Error("LoadKey: phone returned error",
			"credential_id", credIDHex[:16],
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message,
			"error_data", resp.Error.Data)
		return nil, MapRPCError(resp.Error)
	}

	// Decode result
	result, err := DecodeResult[LoadKeyResult](resp)
	if err != nil {
		b.log.Error("LoadKey: failed to decode result", "error", err)
		return nil, ErrInvalidResponse
	}

	if !result.Exists {
		b.log.Error("LoadKey: key does not exist on phone", "credential_id", credIDHex[:16])
		return nil, ErrKeyNotFound
	}

	// Create and cache handle
	handle := &phoneKeyHandle{
		credentialID: credentialID,
		algorithm:    algorithm,
	}

	b.mu.Lock()
	b.handles[credIDHex] = handle
	b.mu.Unlock()

	b.log.Debug("LoadKey: key verified and cached", "credential_id", credIDHex[:16])
	return handle, nil
}

// DeleteKey removes a key from the phone.
func (b *PhoneKeyBackend) DeleteKey(handle keybackend.KeyHandle) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	phoneHandle, ok := handle.(*phoneKeyHandle)
	if !ok {
		return ErrInvalidKeyHandle
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.OperationTimeout)
	defer cancel()

	// Ensure connected
	if !b.connected.Load() {
		if err := b.Connect(ctx); err != nil {
			return err
		}
	}

	// Send delete request
	req := NewRequest(MethodDeleteKey, &DeleteKeyParams{
		CredentialID: phoneHandle.credentialID,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return MapRPCError(resp.Error)
	}

	// Remove from local cache
	b.mu.Lock()
	delete(b.handles, hex.EncodeToString(phoneHandle.credentialID))
	b.mu.Unlock()

	return nil
}

// ExportPrivateKey is not supported for phone backend.
func (b *PhoneKeyBackend) ExportPrivateKey(handle keybackend.KeyHandle) ([]byte, error) {
	return nil, ErrExportNotSupported
}

// ImportPrivateKey is not supported for phone backend.
func (b *PhoneKeyBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (keybackend.KeyHandle, error) {
	return nil, ErrImportNotSupported
}

// Close closes the backend and releases resources.
func (b *PhoneKeyBackend) Close() error {
	if b.closed.Swap(true) {
		return nil // Already closed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Log connection closed before actually closing
	if b.auditLogger != nil && b.connected.Load() {
		b.auditLogger.LogConnectionEvent(
			audit.OpConnectionClosed,
			b.cfg.DeviceAddress,
			b.cfg.DeviceName,
			nil,
		)
	}

	b.connected.Store(false)
	b.handles = nil

	// Stop the message router if running.
	if b.router != nil {
		b.router.Stop()
		b.router = nil
	}

	if b.transport != nil {
		b.transport.Close()
		b.transport = nil
	}

	b.log.Info("phone backend closed")
	return nil
}

// isAlgorithmSupported checks if the algorithm is supported.
func (b *PhoneKeyBackend) isAlgorithmSupported(algorithm int) bool {
	switch algorithm {
	case COSEAlgES256, COSEAlgES384, COSEAlgES512:
		return true
	default:
		return false
	}
}

// IsConnected returns true if connected to a phone.
func (b *PhoneKeyBackend) IsConnected() bool {
	return b.connected.Load()
}

// ConnectedAddress returns the BLE address of the currently connected phone.
// This may differ from the configured DeviceAddress if Android rotated its RPA.
// Returns empty string if not connected or if the transport does not support
// BLE addressing.
// Callers should use this to update their saved configuration if the address changed.
func (b *PhoneKeyBackend) ConnectedAddress() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if bleTransport, ok := b.transport.(BLECapableTransport); ok {
		return bleTransport.ConnectedAddress()
	}
	return ""
}

// LocalStaticPublicKey returns the local Noise static public key.
func (b *PhoneKeyBackend) LocalStaticPublicKey() []byte {
	if b.session == nil {
		return nil
	}
	return b.session.LocalStaticPublicKey()
}

// RemoteStaticPublicKey returns the phone's Noise static public key.
func (b *PhoneKeyBackend) RemoteStaticPublicKey() []byte {
	if b.session == nil {
		return nil
	}
	return b.session.RemoteStaticPublicKey()
}

// GetDeviceInfo retrieves information about the connected phone.
func (b *PhoneKeyBackend) GetDeviceInfo(ctx context.Context) (*GetInfoResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	if !b.connected.Load() {
		if err := b.Connect(ctx); err != nil {
			return nil, err
		}
	}

	req := NewRequest(MethodGetInfo, nil)

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, MapRPCError(resp.Error)
	}

	return DecodeResult[GetInfoResult](resp)
}

// Ping sends a ping to verify the connection is alive.
func (b *PhoneKeyBackend) Ping(ctx context.Context) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	if !b.connected.Load() {
		return ErrNotConnected
	}

	req := NewRequest(MethodPing, nil)

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return MapRPCError(resp.Error)
	}

	result, err := DecodeResult[PingResult](resp)
	if err != nil {
		return ErrInvalidResponse
	}

	if !result.Pong {
		return ErrProtocolError
	}

	return nil
}

// SendPairingConfirm sends a pairing confirmation request to the phone.
// This should be called after the Noise handshake completes during pairing.
// The phone will prompt the user to confirm the pairing. If the user rejects,
// ErrPairingRejected is returned.
func (b *PhoneKeyBackend) SendPairingConfirm(ctx context.Context, deviceName string) (*PairingConfirmResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !b.connected.Load() {
		return nil, ErrNotConnected
	}

	publicKeyHex := hex.EncodeToString(b.LocalStaticPublicKey())

	req := NewRequest(MethodPairingConfirm, &PairingConfirmParams{
		DeviceName:   deviceName,
		PublicKeyHex: publicKeyHex,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		// Log pairing denied
		if b.auditLogger != nil {
			b.auditLogger.LogConnectionEvent(
				audit.OpPairingDenied,
				b.cfg.DeviceAddress,
				b.cfg.DeviceName,
				map[string]any{
					"reason": resp.Error.Message,
				},
			)
		}
		return nil, MapRPCError(resp.Error)
	}

	result, err := DecodeResult[PairingConfirmResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	if !result.Confirmed {
		// Log pairing denied
		if b.auditLogger != nil {
			b.auditLogger.LogConnectionEvent(
				audit.OpPairingDenied,
				b.cfg.DeviceAddress,
				b.cfg.DeviceName,
				map[string]any{
					"reason": "user rejected",
				},
			)
		}
		return nil, ErrPairingRejected
	}

	// Log pairing approved
	if b.auditLogger != nil {
		b.auditLogger.LogConnectionEvent(
			audit.OpPairingApproved,
			b.cfg.DeviceAddress,
			result.DeviceName,
			nil,
		)
	}

	return result, nil
}

// ListFido2Credentials lists shareable FIDO2 credentials on the phone for a
// given relying party. This enables credential discovery for cross-device
// authentication flows where the laptop needs to know which credentials
// are available on the phone for a specific relying party.
func (b *PhoneKeyBackend) ListFido2Credentials(ctx context.Context, rpID string) ([]Fido2CredentialInfo, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if rpID == "" {
		return nil, ErrInvalidRpID
	}

	if !b.connected.Load() {
		if err := b.Connect(ctx); err != nil {
			return nil, err
		}
	}

	req := NewRequest(MethodLocalListFido2Credentials, &LocalListFido2CredentialsParams{
		RpID: rpID,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		b.log.Error("ListFido2Credentials: request failed", "rp_id", rpID, "error", err)
		return nil, err
	}

	if resp.Error != nil {
		b.log.Error("ListFido2Credentials: phone returned error",
			"rp_id", rpID,
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message)
		return nil, MapRPCError(resp.Error)
	}

	result, err := DecodeResult[LocalListFido2CredentialsResult](resp)
	if err != nil {
		b.log.Error("ListFido2Credentials: failed to decode result", "error", err)
		return nil, ErrInvalidResponse
	}

	b.log.Debug("ListFido2Credentials: completed",
		"rp_id", rpID,
		"credential_count", len(result.Credentials))
	return result.Credentials, nil
}

// SignFido2Assertion signs a FIDO2 assertion using a credential on the phone.
// This is used for cross-device authentication flows where the phone acts as
// a FIDO2 authenticator for the laptop. The phone will prompt for biometric
// verification before signing.
func (b *PhoneKeyBackend) SignFido2Assertion(ctx context.Context, params *LocalSignFido2AssertionParams) (*LocalSignFido2AssertionResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if params == nil {
		return nil, ErrInvalidCredentialID
	}
	if len(params.CredentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}
	if len(params.ClientDataHash) == 0 {
		return nil, ErrInvalidClientDataHash
	}
	if params.RpID == "" {
		return nil, ErrInvalidRpID
	}

	if !b.connected.Load() {
		if err := b.Connect(ctx); err != nil {
			return nil, err
		}
	}

	credIDHex := hex.EncodeToString(params.CredentialID)

	req := NewRequest(MethodLocalSignFido2Assertion, params)

	b.log.Debug("SignFido2Assertion: sending request to phone",
		"credential_id", credIDHex,
		"rp_id", params.RpID)

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		b.log.Error("SignFido2Assertion: request failed",
			"credential_id", credIDHex,
			"error", err)
		return nil, err
	}

	if resp.Error != nil {
		b.log.Error("SignFido2Assertion: phone returned error",
			"credential_id", credIDHex,
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message)
		return nil, MapRPCError(resp.Error)
	}

	result, err := DecodeResult[LocalSignFido2AssertionResult](resp)
	if err != nil {
		b.log.Error("SignFido2Assertion: failed to decode result", "error", err)
		return nil, ErrInvalidResponse
	}

	b.log.Debug("SignFido2Assertion: completed",
		"credential_id", credIDHex,
		"rp_id", params.RpID,
		"sign_count", result.SignCount)
	return result, nil
}

// Notifier returns the configured notifier, or nil if none is set.
func (b *PhoneKeyBackend) Notifier() notify.Notifier {
	return b.notifier
}

// Ensure PhoneKeyBackend implements FIDO2KeyBackend.
var _ keybackend.FIDO2KeyBackend = (*PhoneKeyBackend)(nil)
