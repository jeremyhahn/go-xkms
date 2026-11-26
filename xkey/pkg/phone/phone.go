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
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/keybackend"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/internal/lifecycle"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Backend type constant.
const (
	BackendTypePhone xkms.BackendType = xkms.BackendTypePhone
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
)

// PhoneKeyBackendConfig configures the phone key backend.
type PhoneKeyBackendConfig struct {
	// DeviceAddress is the BLE address of the phone to connect to.
	// If empty, will scan for xKey devices.
	DeviceAddress string

	// LocalStaticKey is the persistent local Noise static key, held in
	// protected memory. If nil, the constructor generates one and sets
	// OwnsStaticKey, so the backend always holds a key it can release.
	LocalStaticKey *bootstrap.NoiseStaticKey

	// OwnsStaticKey transfers ownership of LocalStaticKey to the backend, so
	// that Close destroys it. Set it when the key has no other owner — a
	// helper that builds a backend and hands it to a caller has nowhere else
	// to keep the key, and the protected pages would otherwise stay resident
	// for the life of the process. Leave it false when the caller keeps the
	// key: destroying a borrowed key frees pages another session may still be
	// reading.
	OwnsStaticKey bool

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

	// RequireLiveAttestation makes the #129 challenge-response proof mandatory
	// on this connection: after the Noise handshake, the peer must present its
	// attestation chain and sign a fresh challenge with the attested key, or
	// the connection is refused.
	//
	// Set it from the pairing record's attestation protocol version. It is a
	// separate field from LiveAttest, rather than "enforce if a verifier is
	// set", so that FORGETTING to wire the verifier is a refusal instead of a
	// silently skipped check. A security control that fails open on a caller's
	// omission is one omission away from being absent — the same defect
	// PerformHandshake's identity-exchange switch was fixed for.
	RequireLiveAttestation bool

	// LiveAttest performs the challenge-response exchange and judges the
	// answer. It is injected because the decision needs trust material and a
	// pairing record, neither of which this package knows about: pkg/phone
	// carries the transport and the session, not policy.
	//
	// exchange runs one encrypted JSON-RPC round trip over the session just
	// established; channelBinding is that session's attestation channel
	// binding.
	LiveAttest pairingproto.LiveAttestFunc

	// VerifyUser runs the local.verifyUser exchange behind the backend's
	// VerifyUser method (ruling 167): the phone signs a fresh challenge with
	// its user-verification key, which only a biometric match unlocks, and
	// the function judges the answer. It is injected for the same reason as
	// LiveAttest. Nil refuses every VerifyUser with
	// ErrUserVerifierUnavailable.
	VerifyUser pairingproto.LiveAttestFunc
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
func (h *phoneKeyHandle) BackendID() xkms.BackendType {
	return BackendTypePhone
}

// PhoneKeyBackend implements FIDO2KeyBackend for phone-based key storage.
type PhoneKeyBackend struct {
	cfg *PhoneKeyBackendConfig
	log *slog.Logger

	mu sync.RWMutex

	// directMu serializes the direct request path's encrypt/send/decrypt
	// sequence. A Noise CipherState advances a monotonic nonce per message and
	// is not concurrent-safe — MessageRouter says so at its own sendMu and
	// takes it for exactly this reason. The direct path admits concurrent
	// leaseholders and had no equivalent, so two signing operations could
	// interleave their nonce advancement and pair responses with the wrong
	// request.
	//
	// It spans SendAndReceive deliberately: the response belongs to the
	// request that produced the nonce, so releasing before the round trip
	// would order the frames and still mismatch the answers. Close does NOT
	// take it, so a stalled device cannot make this lock block shutdown.
	directMu  sync.Mutex
	transport pairingproto.Transport
	session   *bootstrap.NoiseSession

	// ownedKey is the static key this backend destroys on Close — either one
	// the caller transferred by setting OwnsStaticKey, or one the constructor
	// generated because none was supplied. Nil when the key is borrowed.
	//
	// Ownership lives here rather than being written back into the caller's
	// config. A config is an input and callers reasonably reuse one across
	// constructions; a cfg that silently gained a key after a successful
	// construction would hand the next backend a key the previous one owns
	// and will destroy.
	ownedKey *bootstrap.NoiseStaticKey

	// ops counts operations that took a reference to session and transport
	// and are still using them outside mu — SendRequest encrypts, does a bus
	// round trip, then decrypts, far too long to hold the lock. Close drains
	// this before clearing the session or destroying an owned key, and the
	// drain is bounded: an operation blocked in a Transport that Close did
	// not manage to unblock must not hang shutdown forever.
	ops lifecycle.Drain

	// closeOnce/closeErr latch the shutdown outcome so concurrent and repeat
	// callers see one result and only one of them releases the static key.
	closeOnce   sync.Once
	closeErr    error
	handles     map[string]*phoneKeyHandle // hex(credentialID) -> handle
	router      *pairing.MessageRouter     // nil = unidirectional mode
	notifier    notify.Notifier
	auditLogger audit.Logger

	connected atomic.Bool
	closed    atomic.Bool
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

	// Ownership has already transferred by the time we get here, so the BLE
	// transport failing below must not strand the key.
	var backend *PhoneKeyBackend
	defer func() {
		if backend == nil {
			releaseOwnedKey(cfg)
		}
	}()

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

	backend, err = newPhoneKeyBackend(cfg, transport)
	return backend, err
}

// NewPhoneKeyBackendWithTransport creates a new phone key backend with a
// pre-configured transport. This allows using any Transport implementation
// (BLE, TCP, or custom) as the communication layer. The caller is responsible
// for establishing the transport-level connection before calling Connect()
// on non-BLE transports.
func NewPhoneKeyBackendWithTransport(cfg *PhoneKeyBackendConfig, transport pairingproto.Transport) (*PhoneKeyBackend, error) {
	if cfg == nil {
		cfg = DefaultPhoneKeyBackendConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if transport == nil {
		// Ownership transferred with the config, so rejecting it here still
		// has to release the key.
		releaseOwnedKey(cfg)
		return nil, ErrNotConnected
	}

	return newPhoneKeyBackend(cfg, transport)
}

// releaseOwnedKey destroys cfg's static key when the caller transferred
// ownership by setting OwnsStaticKey. It is idempotent — it clears the field —
// so a nested constructor that already released is not freed twice, and it is
// safe on a nil key.
//
// Every path that can fail after ownership transfers has to call this. Close is
// unreachable when there is no backend, so the constructor is the only place
// left that can release the pages.
func releaseOwnedKey(cfg *PhoneKeyBackendConfig) {
	if cfg == nil || !cfg.OwnsStaticKey {
		return
	}
	cfg.LocalStaticKey.Destroy()
	cfg.LocalStaticKey = nil
}

// newPhoneKeyBackend is the internal constructor shared by both public
// constructors. It initializes the Noise session and assembles the backend.
func newPhoneKeyBackend(cfg *PhoneKeyBackendConfig, transport pairingproto.Transport) (*PhoneKeyBackend, error) {
	// Ownership transfers on entry, so construction failing must not strand
	// the key: the caller set OwnsStaticKey precisely because it kept no
	// reference of its own, and Close is unreachable when there is no backend.
	// Resolve the key and settle who releases it, without writing either back
	// into the caller's config.
	//
	// A nil key is generated here rather than inside NewNoiseSession, where it
	// would not be reachable from the backend and nothing could ever destroy
	// it — the config's documented "if nil, a new key will be generated" would
	// quietly opt out of the whole protected-key lifecycle.
	staticKey := cfg.LocalStaticKey
	var ownedKey *bootstrap.NoiseStaticKey
	switch {
	case staticKey == nil:
		generated, err := bootstrap.GenerateNoiseStaticKey()
		if err != nil {
			return nil, errors.Join(err, transport.Close())
		}
		staticKey, ownedKey = generated, generated // we made it, we own it
	case cfg.OwnsStaticKey:
		// The caller transferred it, so CONSUME it. Leaving the pointer in
		// the config gives the next construction from that same config a
		// second owner for the same protected pages, and whichever backend
		// closes first frees pages the other's Noise session is still
		// reading. Callers do reuse configs — that is what a config is.
		//
		// This is the mirror of the write-back hazard, not a repeat of it:
		// the earlier bug ADDED a generated key the caller never supplied,
		// where this REMOVES one the caller explicitly gave away. The failure
		// paths already clear the field through releaseOwnedKey, so the
		// config was always consumable; the success path just was not doing
		// it.
		//
		// OwnsStaticKey is deliberately left alone. With no key present it
		// changes nothing: a nil key is generated and owned regardless.
		ownedKey = staticKey
		cfg.LocalStaticKey = nil
	}

	constructed := false
	defer func() {
		if !constructed {
			// ownedKey is the only reference by this point — either we
			// generated it, or the transfer above took it out of the config.
			ownedKey.Destroy()
		}
	}()

	// Validate trust settings: if no expected remote key and trust-new-devices is false,
	// reject the connection to prevent connecting to unknown devices.
	if len(cfg.ExpectedRemoteStatic) == 0 && !cfg.TrustNewDevices {
		return nil, errors.Join(ErrUntrustedDevice, transport.Close())
	}

	// Create Noise session with empty prologue initially.
	// The prologue will be set during the pre-handshake identity exchange
	// in performHandshake, which sends our public key to Android and receives
	// the device's attestation fingerprint. This enables trusted device binding
	// for reconnections while allowing empty prologue for initial pairing.
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey:       staticKey,
		ExpectedRemoteStatic: cfg.ExpectedRemoteStatic,
		IsInitiator:          true,
		Prologue:             nil, // Set during identity exchange
	})
	if err != nil {
		return nil, errors.Join(err, transport.Close())
	}

	constructed = true
	backend := &PhoneKeyBackend{
		cfg:         cfg,
		ownedKey:    ownedKey,
		log:         cfg.Logger.With("component", "phone_backend"),
		transport:   transport,
		session:     session,
		handles:     make(map[string]*phoneKeyHandle),
		notifier:    cfg.Notifier,
		auditLogger: cfg.AuditLogger,
	}
	return backend, nil
}

// acquireSession takes a reference to the live transport and session so they
// can be used outside mu without Close tearing them down underneath. The
// release function must be called exactly once; until it is, Close blocks
// rather than clearing the session or destroying an owned key.
//
// It reports false once the backend is closed or disconnected.
func (b *PhoneKeyBackend) acquireSession() (pairingproto.Transport, *bootstrap.NoiseSession, func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed.Load() || b.transport == nil || b.session == nil {
		return nil, nil, nil, false
	}

	b.ops.Add()
	transport, session := b.transport, b.session

	release := func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		b.ops.Done()
	}
	return transport, session, release, true
}

// Type returns the backend type.
func (b *PhoneKeyBackend) Type() xkms.BackendType {
	return BackendTypePhone
}

// HandlesUserVerificationFor reports whether backendID names this backend: every
// phone key operation is gated by the phone's biometric, so a credential this
// backend owns is verified whenever it is used.
func (b *PhoneKeyBackend) HandlesUserVerificationFor(backendID xkms.BackendType) bool {
	return backendID == b.Type() && b.Capabilities().HandlesUserVerification
}

// HandlesUserPresenceFor reports whether backendID names this backend: the
// phone's biometric prompt on every key operation is also the presence check.
func (b *PhoneKeyBackend) HandlesUserPresenceFor(backendID xkms.BackendType) bool {
	return backendID == b.Type() && b.Capabilities().HandlesUserPresence
}

// Capabilities returns the backend capabilities.
func (b *PhoneKeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{pairingproto.COSEAlgES256, pairingproto.COSEAlgES384, pairingproto.COSEAlgES512},
		SupportsExport:          false, // Keys never leave the phone's secure element
		SupportsImport:          false, // Cannot import keys to phone
		SupportsAttestation:     false, // Phone provides its own attestation
		HardwareBacked:          true,  // Phone uses hardware secure element
		HandlesUserPresence:     true,  // Phone biometric IS the user presence check
		HandlesUserVerification: true,  // Phone biometric IS the user verification
		// The phone prompts for biometric during Sign/GenerateKey operations.
		// This serves as both user presence (UP) and user verification (UV)
		// for that operation only: there is no standalone "verify the user"
		// RPC, so the authenticator mints no pinUvAuthToken from it (#1145).
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

	// Close clears transport and session under this same lock, so a Connect
	// after a Close would fall through to performHandshake and dereference a
	// nil session. Refuse rather than panic.
	if b.closed.Load() {
		return ErrBackendClosed
	}
	if b.transport == nil {
		return ErrNotConnected
	}

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
		if auditErr := b.auditLogger.LogConnectionEvent(
			audit.OpConnectionEstablished,
			b.cfg.DeviceAddress,
			b.cfg.DeviceName,
			map[string]any{
				"transport": "non-ble",
			},
		); auditErr != nil {
			return auditErr
		}
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
				if disconnectErr := bleTransport.DisconnectAndRemove(); disconnectErr != nil {
					b.log.Warn("failed to disconnect and remove BLE device", "address", address, "error", disconnectErr)
				}
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
			if disconnectErr := bleTransport.DisconnectAndRemove(); disconnectErr != nil {
				b.log.Warn("failed to disconnect and remove BLE device", "address", address, "error", disconnectErr)
			}
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
			if auditErr := b.auditLogger.LogConnectionEvent(
				audit.OpConnectionEstablished,
				address,
				b.cfg.DeviceName,
				map[string]any{
					"transport": "ble",
					"mtu":       b.cfg.MTU,
				},
			); auditErr != nil {
				return auditErr
			}
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
//
// Must be called with b.mu held: it reads transport and session, which Close
// clears while destroying an owned static key. Both call sites reach it from
// Connect, which holds the write lock for the whole connection attempt — so do
// not take the lock here, it would deadlock.
func (b *PhoneKeyBackend) performHandshake(ctx context.Context) error {
	cfg := &pairingproto.HandshakeConfig{
		Transport:           b.transport,
		Session:             b.session,
		Logger:              b.log,
		StripEnvelopeHeader: false, // Android sends raw Noise messages, no envelope
		EnvelopeHeaderSize:  0,
		// Identity exchange for prologue binding
		LocalStaticPublicKey:      b.session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: b.cfg.ExpectedDeviceFingerprint,
	}
	if err := pairingproto.PerformHandshake(ctx, cfg); err != nil {
		return err
	}

	return b.proveLiveness(ctx)
}

// proveLiveness runs the #129 challenge-response proof, when the configuration
// requires it, before the backend is usable for anything.
//
// It sits here rather than at each Connect branch because both reach
// performHandshake: a check per branch is a check one branch can be missing
// from. The handshake above proves the peer holds the Noise key paired
// earlier; only this proves the peer holds the key that was ATTESTED, and that
// it holds it now — which is what a copied Noise key cannot supply.
//
// Must be called with b.mu held, like its caller.
func (b *PhoneKeyBackend) proveLiveness(ctx context.Context) error {
	if !b.cfg.RequireLiveAttestation {
		return nil
	}
	if b.cfg.LiveAttest == nil {
		b.log.Error("live attestation is required for this device but no verifier was supplied")
		return ErrLiveAttestationUnavailable
	}

	binding, err := pairingproto.AttestChannelBinding(b.session)
	if err != nil {
		return err
	}

	// The exchange goes straight through the transport and session rather than
	// SendRequest, which gates on b.connected — and the whole point is that
	// this runs BEFORE the backend is connected enough to serve anything.
	exchange := func(ctx context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
		plaintext, err := pairingproto.EncodeRequest(req)
		if err != nil {
			return nil, err
		}
		ciphertext, err := b.session.Encrypt(plaintext)
		if err != nil {
			return nil, err
		}
		responseCiphertext, err := b.transport.SendAndReceive(ctx, ciphertext)
		if err != nil {
			return nil, err
		}
		responsePlaintext, err := b.session.Decrypt(responseCiphertext)
		if err != nil {
			return nil, err
		}
		return pairingproto.DecodeResponse(responsePlaintext)
	}

	return b.cfg.LiveAttest(ctx, exchange, binding)
}

// VerifyUser implements keybackend.UserVerifier (ruling 167): it asks the
// connected phone to prove a biometric match with its user-verification key
// over the established session, and returns nil only when cfg.VerifyUser
// accepts the answer. The authenticator calls it before minting a
// pinUvAuthToken through getPinUvAuthTokenUsingUvWithPermissions.
func (b *PhoneKeyBackend) VerifyUser(ctx context.Context) error {
	if b.cfg.VerifyUser == nil {
		b.log.Error("user verification was requested but no verifier was supplied")
		return ErrUserVerifierUnavailable
	}
	if !b.connected.Load() {
		return ErrNotConnected
	}

	// The lease keeps the session alive while its channel binding is read;
	// the exchange itself goes through SendRequest, which takes its own.
	_, session, release, ok := b.acquireSession()
	if !ok {
		return ErrNotConnected
	}
	defer release()

	binding, err := pairingproto.AttestChannelBinding(session)
	if err != nil {
		return err
	}
	return b.cfg.VerifyUser(ctx, b.SendRequest, binding)
}

// EnableBidirectional starts bidirectional JSON-RPC routing using the
// provided request handler (typically a Bridge). It must be called after
// Connect() completes successfully. When enabled, SendRequest uses the
// MessageRouter instead of direct SendAndReceive.
//
// It is idempotent: enabling twice keeps the first router rather than starting
// a second. Replacing the router unconditionally used to orphan the first
// receive loop — Close then joined only the replacement and could destroy the
// static key while the orphan was still decrypting through it. Calling after
// Close, or before a session exists, is refused rather than starting a loop
// over a nil transport.
func (b *PhoneKeyBackend) EnableBidirectional(handler pairing.RequestHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed.Load() {
		return ErrBackendClosed
	}
	// connected, not merely non-nil: the constructors populate transport and
	// session before Connect runs the handshake, so a nil check alone lets a
	// receive loop start pre-handshake and race Connect for the handshake
	// frames.
	if !b.connected.Load() || b.transport == nil || b.session == nil {
		return ErrNotConnected
	}
	if b.router != nil {
		b.log.Debug("bidirectional message routing already enabled")
		return nil
	}

	b.router = pairing.NewMessageRouter(b.transport, b.session, handler, b.log)
	b.router.Start()
	b.log.Info("bidirectional message routing enabled")
	return nil
}

// SendRequest sends an encrypted request and receives the decrypted response.
func (b *PhoneKeyBackend) SendRequest(ctx context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
	if !b.connected.Load() {
		b.log.Error("SendRequest called but not connected")
		return nil, ErrNotConnected
	}

	// Lease first, and hold it across the routed path as well. The router
	// encrypts through the same session, so a routed sender that skipped the
	// lease could resume inside MessageRouter.SendRequest after Close had
	// already freed the key's protected pages.
	transport, session, release, ok := b.acquireSession()
	if !ok {
		return nil, ErrNotConnected
	}
	defer release()

	// If a MessageRouter is active, delegate to it for bidirectional routing.
	b.mu.RLock()
	router := b.router
	b.mu.RUnlock()
	if router != nil {
		return router.SendRequest(ctx, req)
	}

	b.directMu.Lock()
	defer b.directMu.Unlock()

	b.log.Debug("SendRequest starting",
		"method", req.Method,
		"id", req.ID,
	)

	// Encode request
	plaintext, err := pairingproto.EncodeRequest(req)
	if err != nil {
		b.log.Error("failed to encode request", "error", err)
		return nil, ErrProtocolError
	}
	b.log.Debug("request encoded", "plaintext_len", len(plaintext))

	// Encrypt
	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		b.log.Error("failed to encrypt request", "error", err)
		return nil, err
	}
	b.log.Debug("request encrypted", "ciphertext_len", len(ciphertext))

	// Send and receive
	b.log.Debug("sending request to phone...")
	responseCiphertext, err := transport.SendAndReceive(ctx, ciphertext)
	if err != nil {
		b.log.Error("SendAndReceive failed", "error", err)
		return nil, err
	}
	b.log.Debug("received response from phone", "ciphertext_len", len(responseCiphertext))

	// Decrypt
	responsePlaintext, err := session.Decrypt(responseCiphertext)
	if err != nil {
		b.log.Error("failed to decrypt response", "error", err)
		return nil, err
	}
	b.log.Debug("response decrypted", "plaintext_len", len(responsePlaintext))

	// Decode response
	resp, err := pairingproto.DecodeResponse(responsePlaintext)
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
	req := pairingproto.NewRequest(pairingproto.MethodGenerateKey, &pairingproto.GenerateKeyParams{
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
		return nil, nil, pairingproto.MapRPCError(resp.Error)
	}

	// Decode result
	result, err := pairingproto.DecodeResult[pairingproto.GenerateKeyResult](resp)
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
		"credential_id", shortCredID(credIDHex),
		"data_hash_len", len(data))
	req := pairingproto.NewRequest(pairingproto.MethodSign, &pairingproto.SignParams{
		CredentialID:             phoneHandle.credentialID,
		DataHash:                 data,
		UserVerificationRequired: true,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		b.log.Error("Sign: request failed", "credential_id", shortCredID(credIDHex), "error", err)
		return nil, err
	}

	if resp.Error != nil {
		b.log.Error("Sign: phone returned error",
			"credential_id", shortCredID(credIDHex),
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message,
			"error_data", resp.Error.Data)
		return nil, pairingproto.MapRPCError(resp.Error)
	}

	// Decode result
	result, err := pairingproto.DecodeResult[pairingproto.SignResult](resp)
	if err != nil {
		b.log.Error("Sign: failed to decode result", "error", err)
		return nil, ErrInvalidResponse
	}

	b.log.Debug("Sign: completed with biometric verification",
		"credential_id", shortCredID(credIDHex),
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
		b.log.Debug("LoadKey: found in local cache", "credential_id", shortCredID(credIDHex))
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
	b.log.Debug("LoadKey: sending request to phone", "credential_id", shortCredID(credIDHex))
	req := pairingproto.NewRequest(pairingproto.MethodLoadKey, &pairingproto.LoadKeyParams{
		CredentialID: credentialID,
		Algorithm:    algorithm,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		b.log.Error("LoadKey: request failed", "credential_id", shortCredID(credIDHex), "error", err)
		return nil, err
	}

	if resp.Error != nil {
		b.log.Error("LoadKey: phone returned error",
			"credential_id", shortCredID(credIDHex),
			"error_code", resp.Error.Code,
			"error_message", resp.Error.Message,
			"error_data", resp.Error.Data)
		return nil, pairingproto.MapRPCError(resp.Error)
	}

	// Decode result
	result, err := pairingproto.DecodeResult[pairingproto.LoadKeyResult](resp)
	if err != nil {
		b.log.Error("LoadKey: failed to decode result", "error", err)
		return nil, ErrInvalidResponse
	}

	if !result.Exists {
		b.log.Error("LoadKey: key does not exist on phone", "credential_id", shortCredID(credIDHex))
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

	b.log.Debug("LoadKey: key verified and cached", "credential_id", shortCredID(credIDHex))
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
	req := pairingproto.NewRequest(pairingproto.MethodDeleteKey, &pairingproto.DeleteKeyParams{
		CredentialID: phoneHandle.credentialID,
	})

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return pairingproto.MapRPCError(resp.Error)
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
//
// It returns ErrShutdownIncomplete when it could not confirm that every
// reader of the Noise session has finished — a receive loop still blocked in
// an uncancellable read, or an operation still in a bus round trip when the
// shutdown window expired. The backend IS closed either way and Close does
// not need calling again; the error says only that protected pages could not
// be freed safely.
//
// A caller that supplied the static key with OwnsStaticKey unset still owns
// it, and MUST NOT destroy it after an ErrShutdownIncomplete: the whole point
// of the error is that something may still be reading those pages. Retention
// lasts for the life of the process.
func (b *PhoneKeyBackend) Close() error {
	// Latched, so every caller observes the SAME outcome.
	//
	// The old shape returned nil to any caller after the first — including
	// one arriving while the first Close was still draining, and including a
	// second call after the first had reported ErrShutdownIncomplete. Both
	// told the owner of a BORROWED key that destroying it was safe while a
	// reader could still be using those pages, which is the exact fail-open
	// this error exists to prevent. Third component with this shape; the TCP
	// server and BLE peripheral latch for the same reason.
	//
	// MUST NOT be called from an operation this backend is draining: Close
	// waits for leases, and the latch makes a re-entrant caller wait for
	// Close. Bounded by the drain timeout rather than permanent, and the same
	// property net/http.Server.Shutdown has.
	b.closeOnce.Do(func() { b.closeErr = b.close() })
	return b.closeErr
}

func (b *PhoneKeyBackend) close() error {
	// Set before the drain so acquireSession admits no new leases.
	b.closed.Store(true)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Log connection closed before actually closing. OpConnectionClosed is
	// SeverityInformational: LogConnectionEvent returns nil for it today.
	// Logged defensively rather than propagated in case that classification
	// ever changes — close() must still release the transport, router, and
	// in-flight leases below even if the audit write failed; refusing to
	// shut down here would leak the resources this method exists to free.
	if b.auditLogger != nil && b.connected.Load() {
		if auditErr := b.auditLogger.LogConnectionEvent(
			audit.OpConnectionClosed,
			b.cfg.DeviceAddress,
			b.cfg.DeviceName,
			nil,
		); auditErr != nil {
			b.log.Error("audit log failed", "error", auditErr)
		}
	}

	b.connected.Store(false)
	b.handles = nil

	// Order matters, and getting it wrong makes the join useless. receiveLoop
	// is blocked in an uncancellable Receive, so signalling alone never wakes
	// an idle one — closing the transport is what does. Signal first so the
	// loop does not start another iteration, then close the transport to
	// unblock the read it is sitting in, and only then wait.
	//
	// Joining before the close meant an idle backend burned the full timeout,
	// concluded the loop was still running, and kept the key forever.
	router := b.router
	b.router = nil
	if router != nil {
		router.Stop()
	}

	// Also unblocks any leaseholder's round trip rather than leaving it to
	// wait out its own timeout.
	if b.transport != nil {
		if closeErr := b.transport.Close(); closeErr != nil {
			b.log.Warn("transport close failed", "error", closeErr)
		}
		b.transport = nil
	}

	// routerJoined false means the loop may still be running and the key has
	// to stay resident.
	routerJoined := true
	if router != nil {
		routerJoined = router.Join(routerShutdownTimeout)
	}

	// Then drain the leases. Wait releases b.mu, which is what lets the
	// release funcs run.
	//
	// Bounded for exactly the reason the router join is. A leaseholder is in
	// the middle of a bus round trip, and Transport.Close is not required by
	// its contract to unblock a SendAndReceive already in flight — so an
	// unbounded wait here is a Close that can never return, on a mutex every
	// other method needs.
	opsDrained := b.ops.Wait(&b.mu, opsShutdownTimeout)
	if !opsDrained {
		b.log.Warn("phone operations did not finish within the shutdown window",
			"in_flight", b.ops.InFlight(), "timeout", opsShutdownTimeout)
	}

	b.session = nil

	// Only now, and only if every reader is provably gone. Leaking protected
	// memory is the safe failure here; freeing pages a live goroutine is
	// decrypting through is not.
	shutdownClean := routerJoined && opsDrained
	if b.ownedKey != nil {
		if shutdownClean {
			b.ownedKey.Destroy()
			b.ownedKey = nil
		} else {
			b.log.Warn("retaining the static key: shutdown could not confirm " +
				"that every reader has finished, so its pages may still be in use")
		}
	}

	b.log.Info("phone backend closed")

	// Reported even when the key is borrowed rather than owned — especially
	// then. A borrowed key is one this backend cannot retain on the owner's
	// behalf, so the owner is the only one who can decide not to free it, and
	// this return is the only way they learn there is still a reader.
	if !shutdownClean {
		return ErrShutdownIncomplete
	}
	return nil
}

// routerShutdownTimeout bounds how long Close waits for the message router's
// receive loop to exit. It only observes shutdown between messages, so an idle
// transport read will not notice; see MessageRouter.StopAndJoin.
const routerShutdownTimeout = 5 * time.Second

// opsShutdownTimeout bounds how long Close waits for in-flight operations to
// release their session lease. It is longer than routerShutdownTimeout
// because a leaseholder is doing a phone round trip — a user tapping approve
// on a handset — where the router is only reading a socket.
//
// A var rather than a const so tests can exercise the timeout branch without
// spending the production window on it. Nothing else writes it.
var opsShutdownTimeout = 30 * time.Second

// credIDLogPrefixLen is the number of hex characters of a credential ID
// included in log records.
const credIDLogPrefixLen = 16

// shortCredID returns a log-safe prefix of a hex-encoded credential ID.
// Credential IDs shorter than credIDLogPrefixLen/2 bytes are returned whole
// rather than slicing out of range.
func shortCredID(credIDHex string) string {
	if len(credIDHex) > credIDLogPrefixLen {
		return credIDHex[:credIDLogPrefixLen]
	}
	return credIDHex
}

// isAlgorithmSupported checks if the algorithm is supported.
func (b *PhoneKeyBackend) isAlgorithmSupported(algorithm int) bool {
	switch algorithm {
	case pairingproto.COSEAlgES256, pairingproto.COSEAlgES384, pairingproto.COSEAlgES512:
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

// LocalStaticPublicKey returns the local Noise static public key, or nil once
// the backend is closed.
//
// Read under b.mu because Close clears the session and destroys an owned key
// while holding the write side; an unsynchronized reader could otherwise call
// into a session whose protected pages are being freed.
func (b *PhoneKeyBackend) LocalStaticPublicKey() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.session == nil {
		return nil
	}
	return b.session.LocalStaticPublicKey()
}

// RemoteStaticPublicKey returns the phone's Noise static public key, or nil
// once the backend is closed. See LocalStaticPublicKey for the locking.
func (b *PhoneKeyBackend) RemoteStaticPublicKey() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.session == nil {
		return nil
	}
	return b.session.RemoteStaticPublicKey()
}

// GetDeviceInfo retrieves information about the connected phone.
func (b *PhoneKeyBackend) GetDeviceInfo(ctx context.Context) (*pairingproto.GetInfoResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	if !b.connected.Load() {
		if err := b.Connect(ctx); err != nil {
			return nil, err
		}
	}

	req := pairingproto.NewRequest(pairingproto.MethodGetInfo, nil)

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, pairingproto.MapRPCError(resp.Error)
	}

	return pairingproto.DecodeResult[pairingproto.GetInfoResult](resp)
}

// Ping sends a ping to verify the connection is alive.
func (b *PhoneKeyBackend) Ping(ctx context.Context) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	if !b.connected.Load() {
		return ErrNotConnected
	}

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)

	resp, err := b.SendRequest(ctx, req)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return pairingproto.MapRPCError(resp.Error)
	}

	result, err := pairingproto.DecodeResult[pairingproto.PingResult](resp)
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
func (b *PhoneKeyBackend) SendPairingConfirm(ctx context.Context, deviceName string) (*pairingproto.PairingConfirmResult, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !b.connected.Load() {
		return nil, ErrNotConnected
	}

	publicKeyHex := hex.EncodeToString(b.LocalStaticPublicKey())

	req := pairingproto.NewRequest(pairingproto.MethodPairingConfirm, &pairingproto.PairingConfirmParams{
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
			if auditErr := b.auditLogger.LogConnectionEvent(
				audit.OpPairingDenied,
				b.cfg.DeviceAddress,
				b.cfg.DeviceName,
				map[string]any{
					"reason": resp.Error.Message,
				},
			); auditErr != nil {
				return nil, auditErr
			}
		}
		return nil, pairingproto.MapRPCError(resp.Error)
	}

	result, err := pairingproto.DecodeResult[pairingproto.PairingConfirmResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	if !result.Confirmed {
		// Log pairing denied
		if b.auditLogger != nil {
			if auditErr := b.auditLogger.LogConnectionEvent(
				audit.OpPairingDenied,
				b.cfg.DeviceAddress,
				b.cfg.DeviceName,
				map[string]any{
					"reason": "user rejected",
				},
			); auditErr != nil {
				return nil, auditErr
			}
		}
		return nil, ErrPairingRejected
	}

	// Log pairing approved
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogConnectionEvent(
			audit.OpPairingApproved,
			b.cfg.DeviceAddress,
			result.DeviceName,
			nil,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	return result, nil
}

// ListFido2Credentials lists shareable FIDO2 credentials on the phone for a
// given relying party. This enables credential discovery for cross-device
// authentication flows where the laptop needs to know which credentials
// are available on the phone for a specific relying party.
func (b *PhoneKeyBackend) ListFido2Credentials(ctx context.Context, rpID string) ([]pairingproto.Fido2CredentialInfo, error) {
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

	req := pairingproto.NewRequest(pairingproto.MethodLocalListFido2Credentials, &pairingproto.LocalListFido2CredentialsParams{
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
		return nil, pairingproto.MapRPCError(resp.Error)
	}

	result, err := pairingproto.DecodeResult[pairingproto.LocalListFido2CredentialsResult](resp)
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
func (b *PhoneKeyBackend) SignFido2Assertion(ctx context.Context, params *pairingproto.LocalSignFido2AssertionParams) (*pairingproto.LocalSignFido2AssertionResult, error) {
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

	req := pairingproto.NewRequest(pairingproto.MethodLocalSignFido2Assertion, params)

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
		return nil, pairingproto.MapRPCError(resp.Error)
	}

	result, err := pairingproto.DecodeResult[pairingproto.LocalSignFido2AssertionResult](resp)
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
var (
	_ keybackend.FIDO2KeyBackend = (*PhoneKeyBackend)(nil)
	_ keybackend.UserVerifier    = (*PhoneKeyBackend)(nil)
)
