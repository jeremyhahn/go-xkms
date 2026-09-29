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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/internal/lifecycle"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Phone service errors.
var (
	ErrPhoneNotConnected   = errors.New("phone_service: no device connected")
	ErrPhoneDeviceNotFound = errors.New("phone_service: device not found")
	ErrPhoneScanFailed     = errors.New("phone_service: scan failed")
	ErrPhonePairFailed     = errors.New("phone_service: pairing failed")
	ErrPhoneAttestFailed   = errors.New("phone_service: attestation failed")
	ErrPhoneInvalidTimeout = errors.New("phone_service: invalid timeout value")
	ErrPhoneBLEUnavailable = errors.New("phone_service: bluetooth unavailable - ensure bluetooth is enabled")
	ErrPhoneAlreadyPaired  = errors.New("phone_service: device already paired")
	// ErrPhoneShutdownIncomplete reports that a teardown finished without
	// confirming every in-flight operation had released the connection, so
	// the protected static key was retained rather than destroyed. The
	// connection IS torn down; what the error says is that something may
	// still be reading those pages.
	ErrPhoneShutdownIncomplete = errors.New("phone_service: teardown could not confirm every operation finished")

	ErrPhoneConnectFailed   = errors.New("phone_service: BLE connection failed")
	ErrPhoneHandshakeFailed = errors.New("phone_service: Noise handshake failed")
	ErrPhoneMissingKeys     = errors.New("phone_service: device missing Noise keys - re-pair required")
	ErrPhonePolicyViolation = errors.New("phone_service: attestation policy violation")
	ErrPhonePolicyNotSet    = errors.New("phone_service: no attestation policy set for device")
	// ErrPhoneInvalidFingerprint reports that the device's stored fingerprint
	// is present but undecodable. The connection is refused: a fingerprint
	// that cannot be read cannot be checked, and proceeding would bind the
	// handshake to nothing. Re-pair the device to store a fresh one.
	ErrPhoneInvalidFingerprint = errors.New("phone_service: stored device fingerprint is invalid - re-pair required")

	// ErrPhoneAttestationRequired indicates the device's record says it was
	// bound under challenge-response attestation (#129) and the proof could
	// not be obtained or did not verify. The session is not published.
	ErrPhoneAttestationRequired = errors.New("phone_service: device did not prove possession of its attested key - refusing to connect")

	// ErrPhonePairAttestationRefused indicates the device's pairing-time
	// attestation could not be verified and policy does not allow pairing an
	// unattestable device (#115). Nothing is written down: the pairing record
	// is what every later connection is judged against, and a record whose
	// attestation half was never checked is worse than no record at all.
	ErrPhonePairAttestationRefused = errors.New("phone_service: device attestation could not be verified - pairing refused")

	// ErrPhoneBarrierRequired indicates the local Noise static private key
	// could not be sealed (Pair) or unsealed (Connect) because no unsealed
	// barrier is available (#42). The ruling is that this key never touches
	// disk as plaintext, so there is no fallback: pairing and connecting both
	// refuse rather than writing or reading it unsealed.
	ErrPhoneBarrierRequired = errors.New("phone_service: sealing/unsealing the local Noise private key requires an unsealed barrier")
)

// devicesConfigFileName is the config file shared with the CLI.
const devicesConfigFileName = "devices.yaml"

// PhoneEventEmitter is called to emit phone-related events to the frontend.
type PhoneEventEmitter func(evt events.Event)

// PhoneStatusChangeFunc is called when the phone connection status changes.
// This allows the systray and other components to react to phone events.
type PhoneStatusChangeFunc func(connected bool, deviceName string)

// PairedDevice describes a phone that has been previously paired.
//
// It is the Wails/TS-facing view model, and it is deliberately NOT the
// persisted record: pairing.PairedDevice is the one owned type for
// devices.yaml (#130), and this type carries only what the frontend needs to
// display plus fields computed at call time (Connected). deviceView is the
// projection from one to the other; there is no field here that also lives
// in pairing.PairedDevice under a different name.
type PairedDevice struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	PairedAt  time.Time `json:"paired_at"`
	LastSeen  time.Time `json:"last_seen"`
	Connected bool      `json:"connected"`
	IsBackend bool      `json:"is_backend"`
}

// deviceView projects the persisted pairing record onto the view model the
// frontend receives. It is the only place that translates one to the other,
// so a field the persisted record gains is either surfaced here on purpose
// or is deliberately left out — never silently missing (#130).
//
// connected is supplied by the caller rather than read from the record: it
// is live connection state, not something devices.yaml ever stores.
func deviceView(d pairing.PairedDevice, connected bool) PairedDevice {
	return PairedDevice{
		Name:      d.Name,
		Address:   d.Address,
		PairedAt:  d.PairedAt,
		LastSeen:  d.LastDeviceAttestationTime,
		Connected: connected,
		IsBackend: d.IsBackend,
	}
}

// DeviceStatus describes the live status of a paired device.
type DeviceStatus struct {
	Name         string `json:"name"`
	Address      string `json:"address"`
	Connected    bool   `json:"connected"`
	BatteryLevel int    `json:"battery_level"`
	RSSI         int    `json:"rssi"`
	Firmware     string `json:"firmware"`
}

// DiscoveredDevice describes a device found during BLE scanning.
type DiscoveredDevice struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	RSSI    int    `json:"rssi"`
}

// AttestationResult describes the outcome of a device attestation check.
type AttestationResult struct {
	DeviceName   string    `json:"device_name"`
	Verified     bool      `json:"verified"`
	ChainLength  int       `json:"chain_length"`
	AttestTime   time.Time `json:"attest_time"`
	ErrorMessage string    `json:"error_message,omitempty"`

	// Android attestation extension data.
	SecurityLevel     string   `json:"security_level"`
	BootState         string   `json:"boot_state"`
	BootHash          string   `json:"boot_hash"`
	BootKeyHash       string   `json:"boot_key_hash"`
	DeviceLocked      bool     `json:"device_locked"`
	KeyAlgorithm      string   `json:"key_algorithm"`
	KeySize           int      `json:"key_size"`
	KeyPurposes       []string `json:"key_purposes"`
	KeyOrigin         string   `json:"key_origin"`
	AttestVersion     int      `json:"attest_version"`
	KeymasterVersion  int      `json:"keymaster_version"`
	KeymasterSecurity string   `json:"keymaster_security"`

	// Certificate chain details.
	Certificates []AttestCertInfo `json:"certificates"`

	// Trust anchor info.
	TrustAnchorSubject     string `json:"trust_anchor_subject,omitempty"`
	TrustAnchorFingerprint string `json:"trust_anchor_fingerprint,omitempty"`
}

// AttestCertInfo provides certificate details for the frontend.
type AttestCertInfo struct {
	Label         string `json:"label"`
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	Algorithm     string `json:"algorithm"`
	PublicKeyFP   string `json:"public_key_fp"`
	CertFP        string `json:"cert_fp"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	IsCA          bool   `json:"is_ca"`
	IsTrustAnchor bool   `json:"is_trust_anchor"`
}

// phoneConfigDevice is the persisted pairing record this service reads and
// writes. The type itself is owned by pkg/pairing, which also owns the CLI's
// devices.yaml record — this alias keeps the GUI's call sites unchanged now
// that the two surfaces share one definition instead of hand-mirroring it
// field for field (#130).
type phoneConfigDevice = pairing.PairedDevice

// devicesAttestationPolicy mirrors the top-level `attestation_policy` block of
// devices.yaml, the CLI's AttestationPolicy.
//
// Only the key this service consults is named. Every other key the CLI
// writes there rides in Rest, so a GUI save round-trips the block instead of
// erasing it — which is what a mirror without this field did: writing
// devices.yaml back with the block missing, so a user's `xkey device pair`
// settings vanished the first time the GUI paired or unpaired anything.
type devicesAttestationPolicy struct {
	// AllowUnattestableDevices is the USER plane of the owner ruling of
	// 2026-08-23 on #95: whether a pairing whose attestation cannot be
	// verified completes. The zero value refuses. See
	// attestation.AllowUnattestablePairing for how it combines with the
	// enterprise plane.
	AllowUnattestableDevices bool `yaml:"allow_unattestable_devices"`

	// ApplicationPolicy is the attested-application allow-list pairing and
	// every re-attestation judge the phone against (#1305) -- the same keys,
	// by the same type, the CLI reads from this block.
	pairing.ApplicationPolicy `yaml:",inline"`

	Rest map[string]any `yaml:",inline"`
}

// phoneConfig mirrors the CLI PhoneConfig YAML structure.
type phoneConfig struct {
	Devices           []phoneConfigDevice       `yaml:"devices"`
	DefaultDevice     string                    `yaml:"default_device"`
	AttestationPolicy *devicesAttestationPolicy `yaml:"attestation_policy,omitempty"`
}

// applicationPolicy is the attested-application allow-list devices.yaml
// configures. An absent block allow-lists nothing.
func (c *phoneConfig) applicationPolicy() pairing.ApplicationPolicy {
	if c == nil || c.AttestationPolicy == nil {
		return pairing.ApplicationPolicy{}
	}
	return c.AttestationPolicy.ApplicationPolicy
}

// allowsUnattestablePairing is the user plane as devices.yaml states it. An
// absent block is not a permission.
func (c *phoneConfig) allowsUnattestablePairing() bool {
	return c != nil && c.AttestationPolicy != nil && c.AttestationPolicy.AllowUnattestableDevices
}

// phoneConnectionState tracks the live connection state of a phone device.
type phoneConnectionState struct {
	connected  atomic.Bool
	deviceName atomic.Value // string
}

// PhoneService exposes phone backend operations to the frontend.
type PhoneService struct {
	ctx            context.Context
	log            *slog.Logger
	connState      phoneConnectionState
	eventEmitter   PhoneEventEmitter
	statusChangeFn PhoneStatusChangeFunc
	trustStore     truststore.TrustStore

	// barrierSvc seals the local Noise static private key on Pair and
	// unseals it on Connect (#42). Read fresh on every use via
	// noiseKeyBarrier rather than captured once: BarrierService replaces its
	// underlying barrier on every Unseal, so a value captured at wiring time
	// would go stale across an app lock/unlock cycle.
	barrierSvc atomic.Pointer[BarrierService]

	// Active BLE connection state (protected by connMu).
	// A mutex is appropriate here because Connect and Disconnect are slow
	// I/O operations that happen infrequently (user-initiated).
	//
	// connMu also guards the status the service reports. Publishing a
	// connection and saying the service is connected are ONE transition, not
	// two: while they were separate steps, a Connect that published into the
	// slot during a teardown's drain was reported as disconnected by the
	// teardown that followed it — a live session the UI showed as down.
	connMu          sync.Mutex
	activeTransport *phone.BLETransport   // nil when disconnected
	activeSession   *pairing.NoiseSession // nil when disconnected

	// activeDevice names the device the published connection belongs to. The
	// slot alone cannot answer "whose connection is this?", and teardown has
	// to know: a connection published during its drain is left standing only
	// when it belongs to a different device.
	activeDevice string

	// activeStaticKey is the protected key backing activeSession. The session
	// reads its pages in place, so it is released alongside the session in
	// closeActiveConnectionLocked and never before.
	activeStaticKey *pairing.StaticKey

	// unpairing counts the in-flight Unpair calls per device. Publication
	// consults it under connMu, so a Connect cannot install a connection to a
	// device whose pairing record is being removed — see Unpair.
	unpairing map[string]int

	// noticeSeq numbers status transitions in the order connMu decided them.
	// Guarded by connMu; read outside it only through a delivered notice.
	noticeSeq uint64

	// pending holds transitions decided under connMu and not yet delivered,
	// and delivering says whether a drainer goroutine is working through them.
	// Both are guarded by connMu. See deliverPending for why delivery is one
	// goroutine rather than the deciding one.
	pending    []connNotice
	delivering bool

	// activeUsers counts operations that took a reference to activeSession
	// and are still using it outside connMu — attestation runs BLE round
	// trips and cannot hold the lock for their duration. Teardown drains this
	// before destroying the key, so a disconnect racing an attestation cannot
	// free pages the attestation is reading. The drain is bounded: a phone
	// that never answers must not wedge the GUI's teardown.
	activeUsers lifecycle.Drain

	// retainedKeys holds static keys a teardown could not prove unreferenced.
	// They are never destroyed; see closeActiveConnectionLocked.
	retainedKeys []*pairing.StaticKey
}

// connNotice is a connection-status transition decided under connMu and
// delivered to the frontend once the lock is released.
type connNotice struct {
	seq        uint64
	connected  bool
	deviceName string
	reason     string
}

// NewPhoneService creates a new PhoneService.
func NewPhoneService() *PhoneService {
	svc := &PhoneService{
		log: slog.Default().With("component", "phone_service"),
	}
	svc.connState.deviceName.Store("")
	return svc
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PhoneService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetEventEmitter sets the function used to emit phone events to the frontend.
func (s *PhoneService) SetEventEmitter(fn PhoneEventEmitter) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	s.eventEmitter = fn
}

// SetStatusChangeFunc sets the callback invoked when phone connection state changes.
func (s *PhoneService) SetStatusChangeFunc(fn PhoneStatusChangeFunc) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	s.statusChangeFn = fn
}

// SetTrustStore sets the trust store used for attestation verification.
func (s *PhoneService) SetTrustStore(ts truststore.TrustStore) {
	s.trustStore = ts
}

// SetBarrierService wires the barrier service used to seal the local Noise
// static private key on Pair and unseal it on Connect (#42). See
// resolveNoiseKeyBarrier for what happens at each of the barrier's states
// when no BarrierService is wired at all, or one is wired but reports
// differently.
func (s *PhoneService) SetBarrierService(svc *BarrierService) {
	s.barrierSvc.Store(svc)
}

// noiseKeyBarrier returns the current barrier for sealing/unsealing the local
// Noise static private key, or an untyped nil pairing.NoiseKeyBarrier when no
// BarrierService is wired or it is not currently open. IsUnsealed, not a nil
// check on GetBarrier, is what decides "open": BarrierService keeps its
// underlying *xkms.Barrier object across a Seal() call (so a later Unseal
// can reuse it), so GetBarrier() stays non-nil for a sealed barrier too --
// only the object's own IsSealed() state, which IsUnsealed reads, tells the
// two apart. Returning bare nil on the not-open paths (rather than a
// *xkms.Barrier(nil) boxed into the interface) matters: a typed nil inside
// an interface value is not itself nil, and
// pairing.SealLocalNoiseKey/UnsealLocalNoiseKey compare their barrier
// parameter against nil to decide whether one was supplied at all.
//
// This does not distinguish "no barrier was ever initialized on this host"
// from "one exists but is sealed" -- Connect's unseal path does not need to:
// a legacy plaintext record reads with a nil barrier regardless of why, and
// a sealed record refuses with a nil barrier regardless of why. Pair, which
// chooses the record's FORMAT rather than just reading it, needs the
// distinction and uses resolveNoiseKeyBarrier instead.
func (s *PhoneService) noiseKeyBarrier() pairing.NoiseKeyBarrier {
	svc := s.barrierSvc.Load()
	if svc == nil || !svc.IsUnsealed() {
		return nil
	}
	barrier := svc.GetBarrier()
	if barrier == nil {
		return nil
	}
	return barrier
}

// resolveNoiseKeyBarrier is Pair's version of noiseKeyBarrier: it also
// reports whether an absent barrier is because none was ever initialized on
// this host, which Pair treats differently from one that exists but is
// currently sealed (owner ruling on #42, recorded on the issue).
//
// Three outcomes:
//   - No BarrierService is wired, or one is wired but IsInitialized() is
//     false: (nil, true). There is nothing to seal the new key into, and
//     that is not a refusal -- Pair logs a warning and writes the legacy
//     plaintext form, same as it always could before #42.
//   - A BarrierService is wired and initialized, but not currently open
//     (sealed, e.g. the app is locked, or the CLI was not given a
//     password): (nil, false). The operator chose to protect this host's
//     pairing key by initializing a barrier; a locked one is not consent
//     to fall back to plaintext, so Pair refuses. IsUnsealed(), not a nil
//     check on GetBarrier, is what detects this -- see noiseKeyBarrier's
//     comment for why GetBarrier alone cannot.
//   - Open: (barrier, false).
func (s *PhoneService) resolveNoiseKeyBarrier() (barrier pairing.NoiseKeyBarrier, noBarrierConfigured bool) {
	svc := s.barrierSvc.Load()
	if svc == nil || !svc.IsInitialized() {
		return nil, true
	}
	if !svc.IsUnsealed() {
		return nil, false
	}
	b := svc.GetBarrier()
	if b == nil {
		return nil, false
	}
	return b, false
}

// sealOrWarnLocalNoiseKey resolves the value to store in a fresh
// PairedDevice's LocalNoisePrivateKey field for priv, the raw private
// scalar. It seals priv when a barrier is open, warns and returns the
// legacy plaintext form when no barrier is initialized on this host at all,
// and refuses when a barrier is initialized but not currently open (#42
// owner ruling, recorded on the issue).
//
// The warning is logged exactly once per call, here, so every caller that
// persists a newly generated key gets it without repeating the log line
// itself.
func (s *PhoneService) sealOrWarnLocalNoiseKey(deviceName string, priv []byte) (string, error) {
	barrier, noBarrierConfigured := s.resolveNoiseKeyBarrier()
	switch {
	case barrier != nil:
		sealed, err := pairing.SealLocalNoiseKey(barrier, priv)
		if err != nil {
			return "", errors.Join(ErrPhoneBarrierRequired, err)
		}
		return sealed, nil
	case noBarrierConfigured:
		s.log.Warn("pairing key stored unencrypted: no barrier is initialized on this host; "+
			"run `xkey barrier init` to protect it",
			"device", deviceName)
		return base64.StdEncoding.EncodeToString(priv), nil
	default:
		return "", ErrPhoneBarrierRequired
	}
}

// IsConnected returns true if a phone device is currently connected.
func (s *PhoneService) IsConnected() bool {
	return s.connState.connected.Load()
}

// ConnectedDeviceName returns the name of the currently connected device,
// or an empty string if no device is connected.
func (s *PhoneService) ConnectedDeviceName() string {
	name, _ := s.connState.deviceName.Load().(string)
	return name
}

// ListDevices returns all paired devices from the shared config file.
func (s *PhoneService) ListDevices() ([]PairedDevice, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []PairedDevice{}, nil
		}
		s.log.Warn("failed to load phone config", "error", err)
		return []PairedDevice{}, nil
	}

	isConnected := s.connState.connected.Load()
	connName := s.ConnectedDeviceName()

	devices := make([]PairedDevice, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		connected := isConnected && d.Name == connName
		devices = append(devices, deviceView(d, connected))
	}
	return devices, nil
}

// GetDeviceStatus returns the live status of a named device.
func (s *PhoneService) GetDeviceStatus(name string) (*DeviceStatus, error) {
	if name == "" {
		return nil, ErrPhoneDeviceNotFound
	}
	return nil, ErrPhoneNotConnected
}

// Scan performs BLE scanning for xKey-compatible devices.
func (s *PhoneService) Scan(timeoutSeconds int) ([]DiscoveredDevice, error) {
	if timeoutSeconds <= 0 || timeoutSeconds > 120 {
		return nil, ErrPhoneInvalidTimeout
	}

	timeout := time.Duration(timeoutSeconds) * time.Second

	s.log.Info("starting BLE scan", "timeout", timeout)

	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout: timeout,
		Logger:      s.log,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			s.log.Error("BLE unavailable", "error", err)
			return nil, ErrPhoneBLEUnavailable
		}
		s.log.Error("failed to create BLE transport", "error", err)
		return nil, ErrPhoneScanFailed
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil {
			s.log.Warn("failed to close BLE transport", "error", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results, err := transport.ScanAll(ctx)
	if err != nil {
		s.log.Error("BLE scan failed", "error", err)
		return nil, ErrPhoneScanFailed
	}

	devices := make([]DiscoveredDevice, 0, len(results))
	for _, r := range results {
		devices = append(devices, DiscoveredDevice{
			Name:    r.DisplayName(),
			Address: r.Address,
			RSSI:    int(r.RSSI),
		})
	}

	s.log.Info("BLE scan complete", "devices_found", len(devices))

	// Emit scan results to frontend.
	if s.eventEmitter != nil {
		scanPayloads := make([]events.DiscoveredDevicePayload, 0, len(devices))
		for _, d := range devices {
			scanPayloads = append(scanPayloads, events.DiscoveredDevicePayload{
				Name:    d.Name,
				Address: d.Address,
				RSSI:    d.RSSI,
			})
		}
		s.eventEmitter(events.NewEvent(events.EventPhoneScanResult, events.PhoneScanResultPayload{
			Devices: scanPayloads,
		}))
	}

	return devices, nil
}

// Pair initiates pairing with a discovered device at the given BLE address.
//
// It owns what is genuinely this surface's: the BLE transport and the
// connection. Everything from the handshake on, including the attestation
// gate and what gets written down, is pairOverTransport, so the decision can
// be exercised against an in-memory phone rather than a radio.
func (s *PhoneService) Pair(address string) (*PairedDevice, error) {
	if address == "" {
		return nil, ErrPhonePairFailed
	}

	// The barrier is checked before anything touches the radio: pairing
	// generates a new Noise static private key, and there is nothing to gain
	// by running the whole handshake and attestation exchange only to refuse
	// at the last step. A host with no barrier initialized at all is not
	// refused here -- see resolveNoiseKeyBarrier and sealOrWarnLocalNoiseKey
	// -- only one whose barrier exists but is not currently open (#42 owner
	// ruling).
	if barrier, noBarrierConfigured := s.resolveNoiseKeyBarrier(); barrier == nil && !noBarrierConfigured {
		s.log.Error("pairing refused: a barrier is initialized on this host but is not open; cannot seal the local Noise private key")
		return nil, ErrPhoneBarrierRequired
	}

	s.log.Info("starting pairing", "address", address)

	// Generate a local Noise static key for this pairing. It does not outlive
	// this call: the session is built here, and the private half is sealed
	// into the stored device record before we return (#42).
	localKey, err := pairing.GenerateStaticKey()
	if err != nil {
		s.log.Error("failed to generate local key", "error", err)
		return nil, ErrPhonePairFailed
	}
	defer localKey.Destroy()

	// Create a Noise session.
	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: localKey,
		IsInitiator:    true,
	})
	if err != nil {
		s.log.Error("failed to create noise session", "error", err)
		return nil, ErrPhonePairFailed
	}

	// Create BLE transport.
	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout:    10 * time.Second,
		ConnectTimeout: 30 * time.Second,
		Logger:         s.log,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return nil, ErrPhoneBLEUnavailable
		}
		s.log.Error("failed to create BLE transport for pairing", "error", err)
		return nil, ErrPhonePairFailed
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil {
			s.log.Warn("failed to close BLE transport", "error", closeErr)
		}
	}()

	// Connect to the device.
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer connectCancel()

	s.log.Info("connecting to device", "address", address)
	if err := transport.Connect(connectCtx, address); err != nil {
		s.log.Error("BLE connection failed", "address", address, "error", err)
		return nil, ErrPhonePairFailed
	}
	// Disconnect after pairing, whatever its outcome (reconnects on demand).
	defer func() {
		if disconnectErr := transport.Disconnect(); disconnectErr != nil {
			s.log.Warn("failed to disconnect BLE transport", "error", disconnectErr)
		}
	}()

	return s.pairOverTransport(connectCtx, transport, session, localKey, address)
}

// pairOverTransport runs the pairing protocol on a connected transport:
// handshake, pairing confirmation, attestation, and only then the record.
//
// The transport's lifetime is the caller's: Pair disconnects it when this
// returns, and a test hands in an in-memory one with nothing to disconnect.
func (s *PhoneService) pairOverTransport(
	ctx context.Context,
	transport pairing.Transport,
	session *pairing.NoiseSession,
	localKey *pairing.StaticKey,
	address string,
) (*PairedDevice, error) {
	// Perform Noise XX handshake. The identity exchange runs on every
	// connection, pairing included: the phone answers an unknown key with
	// "new device" and both sides fall back to an empty prologue, so pairing
	// and reconnecting negotiate the same way.
	s.log.Info("performing Noise handshake")
	handshakeCfg := &pairing.HandshakeConfig{
		Transport:            transport,
		Session:              session,
		Logger:               s.log,
		StripEnvelopeHeader:  false,
		EnvelopeHeaderSize:   0,
		LocalStaticPublicKey: session.LocalStaticPublicKey(),
	}
	if err := pairing.PerformHandshake(ctx, handshakeCfg); err != nil {
		s.log.Error("Noise handshake failed", "error", err)
		return nil, ErrPhonePairFailed
	}

	// Send pairing confirmation to phone.
	s.log.Info("sending pairing confirmation")
	deviceName := hostname()
	pairingReq := pairing.NewRequest(pairing.MethodPairingConfirm, &pairing.PairingConfirmParams{
		DeviceName:   deviceName,
		PublicKeyHex: hex.EncodeToString(session.LocalStaticPublicKey()),
	})
	pairingPlaintext, err := pairing.EncodeRequest(pairingReq)
	if err != nil {
		return nil, ErrPhonePairFailed
	}
	pairingCiphertext, err := session.Encrypt(pairingPlaintext)
	if err != nil {
		return nil, ErrPhonePairFailed
	}
	respCiphertext, err := transport.SendAndReceive(ctx, pairingCiphertext)
	if err != nil {
		return nil, ErrPhonePairFailed
	}
	respPlaintext, err := session.Decrypt(respCiphertext)
	if err != nil {
		return nil, ErrPhonePairFailed
	}
	pairingResp, err := pairing.DecodeResponse(respPlaintext)
	if err != nil {
		return nil, ErrPhonePairFailed
	}
	if pairingResp.Error != nil {
		s.log.Error("phone rejected pairing", "error", pairingResp.Error.Message)
		return nil, ErrPhonePairFailed
	}
	pairingResult, err := pairing.DecodeResult[pairing.PairingConfirmResult](pairingResp)
	if err != nil {
		return nil, ErrPhonePairFailed
	}
	if !pairingResult.Confirmed {
		return nil, phone.ErrPairingRejected
	}

	phoneName := pairingResult.DeviceName
	remotePublicKey := session.RemoteStaticPublicKey()

	// The record is loaded BEFORE the attestation because the user plane of
	// the pairing policy lives in it. A file that cannot be read yields an
	// empty config, which is the same answer as no policy: refuse.
	cfg, err := s.loadConfig()
	if err != nil {
		cfg = &phoneConfig{Devices: []phoneConfigDevice{}}
	}

	// Attest the device before anything is written down. Whether an
	// UNATTESTABLE device may still be paired is policy (see
	// allowUnattestablePairing); what is not policy is that no unverified
	// claim is ever written down. The pairing record is what every later
	// connection is judged against, so a record whose attestation half was
	// never checked is worse than no record at all (#95, #115).
	allowUnattestable := s.allowUnattestablePairing(cfg)
	attestResult, attestErr := s.attestForPairing(ctx, transport, session)
	if attestErr != nil {
		if !allowUnattestable {
			s.log.Error("pairing refused: device attestation could not be verified",
				"device", phoneName, "address", address, "error", attestErr)
			s.emitAttestationEvent(phoneName, false, "pairing refused: "+attestErr.Error())
			return nil, errors.Join(ErrPhonePairAttestationRefused, attestErr)
		}
		s.log.Warn("pairing continued without a verified attestation",
			"device", phoneName,
			"reason", attestErr,
			"policy", "allow_unattestable_devices")
		s.emitAttestationEvent(phoneName, false,
			"paired WITHOUT a verified attestation: policy allows unattestable devices, "+
				"so the record carries no security level, boot state or device fingerprint")
	}

	// Seal the local Noise static private key before it is written anywhere,
	// or fall back to the legacy plaintext form with a warning if no barrier
	// is initialized on this host at all (#42). The barrier's state was
	// confirmed at the top of Pair, but is re-checked here rather than
	// trusted from that earlier check: nothing in this package should assume
	// the barrier's state is unchanged across a long-running BLE exchange
	// and attestation round trip.
	noiseKeyField, err := s.sealOrWarnLocalNoiseKey(phoneName, localKey.Private)
	if err != nil {
		s.log.Error("pairing refused: failed to seal the local Noise private key",
			"device", phoneName, "error", err)
		return nil, err
	}

	// Save to shared config file.
	now := time.Now().UTC()
	cfgDevice := phoneConfigDevice{
		Name:                 phoneName,
		Address:              address,
		NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublicKey),
		LocalNoisePrivateKey: noiseKeyField,
		PairedAt:             now,
	}
	if attestResult != nil {
		xkeyAttestation.ApplyVerifiedAttestation(&cfgDevice, attestResult)
		s.emitAttestationEvent(phoneName, true, "pairing attestation verified: "+attestResult.SecurityLevel)
	}

	// Replace existing device with same address, or append.
	replaced := false
	for i := range cfg.Devices {
		if cfg.Devices[i].Address == address {
			cfg.Devices[i] = cfgDevice
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.Devices = append(cfg.Devices, cfgDevice)
	}
	if cfg.DefaultDevice == "" {
		cfg.DefaultDevice = phoneName
	}

	if err := s.saveConfig(cfg); err != nil {
		s.log.Error("failed to save phone config", "error", err)
		return nil, ErrPhonePairFailed
	}

	s.log.Info("pairing complete", "device", phoneName, "address", address,
		"attested", attestResult != nil)

	view := deviceView(cfgDevice, false)
	return &view, nil
}

// attestForPairing attests the device during pairing and returns what was
// VERIFIED about it.
//
// It fails closed: every step — the trust store being configured at all,
// loading the trust material, the RPC round trip, chain verification, the
// live challenge signature — returns an error, and no attestation claim is
// persisted unless it came out of evidence that verified.
//
// The decision itself is attestation.AttestOverSession, shared with the CLI's
// `device pair`, `device attest-device` and the reconnect path. What stays
// here is what is genuinely this surface's: which trust store to open.
func (s *PhoneService) attestForPairing(
	ctx context.Context,
	transport pairing.Transport,
	session *pairing.NoiseSession,
) (*xkeyAttestation.Result, error) {
	if s.trustStore == nil {
		// No trust store means nothing to judge the evidence against, so the
		// evidence is not even requested. Absent authorization material must
		// never be less restrictive than the policy it implements.
		s.log.Error("pairing attestation impossible: no trust store is configured")
		return nil, ErrPhoneAttestFailed
	}

	trust, err := s.loadAttestationTrust()
	if err != nil {
		s.log.Error("pairing attestation impossible: trust material unavailable", "error", err)
		return nil, err
	}

	verified, err := xkeyAttestation.AttestOverSession(
		ctx, transport, session, trust, pairing.AttestPurposePair, s.log)
	if err != nil {
		return nil, err
	}

	s.log.Info("pairing attestation verified",
		"trust_anchor", verified.TrustAnchor,
		"security_level", verified.Result.SecurityLevel,
		"boot_state", verified.BootState)
	return verified.Result, nil
}

// allowUnattestablePairing projects this surface's two policy planes onto the
// shared decision, attestation.AllowUnattestablePairing, exactly as the CLI's
// `device pair` does. The user plane is the devices.yaml this service just
// read; the enterprise plane is xkey.yaml as config.Load reads it, consumed
// only through config.LoadVerifiedPolicy (#118).
//
// A GUI pairing has no SO at the keyboard, so it supplies no SO PIN. In
// personal mode (no HMAC file) that costs nothing: the section is the user's
// own and is honoured in both directions. In a sealed deployment the section
// cannot be verified here, so it is not consulted at all and the shared
// decision fails closed, whatever devices.yaml says; a fleet that wants the
// setting locked open proves it with the SO PIN through `xkey device pair`.
//
// A unified config that fails to LOAD is not the same as one that is absent.
// Absent means "no enterprise plane, the user decides". A file that exists and
// cannot be read may well be one that locks the setting closed, and the only
// answer that cannot be wrong in the direction an attacker wants is to refuse.
func (s *PhoneService) allowUnattestablePairing(cfg *phoneConfig) bool {
	unified, err := config.Load()
	if err != nil {
		s.log.Error("pairing policy: unified config unreadable; refusing unattestable devices", "error", err)
		return false
	}
	policy, err := config.LoadVerifiedPolicy(unified, config.ConfigDir(), "")
	if err != nil {
		s.log.Info("pairing policy: sealed enterprise policy not consulted by a GUI pairing; refusing unattestable devices",
			"config_dir", config.ConfigDir(), "reason", err)
		policy = nil
	}
	return xkeyAttestation.AllowUnattestablePairing(cfg.allowsUnattestablePairing(), policy)
}

// Unpair removes pairing information for the named device.
func (s *PhoneService) Unpair(name string) error {
	if name == "" {
		return ErrPhoneDeviceNotFound
	}

	cfg, err := s.loadConfig()
	if err != nil {
		return ErrPhoneDeviceNotFound
	}

	idx := -1
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrPhoneDeviceNotFound
	}

	cfg.Devices = append(cfg.Devices[:idx], cfg.Devices[idx+1:]...)
	if cfg.DefaultDevice == name {
		if len(cfg.Devices) > 0 {
			cfg.DefaultDevice = cfg.Devices[0].Name
		} else {
			cfg.DefaultDevice = ""
		}
	}

	// Refuse publication of a connection to this device for the rest of the
	// call. Tearing the connection down is not enough on its own: the drain
	// releases connMu, and a Connect that had already passed its own config
	// load could publish into the slot while it is released — leaving a live
	// connection to a device whose pairing record this call is deleting.
	// Stopping it at the publication step means that when Unpair returns,
	// nothing to this device is published and nothing can be.
	//
	// The window it does NOT cover: a Connect that loaded the config before
	// the record was removed and publishes after Unpair returns. That is the
	// config file's own read-modify-write race rather than this one, it needs
	// Connect to revalidate against the write it raced, and it is filed for
	// v0.7.7 rather than half-closed here.
	s.beginUnpair(name)
	defer s.endUnpair(name)

	// If the unpaired device is currently connected, close the BLE transport
	// and disconnect. An incomplete drain is reported through the service's
	// own state — RetainedKeyCount, and the service no longer claiming to be
	// connected — plus this log line, not through Unpair's return: what Unpair
	// was asked to do is remove the pairing record.
	if s.connState.connected.Load() && s.ConnectedDeviceName() == name {
		if closeErr := s.teardownActiveConnection(name, "unpaired"); closeErr != nil {
			s.log.Warn("unpair tore down the connection but could not confirm "+
				"it drained; its static key is retained for the life of the "+
				"process", "device", name, "error", closeErr,
				"retained_keys", s.RetainedKeyCount())
		}
	}

	return s.saveConfig(cfg)
}

// beginUnpair marks name as having an Unpair in flight, which stops Connect
// from publishing a connection to it. Counted, so concurrent Unpair calls for
// the same device cannot unmark each other's window.
func (s *PhoneService) beginUnpair(name string) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	if s.unpairing == nil {
		s.unpairing = make(map[string]int)
	}
	s.unpairing[name]++
}

// unpairingLocked reports whether an Unpair for name is in flight, and is the
// predicate the publication step refuses on. connMu must be held.
func (s *PhoneService) unpairingLocked(name string) bool {
	return s.unpairing[name] > 0
}

// endUnpair releases the mark taken by beginUnpair.
func (s *PhoneService) endUnpair(name string) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	if s.unpairing[name] <= 1 {
		delete(s.unpairing, name)
		return
	}
	s.unpairing[name]--
}

// SetDeviceAsBackend marks or unmarks a paired device as a key backend.
// When enabled, the device will appear in backend selection lists throughout the app.
func (s *PhoneService) SetDeviceAsBackend(name string, enabled bool) error {
	if name == "" {
		return ErrPhoneDeviceNotFound
	}

	cfg, err := s.loadConfig()
	if err != nil {
		return ErrPhoneDeviceNotFound
	}

	found := false
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			cfg.Devices[i].IsBackend = enabled
			found = true
			break
		}
	}
	if !found {
		return ErrPhoneDeviceNotFound
	}

	return s.saveConfig(cfg)
}

// GetBackendDevices returns only devices that are marked as key backends.
// These are the devices that should appear in backend selection dropdowns.
func (s *PhoneService) GetBackendDevices() ([]PairedDevice, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []PairedDevice{}, nil
		}
		s.log.Warn("failed to load phone config", "error", err)
		return []PairedDevice{}, nil
	}

	isConnected := s.connState.connected.Load()
	connName := s.ConnectedDeviceName()

	devices := make([]PairedDevice, 0)
	for _, d := range cfg.Devices {
		if !d.IsBackend {
			continue
		}
		connected := isConnected && d.Name == connName
		devices = append(devices, deviceView(d, connected))
	}
	return devices, nil
}

// Connect establishes a real BLE connection and Noise handshake to the named paired device.
func (s *PhoneService) Connect(name string) error {
	if name == "" {
		return ErrPhoneDeviceNotFound
	}

	// Load device config to get saved Noise keys and device address.
	cfg, err := s.loadConfig()
	if err != nil {
		return ErrPhoneDeviceNotFound
	}

	var device *phoneConfigDevice
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			device = &cfg.Devices[i]
			break
		}
	}
	if device == nil {
		return ErrPhoneDeviceNotFound
	}

	// Validate that Noise keys exist (device must have been paired).
	if device.LocalNoisePrivateKey == "" || device.NoisePublicKey == "" {
		s.log.Error("device missing Noise keys", "device", name)
		return ErrPhoneMissingKeys
	}

	// Unseal the saved local Noise private key (#42). The expected form is
	// chosen by barrier presence, not the stored value: a record in the
	// other form returns pairing.ErrNoiseKeyFormMismatch, telling the
	// operator to re-pair (there is no migration between the two forms).
	localPrivateKey, err := pairing.UnsealLocalNoiseKey(s.noiseKeyBarrier(), device.LocalNoisePrivateKey)
	if err != nil {
		s.log.Error("failed to unseal local noise key", "device", name, "error", err)
		if errors.Is(err, pairing.ErrNoiseKeyFormMismatch) {
			return errors.Join(ErrPhoneMissingKeys, err)
		}
		return ErrPhoneMissingKeys
	}
	// Destroyed here, at the unseal, not at the LoadStaticKey below: a
	// decode failure on any other field returns in between, and the raw
	// scalar would be left sitting in protected memory nothing releases.
	defer localPrivateKey.Destroy()
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		s.log.Error("invalid phone noise key", "device", name, "error", err)
		return ErrPhoneMissingKeys
	}

	// Reconstruct the local Noise DH key pair. Ownership stays local until it
	// is published onto the service below; every failure path in between has
	// to release the protected pages.
	localKey, err := pairing.LoadStaticKey(localPrivateKey.Bytes())
	if err != nil {
		s.log.Error("failed to load local static key", "device", name, "error", err)
		return ErrPhoneMissingKeys
	}
	published := false
	defer func() {
		if !published {
			localKey.Destroy()
		}
	}()

	// Decode the expected device fingerprint. A stored-but-malformed value is
	// refused rather than treated as "no fingerprint configured" — see
	// phone.DecodeDeviceFingerprint.
	expectedFingerprint, err := phone.DecodeDeviceFingerprint(device.DeviceFingerprint)
	if err != nil {
		s.log.Error("stored device fingerprint is invalid; refusing to connect without identity binding",
			"device", name, "error", err)
		return errors.Join(ErrPhoneInvalidFingerprint, err)
	}

	// Create Noise session with expected remote static key.
	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		IsInitiator:          true,
	})
	if err != nil {
		s.log.Error("failed to create noise session", "device", name, "error", err)
		return ErrPhoneConnectFailed
	}

	// Create BLE transport.
	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout:    10 * time.Second,
		ConnectTimeout: 30 * time.Second,
		Logger:         s.log,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrPhoneBLEUnavailable
		}
		s.log.Error("failed to create BLE transport", "device", name, "error", err)
		return ErrPhoneConnectFailed
	}

	// Connect to the device over BLE.
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer connectCancel()

	s.log.Info("connecting to device", "device", name, "address", device.Address)
	if err := transport.Connect(connectCtx, device.Address); err != nil {
		closeErr := transport.Close()
		s.log.Error("BLE connection failed", "device", name, "address", device.Address, "error", err)
		return errors.Join(ErrPhoneConnectFailed, closeErr)
	}

	// Perform Noise XX handshake with identity exchange for prologue binding.
	s.log.Info("performing Noise handshake", "device", name)
	handshakeCfg := &pairing.HandshakeConfig{
		Transport:                 transport,
		Session:                   session,
		Logger:                    s.log,
		StripEnvelopeHeader:       false,
		EnvelopeHeaderSize:        0,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expectedFingerprint,
	}
	if err := pairing.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		cleanupErr := errors.Join(transport.Disconnect(), transport.Close())
		s.log.Error("Noise handshake failed", "device", name, "error", err)
		return errors.Join(ErrPhoneHandshakeFailed, cleanupErr)
	}

	// The #129 liveness proof, BEFORE the session is published (#130).
	//
	// The handshake above proves the peer holds the Noise key paired earlier.
	// Only this proves the peer holds the key that was ATTESTED, and that it
	// holds it now — which is exactly what possession of a COPIED paired Noise
	// key cannot supply. Publishing first and checking after would hand every
	// caller of this service a usable session in the window between.
	//
	// It runs against the shared decision in pkg/attestation rather than a
	// GUI-local copy. That this package could not reach the verifier at all is
	// why the GUI went without the check while the CLI had it.
	if err := s.proveDeviceLiveness(connectCtx, transport, session, device); err != nil {
		cleanupErr := errors.Join(transport.Disconnect(), transport.Close())
		s.log.Error("device liveness attestation failed; refusing to publish the session",
			"device", name, "error", err)
		return errors.Join(ErrPhoneAttestationRequired, err, cleanupErr)
	}

	// Store transport + session on PhoneService fields. A refusal is ours to
	// clean up: published stays false, so the deferred cleanup releases the
	// key this call generated.
	if err := s.publishConnection(name, transport, session, localKey); err != nil {
		cleanupErr := errors.Join(transport.Disconnect(), transport.Close())
		return errors.Join(err, cleanupErr)
	}
	published = true

	s.log.Info("connected to device", "device", name, "address", device.Address)

	// Auto-attestation: enforce policy if enabled, or refresh if previously
	// attested. Its teardown result is the caller's to hear: a policy
	// violation closes this connection, and an incomplete drain means the
	// protected key it was using is still resident.
	return s.autoAttest(cfg, device, name)
}

// proveDeviceLiveness runs the challenge-response attestation for a device
// (#129/#130).
//
// Every record is now required to carry a version 2 binding (BREAKING,
// go-xkms compat cleanup PR5, removing the original #129/#130 grace period
// for a record with no protocol version or version 1): DeviceBinding.Validate,
// called inside VerifyReattestation, refuses one that does not and tells the
// operator to re-pair. The answer comes from the RECORD, never from anything
// the peer says.
//
// The trust pool is built the same way the GUI's attestation display builds
// it, and per connection rather than captured, so a root an operator installs
// while the app is running takes effect.
func (s *PhoneService) proveDeviceLiveness(
	ctx context.Context,
	transport pairing.Transport,
	session *pairing.NoiseSession,
	device *phoneConfigDevice,
) error {
	binding := xkeyAttestation.DeviceBindingFor(*device)

	// Checked before the trust store, so a record that predates the
	// challenge-response model is refused with a re-pair message rather than
	// a "no trust store configured" one that misdiagnoses the actual problem.
	if err := binding.Validate(); err != nil {
		s.log.Error("device attestation binding is invalid", "device", device.Name, "error", err)
		return err
	}

	if s.trustStore == nil {
		// A record that requires the proof, on a service with no trust store to
		// judge it against, is refused rather than admitted unchecked. Absent
		// authorization material must never be less restrictive than the policy
		// it implements.
		s.log.Error("device requires live attestation but no trust store is configured",
			"device", device.Name)
		return ErrPhoneAttestationRequired
	}

	trust, err := s.loadAttestationTrust()
	if err != nil {
		return err
	}

	return xkeyAttestation.VerifyReattestation(ctx, transport, session, binding, trust, s.log)
}

// Disconnect terminates the BLE connection to the named device.
func (s *PhoneService) Disconnect(name string) error {
	if name == "" {
		return ErrPhoneDeviceNotFound
	}

	// Propagated, not swallowed. Returning nil over a timed-out drain tells
	// the caller the connection is fully released when its protected key is
	// still resident and an operation may still be reading it.
	return s.teardownActiveConnection(name, "user_requested")
}

// AttestDevice performs hardware attestation of the named device.
// It establishes a BLE connection, sends a nonce challenge over an encrypted
// Noise channel, receives the Android hardware attestation certificate chain,
// and verifies it against trusted root CAs.
func (s *PhoneService) AttestDevice(name string) (*AttestationResult, error) {
	if name == "" {
		return nil, ErrPhoneDeviceNotFound
	}

	if !s.connState.connected.Load() {
		return nil, ErrPhoneNotConnected
	}

	connName := s.ConnectedDeviceName()
	if connName != name {
		return nil, ErrPhoneNotConnected
	}

	// Load phone config to get Noise keys for BLE attestation.
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, ErrPhoneAttestFailed
	}

	var device *phoneConfigDevice
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			device = &cfg.Devices[i]
			break
		}
	}
	if device == nil {
		return nil, ErrPhoneDeviceNotFound
	}

	result, err := s.performAttestation(device)
	if err != nil {
		s.log.Error("attestation failed", "device", name, "error", err)
		// Return a result with the error message rather than just an error,
		// so the frontend can display attestation failure details.
		errResult := &AttestationResult{
			DeviceName:   name,
			Verified:     false,
			AttestTime:   time.Now(),
			ErrorMessage: err.Error(),
		}
		s.emitAttestationEvent(name, false, err.Error())
		return errResult, nil
	}

	// Save attestation data to config.
	s.saveAttestationResult(cfg, device, result)

	// Emit success event.
	s.emitAttestationEvent(name, result.Verified, "")
	return result, nil
}

// enforceAttestationPolicy performs attestation and compares the result against
// the stored policy. Returns ErrPhonePolicyViolation if any field mismatches.
func (s *PhoneService) enforceAttestationPolicy(deviceName string, device *phoneConfigDevice) error {
	policy := device.AttestationPolicy

	// Perform fresh attestation.
	result, err := s.performAttestation(device)
	if err != nil {
		s.emitPolicyViolationEvent(deviceName, map[string]string{
			"attestation": fmt.Sprintf("attestation failed: %v", err),
		}, "Attestation failed during policy check")
		return &DetailError{Err: ErrPhonePolicyViolation, Detail: fmt.Sprintf(": attestation failed: %v", err)}
	}

	if !result.Verified {
		s.emitPolicyViolationEvent(deviceName, map[string]string{
			"verification": "attestation chain not verified",
		}, "Attestation verification failed")
		return &DetailError{Err: ErrPhonePolicyViolation, Detail: ": attestation chain not verified"}
	}

	// Compare fields.
	mismatches := make(map[string]string)

	if policy.BootHash != "" && result.BootHash != policy.BootHash {
		mismatches["boot_hash"] = fmt.Sprintf("expected %s, got %s", truncateHash(policy.BootHash), truncateHash(result.BootHash))
	}
	if policy.BootKeyHash != "" && result.BootKeyHash != policy.BootKeyHash {
		mismatches["boot_key_hash"] = fmt.Sprintf("expected %s, got %s", truncateHash(policy.BootKeyHash), truncateHash(result.BootKeyHash))
	}
	if policy.BootState != "" && result.BootState != policy.BootState {
		mismatches["boot_state"] = fmt.Sprintf("expected %s, got %s", policy.BootState, result.BootState)
	}
	if policy.DeviceLocked && !result.DeviceLocked {
		mismatches["device_locked"] = "expected locked, got unlocked"
	}
	if policy.SecurityLevel != "" {
		if securityLevelRank(result.SecurityLevel) < securityLevelRank(policy.SecurityLevel) {
			mismatches["security_level"] = fmt.Sprintf("expected at least %s, got %s", policy.SecurityLevel, result.SecurityLevel)
		}
	}

	if len(mismatches) > 0 {
		msg := fmt.Sprintf("Attestation policy violation: %d field(s) mismatched", len(mismatches))
		s.emitPolicyViolationEvent(deviceName, mismatches, msg)
		return &DetailError{Err: ErrPhonePolicyViolation, Detail: fmt.Sprintf(": %s", msg)}
	}

	return nil
}

// truncateHash returns the first 16 and last 8 chars of a hash for display.
func truncateHash(h string) string {
	if len(h) <= 28 {
		return h
	}
	return h[:16] + "..." + h[len(h)-8:]
}

// securityLevelRank returns a numeric rank for security level comparison.
// Higher ranks indicate stronger security. Unknown levels return -1.
var securityLevelRankMap = map[string]int{
	"software":  0,
	"tee":       1,
	"strongbox": 2,
}

func securityLevelRank(level string) int {
	if r, ok := securityLevelRankMap[level]; ok {
		return r
	}
	return -1
}

// emitPolicyViolationEvent sends a policy violation event to the frontend.
func (s *PhoneService) emitPolicyViolationEvent(deviceName string, mismatches map[string]string, message string) {
	if s.eventEmitter == nil {
		return
	}
	s.eventEmitter(events.NewEvent(events.EventPolicyViolation, events.PolicyViolationPayload{
		DeviceName: deviceName,
		Mismatches: mismatches,
		Message:    message,
	}))
}

// acquireActiveConnection takes a reference to the live transport and session
// so they can be used outside connMu without teardown freeing the static key
// underneath. The release function must be called exactly once, and until it
// is, closeActiveConnectionLocked will block rather than destroy.
//
// It reports false when nothing is connected.
func (s *PhoneService) acquireActiveConnection() (*phone.BLETransport, *pairing.NoiseSession, func(), bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	if s.activeTransport == nil || s.activeSession == nil {
		return nil, nil, nil, false
	}

	s.activeUsers.Add()
	transport, session := s.activeTransport, s.activeSession

	release := func() {
		s.connMu.Lock()
		defer s.connMu.Unlock()

		s.activeUsers.Done()
	}
	return transport, session, release, true
}

// performAttestation runs the attestation flow using the active BLE
// connection. It leases the transport and session -- the round trip is far
// too long to hold connMu, but teardown must not destroy the session's
// static key while it is in flight -- then delegates to attestOverTransport
// for the actual exchange.
func (s *PhoneService) performAttestation(device *phoneConfigDevice) (*AttestationResult, error) {
	transport, session, release, ok := s.acquireActiveConnection()
	if !ok {
		return nil, ErrPhoneNotConnected
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.attestOverTransport(ctx, transport, session, device)
}

// attestOverTransport runs one challenge-response device attestation
// (local.attestDevice, protocol version 2) over transport/session and builds
// the GUI's display-rich AttestationResult.
//
// The accept/reject decision is xkeyAttestation.VerifyDeviceAttestation --
// the SAME decision attestForPairing and proveDeviceLiveness judge a device
// by -- so a device this method accepts is a device every surface would
// accept (#95, #129). Everything below that call is display enrichment: the
// parsed certificate chain and the Android key description are read again,
// independently, purely to populate fields the frontend shows; nothing
// derived from them feeds back into whether the device was trusted.
//
// transport takes the pairing.Transport interface rather than the active
// connection's concrete BLE type -- the same seam pairOverTransport uses --
// so this can be driven by an in-memory phone fake in tests.
func (s *PhoneService) attestOverTransport(
	ctx context.Context,
	transport pairing.Transport,
	session *pairing.NoiseSession,
	device *phoneConfigDevice,
) (*AttestationResult, error) {
	if s.trustStore == nil {
		// No trust store means nothing to judge the evidence against, so the
		// evidence is not even requested. Absent authorization material must
		// never be less restrictive than the policy it implements.
		s.log.Error("attestation impossible: no trust store is configured", "device", device.Name)
		return nil, ErrPhoneAttestFailed
	}
	trust, err := s.loadAttestationTrust()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPhoneAttestFailed, Cause: err}
	}

	// The challenge is bound to THIS session, exactly as attestForPairing and
	// proveDeviceLiveness derive theirs, so the device's answer is useless to
	// anyone relaying it onto a different connection.
	channelBinding, err := session.AttestChannelBinding()
	if err != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": channel binding unavailable"}
	}
	challenge, err := xkeyAttestation.NewChallenge(pairing.AttestPurposeReattest, channelBinding)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPhoneAttestFailed, Cause: err}
	}

	req := pairing.NewRequest(pairing.MethodLocalAttestDevice, challenge.Params())
	reqPlaintext, err := pairing.EncodeRequest(req)
	if err != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": encode request failed"}
	}
	reqCiphertext, err := session.Encrypt(reqPlaintext)
	if err != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": encrypt failed"}
	}

	respCiphertext, err := transport.SendAndReceive(ctx, reqCiphertext)
	if err != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": send/receive failed"}
	}

	s.log.Debug("attestation response received",
		"ciphertext_len", len(respCiphertext),
		"ciphertext_hex_prefix", hex.EncodeToString(respCiphertext[:min(len(respCiphertext), 64)]),
	)

	respPlaintext, err := session.Decrypt(respCiphertext)
	if err != nil {
		s.log.Error("attestation decrypt failed",
			"error", err,
			"ciphertext_len", len(respCiphertext),
			"ciphertext_hex", hex.EncodeToString(respCiphertext[:min(len(respCiphertext), 128)]),
		)
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": decrypt failed"}
	}

	resp, err := pairing.DecodeResponse(respPlaintext)
	if err != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": decode response failed"}
	}
	if resp.Error != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: fmt.Sprintf(": %s", resp.Error.Message)}
	}

	attestResult, err := pairing.DecodeResult[pairing.LocalAttestDeviceResult](resp)
	if err != nil {
		return nil, &DetailError{Err: ErrPhoneAttestFailed, Detail: ": decode result failed"}
	}

	// The security decision: identical to attestForPairing and
	// proveDeviceLiveness. The verified record itself is not consulted
	// below: the display fields are populated from an independent parse
	// (see the comment above the function), so this is only the
	// accept/reject outcome.
	_, verifyErr := xkeyAttestation.VerifyDeviceAttestation(attestResult, challenge, trust)

	now := time.Now()
	result := &AttestationResult{
		DeviceName: device.Name,
		Verified:   verifyErr == nil,
		AttestTime: now,
	}
	if verifyErr != nil {
		result.ErrorMessage = verifyErr.Error()
	}

	// From here on, everything is DISPLAY enrichment: the certificate chain
	// and the Android key description are read again, independently, purely
	// to populate fields the frontend shows. Whether the device was trusted
	// was already decided above.
	chain, chainErr := parseDERChain(attestResult.CertificateChain)
	if chainErr != nil {
		return result, nil
	}
	result.ChainLength = len(chain)

	embeddedRoots := truststore.LoadEmbeddedRoots(truststore.PurposeAndroidHardware)
	result.Certificates = buildCertInfoList(chain, embeddedRoots)
	if matchedRoot := findMatchingTrustRoot(chain, embeddedRoots); matchedRoot != nil {
		result.TrustAnchorSubject = formatTrustAnchorName(matchedRoot)
		result.TrustAnchorFingerprint = certFP(matchedRoot)
	}

	desc, descErr := xkms.VerifyAndroidKeyAttestation(chain, xkeyAttestation.VerifyOptions(trust.Pool))
	if descErr != nil || desc == nil {
		return result, nil
	}

	result.AttestVersion = desc.AttestationVersion
	result.SecurityLevel = desc.AttestationSecurityLevel.String()
	result.KeymasterVersion = desc.KeymasterVersion
	result.KeymasterSecurity = desc.KeymasterSecurityLevel.String()

	tee := &desc.TeeEnforced
	if tee.Algorithm > 0 {
		result.KeyAlgorithm = keymasterAlgorithmName(tee.Algorithm)
	}
	result.KeySize = tee.KeySize
	result.KeyPurposes = keymasterPurposeNameList(tee.Purpose)
	if tee.Origin > 0 {
		result.KeyOrigin = keymasterOriginName(tee.Origin)
	}
	if tee.RootOfTrust != nil {
		rot := tee.RootOfTrust
		result.BootKeyHash = hex.EncodeToString(rot.VerifiedBootKey)
		result.BootHash = hex.EncodeToString(rot.VerifiedBootHash)
		result.BootState = verifiedBootStateName(rot.VerifiedBootState)
		result.DeviceLocked = rot.DeviceLocked
	}

	return result, nil
}

// emitAttestationEvent sends an attestation result event to the frontend.
func (s *PhoneService) emitAttestationEvent(deviceName string, success bool, details string) {
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventAttestationResult, events.AttestationResultPayload{
			DeviceName: deviceName,
			Success:    success,
			Details:    details,
		}))
	}
}

// saveAttestationResult persists attestation data to the phone config file.
func (s *PhoneService) saveAttestationResult(cfg *phoneConfig, device *phoneConfigDevice, result *AttestationResult) {
	device.LastDeviceAttestationTime = result.AttestTime
	device.SecurityLevel = result.SecurityLevel
	device.BootStateVerified = result.BootState == "verified"
	device.LastAttestation = &pairing.PairedDeviceAttestationSnapshot{
		Verified:      result.Verified,
		SecurityLevel: result.SecurityLevel,
		BootHash:      result.BootHash,
		BootKeyHash:   result.BootKeyHash,
		BootState:     result.BootState,
		DeviceLocked:  result.DeviceLocked,
		Timestamp:     result.AttestTime,
	}

	// Update config device in-place.
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == device.Name {
			cfg.Devices[i] = *device
			break
		}
	}
	if err := s.saveConfig(cfg); err != nil {
		s.log.Warn("failed to persist attestation data", "error", err)
	}
}

// SetAttestationPolicy saves the last attestation result as the connection policy
// for a device. Subsequent attestations will be compared against this policy.
func (s *PhoneService) SetAttestationPolicy(deviceName string) error {
	if deviceName == "" {
		return ErrPhoneDeviceNotFound
	}

	cfg, err := s.loadConfig()
	if err != nil {
		return ErrPhoneDeviceNotFound
	}

	for i := range cfg.Devices {
		if cfg.Devices[i].Name == deviceName {
			if cfg.Devices[i].LastAttestation == nil {
				return ErrPhonePolicyNotSet
			}
			last := cfg.Devices[i].LastAttestation
			cfg.Devices[i].AttestationPolicy = &pairing.PairedDeviceAttestationPolicy{
				Enabled:       true,
				BootHash:      last.BootHash,
				BootKeyHash:   last.BootKeyHash,
				BootState:     last.BootState,
				DeviceLocked:  last.DeviceLocked,
				SecurityLevel: last.SecurityLevel,
				SetAt:         time.Now().UTC(),
			}
			return s.saveConfig(cfg)
		}
	}
	return ErrPhoneDeviceNotFound
}

// ClearAttestationPolicy removes the attestation policy for a device.
func (s *PhoneService) ClearAttestationPolicy(deviceName string) error {
	if deviceName == "" {
		return ErrPhoneDeviceNotFound
	}

	cfg, err := s.loadConfig()
	if err != nil {
		return ErrPhoneDeviceNotFound
	}

	for i := range cfg.Devices {
		if cfg.Devices[i].Name == deviceName {
			cfg.Devices[i].AttestationPolicy = nil
			return s.saveConfig(cfg)
		}
	}
	return ErrPhoneDeviceNotFound
}

// GetAttestationPolicy returns the current attestation policy for a device.
func (s *PhoneService) GetAttestationPolicy(deviceName string) (*pairing.PairedDeviceAttestationPolicy, error) {
	if deviceName == "" {
		return nil, ErrPhoneDeviceNotFound
	}

	cfg, err := s.loadConfig()
	if err != nil {
		return nil, ErrPhoneDeviceNotFound
	}

	for _, d := range cfg.Devices {
		if d.Name == deviceName {
			return d.AttestationPolicy, nil
		}
	}
	return nil, ErrPhoneDeviceNotFound
}

// publishConnection installs a completed connection as the active one, and
// with it the status the service reports, in a single critical section.
//
// It refuses in two cases, and in both the caller owns what it built and must
// tear it down:
//
//   - Another connection was published while the teardown of the previous one
//     had connMu released. Overwriting it would drop a live transport on the
//     floor and orphan its protected key, silently, with the service still
//     reporting connected.
//   - The device is being unpaired. A connection published here has no pairing
//     record to stand on by the time it lands — this is how a device came back
//     live behind the Unpair that had just removed it — and Unpair cannot fix
//     it afterwards, because it releases connMu inside its own drain. The
//     publication step is the only place that can see both facts at once.
//
// It is a method rather than inline code in Connect because those two refusals
// are the contract; the only way to test them is to be able to attempt a
// publication at the moment they apply.
func (s *PhoneService) publishConnection(name string, transport *phone.BLETransport, session *pairing.NoiseSession, key *pairing.StaticKey) error {
	s.connMu.Lock()

	// REFUSE BEFORE TOUCHING THE PUBLISHED CONNECTION. Tearing down whatever is
	// connected and only then discovering that this publication is not allowed
	// takes an unrelated device down with it: a Connect(A) that went stale
	// during Unpair(A) would arrive here with B connected, destroy or retain
	// B's protected key and clear B's transport and session, and only then
	// refuse — leaving the service reporting B connected with nothing behind
	// it. The refusal has to come first precisely because the teardown below
	// is destructive.
	if s.unpairingLocked(name) {
		s.connMu.Unlock()

		s.log.Warn("the device is being unpaired; discarding this connection",
			"device", name)
		return ErrPhoneDeviceNotFound
	}

	// Whose connection the teardown below is about to end, kept because
	// closeActiveConnectionLocked clears it and the refusal path underneath
	// needs to name it.
	previous := s.activeDevice

	if closeErr := s.closeActiveConnectionLocked(); closeErr != nil {
		s.log.Warn("replacing a connection whose teardown could not be "+
			"confirmed drained", "device", name, "error", closeErr)
	}

	if s.activeTransport != nil || s.activeSession != nil || s.activeStaticKey != nil {
		s.connMu.Unlock()

		s.log.Warn("another connection was published during teardown; "+
			"discarding this one rather than overwriting it", "device", name)
		return ErrPhoneConnectFailed
	}

	// Both facts have to be re-established, because the drain released connMu:
	// an Unpair for this device can have begun in that window. The previous
	// generation is already gone by now, so unlike the refusal above this one
	// must settle the status too — otherwise the service goes on reporting a
	// connection that no longer exists, which is the divergence this whole
	// contract is about.
	if s.unpairingLocked(name) {
		if previous != "" {
			s.setDisconnectedLocked(previous, "unpaired")
		}
		s.connMu.Unlock()

		s.log.Warn("an unpair for this device began while the previous "+
			"connection was draining; discarding this connection",
			"device", name, "replaced", previous)
		return ErrPhoneDeviceNotFound
	}

	s.publishConnectionLocked(name, transport, session, key)
	s.connMu.Unlock()

	return nil
}

// publishConnectionLocked installs the connection and the status that
// describes it. connMu must be held.
//
// The two are one transition, which is the whole contract: writing the status
// after releasing the lock is what let a teardown running in between mark this
// connection down while it was live. Split out from publishConnection because
// publishConnection first drains the previous generation, and a caller that is
// already inside that drain — a Connect racing a Disconnect over the same
// lease counter — has to be able to publish without waiting on it a second
// time.
func (s *PhoneService) publishConnectionLocked(name string, transport *phone.BLETransport, session *pairing.NoiseSession, key *pairing.StaticKey) {
	s.activeTransport = transport
	s.activeSession = session
	s.activeStaticKey = key
	s.activeDevice = name
	s.setConnectedLocked(name)
}

// teardownActiveConnection closes the published connection and settles the
// service's reported status in the SAME critical section.
//
// That is the whole point of it. Teardown and the status write used to be
// separate steps with connMu released in between, and the gap was reachable:
// closeActiveConnectionLocked's drain releases the lock, a Connect publishes a
// new transport, session and protected key into the empty slot, and the status
// write that follows marks the service disconnected on top of a session that
// is live. The connection was stranded — running, holding protected pages, and
// shown as down everywhere the UI reads status.
//
// Status and publication now move together under connMu, so the two can no
// longer disagree: either this call finds the slot empty and reports
// disconnected, or it finds a replacement and leaves the status the
// replacement published.
//
// A replacement for the SAME device is torn down rather than left standing.
// Only Unpair produces that case, and it does so with the device marked
// unpairing, which stops publication at the source — see Unpair.
//
// It returns closeActiveConnectionLocked's result: ErrPhoneShutdownIncomplete
// when the drain timed out and the connection's static key was retained rather
// than destroyed.
func (s *PhoneService) teardownActiveConnection(name, reason string) error {
	s.connMu.Lock()
	closeErr := s.closeActiveConnectionLocked()

	if s.activeTransport != nil || s.activeSession != nil {
		replacement := s.activeDevice
		s.connMu.Unlock()

		s.log.Warn("a new connection was published while this one was being "+
			"torn down; leaving the service marked connected",
			"device", name, "published", replacement)
		return closeErr
	}

	s.setDisconnectedLocked(name, reason)
	s.connMu.Unlock()

	return closeErr
}

// RetainedKeyCount reports how many connection static keys teardown could not
// prove unreferenced and therefore retained rather than destroyed.
//
// It is the observable record of an incomplete drain. Unpair reports the
// removal of the pairing record and nothing else, because that is what it was
// asked to do and it either happened or it did not; the fact that a key
// outlived the teardown belongs to the service's own state, which is where the
// UI reads it, rather than to the return value of an unrelated operation.
func (s *PhoneService) RetainedKeyCount() int {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	return len(s.retainedKeys)
}

// closeActiveConnectionLocked closes the active BLE transport and clears session state.
// Must be called with connMu held.
// It reports ErrPhoneShutdownIncomplete when the drain timed out, so callers
// can propagate the fact rather than reporting a clean disconnect over a
// connection whose key is still live. A void return was the fail-open here:
// the components below learned to say "incomplete" and this layer discarded
// it.
func (s *PhoneService) closeActiveConnectionLocked() error {
	// Detach this connection generation into locals BEFORE anything can
	// release connMu.
	//
	// The wait below releases the mutex — that is what lets leaseholders
	// reach their release() — and a concurrent Connect can take it in that
	// window and publish a new transport, session and protected key. Code
	// after the wait that still read s.activeSession and s.activeStaticKey
	// would then clear the NEW session and destroy the NEW key: a service
	// left half-connected, with a live session reading freed pages.
	//
	// Clearing the fields first also closes the door behind us:
	// acquireActiveConnection refuses once activeTransport or activeSession
	// is nil, so no further lease can be taken against the generation being
	// torn down.
	transport := s.activeTransport
	key := s.activeStaticKey
	s.activeTransport = nil
	s.activeSession = nil
	s.activeStaticKey = nil
	s.activeDevice = ""

	// Disconnect first so any leaseholder's round trip fails fast rather than
	// waiting out its own timeout.
	var cleanupErr error
	if transport != nil {
		cleanupErr = errors.Join(transport.Disconnect(), transport.Close())
		if cleanupErr != nil {
			s.log.Warn("failed to cleanly disconnect BLE transport during shutdown", "error", cleanupErr)
		}
	}

	// Bounded: a leaseholder is mid BLE round trip with a handset that may
	// never answer, and this runs on the GUI's teardown path. An unbounded
	// wait here is an application that cannot close.
	//
	// The drain counts leases across generations, which is the conservative
	// direction: a true result means no leaseholder exists at all, so the
	// detached key is provably unreferenced.
	drained := s.activeUsers.Wait(&s.connMu, connShutdownTimeout)

	// Only once every leaseholder has returned: destroying earlier would free
	// pages an in-flight operation is still reading.
	if drained {
		key.Destroy()
		return cleanupErr
	}

	// Parked, not dropped. The local would otherwise go out of scope here,
	// which reads as "we forgot" rather than "we decided". memguard pins
	// every live buffer in a package-level list, so the pages survive either
	// way — but holding the owner is what says so, and what a future
	// reclamation path would need.
	//
	// Only when there was a key. The drain counts leases across generations,
	// so it can time out on a slot that was already empty — a Connect landing
	// behind a Disconnect that is still waiting for someone else's lease. The
	// drain is genuinely incomplete and the error says so, but recording a nil
	// as a retained key would make the count the UI reads report key material
	// that never existed.
	if key != nil {
		s.retainedKeys = append(s.retainedKeys, key)
		s.log.Warn("retaining the connection static key: an operation did not "+
			"finish within the shutdown window",
			"in_flight", s.activeUsers.InFlight(), "timeout", connShutdownTimeout)
	}
	return errors.Join(ErrPhoneShutdownIncomplete, cleanupErr)
}

// connShutdownTimeout bounds how long teardown waits for in-flight operations
// to release the active connection. On timeout the protected key is retained
// rather than destroyed, permanently, because an operation still reading
// those pages is the only thing the wait was ever protecting against.
//
// A var rather than a const so tests can exercise the timeout branch without
// spending the production window on it. Nothing else writes it.
var connShutdownTimeout = 30 * time.Second

// autoAttest performs automatic attestation after a successful connection.
// If an attestation policy is enabled, it enforces the policy.
// If the device has been previously attested (but no policy), it refreshes attestation.
//
// It returns the result of the teardown a policy violation forces — the fourth
// caller of closeActiveConnectionLocked, and the last one that discarded it.
// A violation closes the connection this attestation was running over, so
// whether that close drained is exactly as consequential here as on the
// disconnect path: an ErrPhoneShutdownIncomplete means the connection's
// protected key is still resident. Attestation failures that do not tear the
// connection down are reported to the frontend as attestation events, which is
// where they belong.
func (s *PhoneService) autoAttest(cfg *phoneConfig, device *phoneConfigDevice, name string) error {
	// Enforce attestation policy if enabled.
	if device.AttestationPolicy != nil && device.AttestationPolicy.Enabled {
		if err := s.enforceAttestationPolicy(name, device); err != nil {
			s.log.Error("attestation policy enforcement failed on connect", "device", name, "error", err)
			return s.teardownActiveConnection(name, "policy_violation")
		}
		s.log.Info("attestation policy enforced successfully", "device", name)
		return nil
	}

	// If device was previously attested, perform a fresh attestation.
	if device.LastAttestation != nil {
		s.log.Info("auto-attesting previously attested device", "device", name)
		result, err := s.performAttestation(device)
		if err != nil {
			s.log.Warn("auto-attestation failed", "device", name, "error", err)
			s.emitAttestationEvent(name, false, err.Error())
			return nil
		}
		s.saveAttestationResult(cfg, device, result)
		s.emitAttestationEvent(name, result.Verified, "")
		s.log.Info("auto-attestation complete", "device", name, "verified", result.Verified)
	}
	return nil
}

// setConnectedLocked records a connected transition and queues its
// notification. connMu must be held, so that the status the service reports
// and the connection published in the slot move together.
func (s *PhoneService) setConnectedLocked(deviceName string) {
	s.connState.deviceName.Store(deviceName)
	s.connState.connected.Store(true)

	s.noticeSeq++
	s.enqueueNoticeLocked(connNotice{
		seq:        s.noticeSeq,
		connected:  true,
		deviceName: deviceName,
	})
}

// setDisconnectedLocked records a disconnected transition and returns the
// notice describing it. connMu must be held; see setConnectedLocked.
func (s *PhoneService) setDisconnectedLocked(deviceName string, reason string) {
	s.connState.connected.Store(false)
	s.connState.deviceName.Store("")

	s.noticeSeq++
	s.enqueueNoticeLocked(connNotice{
		seq:        s.noticeSeq,
		deviceName: deviceName,
		reason:     reason,
	})
}

// setConnected updates the internal state to reflect a connected phone device.
func (s *PhoneService) setConnected(deviceName string) {
	s.connMu.Lock()
	s.setConnectedLocked(deviceName)
	s.connMu.Unlock()

	s.awaitNoticesDelivered()
}

// setDisconnected updates the internal state to reflect a disconnected phone device.
func (s *PhoneService) setDisconnected(deviceName string, reason string) {
	s.connMu.Lock()
	s.setDisconnectedLocked(deviceName, reason)
	s.connMu.Unlock()

	s.awaitNoticesDelivered()
}

// deliverNotice logs a transition and hands it to the frontend.
//
// NO LOCK IS HELD HERE, AND THAT IS THE POINT. The emitter and the status
// callback reach into the GUI — a systray update and a Wails event — and a
// callback that re-enters the service (Connect, Disconnect, or anything that
// changes status) would deadlock on any lock held across it. An earlier
// version serialized delivery under a dedicated mutex to keep transitions in
// order and had exactly that defect: re-entrancy hit a non-reentrant lock.
//
// ORDER NEEDS ONE DELIVERER, and two attempts to get it any other way both
// failed in the same way. Sequence numbers claimed before each callback order
// the CLAIMS, not the CALLS: whoever wins a claim can be preempted before
// invoking the sink, a later transition can claim and invoke, and the first
// then resumes and invokes stale state on top. Making the claim per-sink
// narrowed that window without closing it, because the gap between reserving
// and calling is still a gap. Nothing an atomic can do serializes a function
// call it does not own.
//
// So delivery is a single drainer. Deciders append under connMu and return;
// one goroutine takes notices off the front, in the order they were decided,
// and invokes the sinks with no lock held. Ordering is structural — there is
// only ever one caller — and re-entrancy is safe, because a callback that
// re-enters the service appends and returns rather than waiting for a delivery
// it is itself inside. The drainer exits when the queue empties and the next
// decider starts a new one.
func (s *PhoneService) enqueueNoticeLocked(notice connNotice) {
	s.pending = append(s.pending, notice)
	if s.delivering {
		return
	}
	s.delivering = true
	go s.deliverPending()
}

// deliverPending drains queued transitions to the frontend, one at a time,
// with connMu released across every callback.
func (s *PhoneService) deliverPending() {
	for {
		s.connMu.Lock()
		if len(s.pending) == 0 {
			s.delivering = false
			s.connMu.Unlock()
			return
		}
		notice := s.pending[0]
		s.pending = s.pending[1:]
		emit := s.eventEmitter
		status := s.statusChangeFn
		s.connMu.Unlock()

		s.deliverNotice(notice, emit, status)
	}
}

// deliverNotice logs a transition and hands it to the frontend sinks. Called
// only from deliverPending, so the sinks see transitions in decision order.
func (s *PhoneService) deliverNotice(notice connNotice, emit PhoneEventEmitter, status PhoneStatusChangeFunc) {
	if notice.connected {
		s.log.Info("phone connected", "device", notice.deviceName)
	} else {
		s.log.Info("phone disconnected", "device", notice.deviceName, "reason", notice.reason)
	}

	if emit != nil {
		if notice.connected {
			emit(events.NewEvent(events.EventPhoneConnected, events.PhoneConnectedPayload{
				DeviceName: notice.deviceName,
			}))
		} else {
			emit(events.NewEvent(events.EventPhoneDisconnected, events.PhoneDisconnectedPayload{
				DeviceName: notice.deviceName,
				Reason:     notice.reason,
			}))
		}
	}

	if status != nil {
		if notice.connected {
			status(true, notice.deviceName)
		} else {
			status(false, "")
		}
	}
}

// awaitNoticesDelivered blocks until every queued transition has been handed to
// the frontend. Delivery is asynchronous, so a caller that needs to observe its
// effect — a test, or a shutdown path that wants the last status out — has to
// say so.
func (s *PhoneService) awaitNoticesDelivered() bool {
	deadline := time.Now().Add(noticeDeliveryTimeout)
	for {
		s.connMu.Lock()
		idle := !s.delivering && len(s.pending) == 0
		s.connMu.Unlock()
		if idle {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		runtime.Gosched()
	}
}

// noticeDeliveryTimeout bounds awaitNoticesDelivered. A frontend callback is
// caller-supplied and may not return; an unbounded wait here would turn a
// wedged systray handler into a wedged service, which is the same
// bound-the-wait reasoning as every drain on this branch.
var noticeDeliveryTimeout = 30 * time.Second

// loadAttestationTrust builds what every attestation this service performs is
// judged against: the trust store's Android hardware roots and devices.yaml's
// attested-application allow-list (#1305), through the same
// attestation.LoadTrust the CLI calls.
//
// A missing devices.yaml allow-lists nothing, so LoadTrust refuses with
// pairing.ErrApplicationPolicyUnconfigured. One that exists but cannot be read
// refuses outright: it may well be the file that lists the allowed builds, and
// guessing that it does not is how an unreadable policy becomes no policy.
func (s *PhoneService) loadAttestationTrust() (*xkeyAttestation.Trust, error) {
	cfg, err := s.loadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &SentinelCauseError{Sentinel: ErrPhoneAttestFailed, Cause: err}
	}
	return xkeyAttestation.LoadTrust(s.trustStore, cfg.applicationPolicy())
}

// loadConfig loads the phone config from the shared YAML file.
func (s *PhoneService) loadConfig() (*phoneConfig, error) {
	path, err := phoneConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg phoneConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// saveConfig writes the phone config to the shared YAML file.
func (s *PhoneService) saveConfig(cfg *phoneConfig) error {
	path, err := phoneConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// phoneConfigPath returns the path to the shared devices config file
// (~/.xkey/devices.yaml).
func phoneConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".xkey", devicesConfigFileName), nil
}

// hostname returns the local hostname.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "xKey Desktop"
	}
	return name
}

// parseDERChain parses a slice of DER-encoded certificates into x509 objects.
func parseDERChain(derChain [][]byte) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(derChain))
	for i, der := range derChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("certificate at index %d", i), Err: err}
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// findMatchingTrustRoot finds which trusted root certificate matches the
// last certificate in the device's chain.
func findMatchingTrustRoot(chain []*x509.Certificate, roots []*x509.Certificate) *x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	deviceRoot := chain[len(chain)-1]
	deviceRootFP := certFP(deviceRoot)
	for _, root := range roots {
		if certFP(root) == deviceRootFP {
			return root
		}
	}
	return nil
}

// certFP returns the SHA-256 fingerprint of a certificate as hex.
func certFP(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// pubKeyFP returns the SHA-256 fingerprint of a public key as hex.
func pubKeyFP(cert *x509.Certificate) string {
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(pubDER)
	return hex.EncodeToString(hash[:])
}

// formatTrustAnchorName returns a human-readable name for a trust anchor.
func formatTrustAnchorName(cert *x509.Certificate) string {
	if cert == nil {
		return "Unknown"
	}
	if len(cert.Subject.Organization) > 0 && cert.Subject.CommonName != "" {
		return cert.Subject.Organization[0] + " - " + cert.Subject.CommonName
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	if cert.Subject.SerialNumber != "" {
		return "Google Hardware Attestation Root (SN=" + cert.Subject.SerialNumber + ")"
	}
	return "Google Hardware Attestation Root"
}

// buildCertInfoList builds AttestCertInfo entries for the certificate chain.
func buildCertInfoList(chain, embeddedRoots []*x509.Certificate) []AttestCertInfo {
	infos := make([]AttestCertInfo, 0, len(chain))
	for i, cert := range chain {
		label := getCertLabel(i, len(chain))
		isTrustAnchor := false
		if i == len(chain)-1 {
			isTrustAnchor = findMatchingTrustRoot(chain, embeddedRoots) != nil
		}

		algo, size, curve := pubKeyAlgoInfo(cert)
		algoStr := algo
		if curve != "" {
			algoStr = fmt.Sprintf("%s %s (%d bits)", algo, curve, size)
		} else if size > 0 {
			algoStr = fmt.Sprintf("%s %d bits", algo, size)
		}

		infos = append(infos, AttestCertInfo{
			Label:         label,
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			Algorithm:     algoStr,
			PublicKeyFP:   pubKeyFP(cert),
			CertFP:        certFP(cert),
			NotBefore:     cert.NotBefore.Format(time.RFC3339),
			NotAfter:      cert.NotAfter.Format(time.RFC3339),
			IsCA:          cert.IsCA,
			IsTrustAnchor: isTrustAnchor,
		})
	}
	return infos
}

// getCertLabel returns a label for a certificate position in the chain.
func getCertLabel(index, total int) string {
	if index == 0 {
		return "Leaf"
	}
	if index == total-1 {
		return "Root"
	}
	if total > 3 {
		return fmt.Sprintf("Intermediate %d", index)
	}
	return "Intermediate"
}

// pubKeyAlgoInfo returns the public key algorithm, size, and curve name.
func pubKeyAlgoInfo(cert *x509.Certificate) (algo string, size int, curve string) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen(), ""
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize, pub.Curve.Params().Name
	default:
		return cert.PublicKeyAlgorithm.String(), 0, ""
	}
}

// Android Keymaster lookup maps for O(1) constant-time dispatch.
var keymasterPurposeNameMap = map[int]string{
	0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY",
	4: "DERIVE_KEY", 5: "WRAP_KEY", 6: "AGREE_KEY", 7: "ATTEST_KEY",
}

var keymasterAlgorithmNameMap = map[int]string{
	1: "RSA", 3: "EC", 32: "AES", 33: "TRIPLE_DES", 128: "HMAC",
}

var keymasterOriginNameMap = map[int]string{
	0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "UNKNOWN", 4: "SECURELY_IMPORTED",
}

// keymasterPurposeNameList converts Keymaster purpose codes to human-readable names.
func keymasterPurposeNameList(codes []int) []string {
	names := make([]string, 0, len(codes))
	for _, c := range codes {
		if name, ok := keymasterPurposeNameMap[c]; ok {
			names = append(names, name)
		} else {
			names = append(names, fmt.Sprintf("UNKNOWN(%d)", c))
		}
	}
	return names
}

// keymasterAlgorithmName converts a Keymaster algorithm code to a human-readable name.
func keymasterAlgorithmName(code int) string {
	if name, ok := keymasterAlgorithmNameMap[code]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", code)
}

// keymasterOriginName converts a Keymaster origin code to a human-readable name.
func keymasterOriginName(code int) string {
	if name, ok := keymasterOriginNameMap[code]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", code)
}

// verifiedBootStateNames provides O(1) lookup for boot state display names.
var verifiedBootStateNameMap = map[xkms.AndroidVerifiedBootState]string{
	xkms.AndroidVerifiedBootVerified:   "verified",
	xkms.AndroidVerifiedBootSelfSigned: "self-signed",
	xkms.AndroidVerifiedBootUnverified: "unverified",
	xkms.AndroidVerifiedBootFailed:     "failed",
}

// verifiedBootStateName converts an Android VerifiedBootState to a human-readable name.
func verifiedBootStateName(state xkms.AndroidVerifiedBootState) string {
	if name, ok := verifiedBootStateNameMap[state]; ok {
		return name
	}
	return "unknown"
}
