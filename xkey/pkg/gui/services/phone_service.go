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
	cryptorand "crypto/rand"
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
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Phone service errors.
var (
	ErrPhoneNotConnected         = errors.New("phone_service: no device connected")
	ErrPhoneDeviceNotFound       = errors.New("phone_service: device not found")
	ErrPhoneScanFailed           = errors.New("phone_service: scan failed")
	ErrPhonePairFailed           = errors.New("phone_service: pairing failed")
	ErrPhoneAttestFailed         = errors.New("phone_service: attestation failed")
	ErrPhoneInvalidTimeout       = errors.New("phone_service: invalid timeout value")
	ErrPhoneBLEUnavailable       = errors.New("phone_service: bluetooth unavailable - ensure bluetooth is enabled")
	ErrPhoneAlreadyPaired        = errors.New("phone_service: device already paired")
	ErrPhoneAttestNotImplemented = errors.New("phone_service: attestation requires BLE connection to device")
	ErrPhoneConnectFailed        = errors.New("phone_service: BLE connection failed")
	ErrPhoneHandshakeFailed      = errors.New("phone_service: Noise handshake failed")
	ErrPhoneMissingKeys          = errors.New("phone_service: device missing Noise keys - re-pair required")
	ErrPhonePolicyViolation      = errors.New("phone_service: attestation policy violation")
	ErrPhonePolicyNotSet         = errors.New("phone_service: no attestation policy set for device")
)

// devicesConfigFileName is the config file shared with the CLI.
const devicesConfigFileName = "devices.yaml"

// legacyPhoneConfigFileName is the old config file name for migration.
const legacyPhoneConfigFileName = "phone.yaml"

// PhoneEventEmitter is called to emit phone-related events to the frontend.
type PhoneEventEmitter func(evt events.Event)

// PhoneStatusChangeFunc is called when the phone connection status changes.
// This allows the systray and other components to react to phone events.
type PhoneStatusChangeFunc func(connected bool, deviceName string)

// PairedDevice describes a phone that has been previously paired.
type PairedDevice struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	PairedAt  time.Time `json:"paired_at"`
	LastSeen  time.Time `json:"last_seen"`
	Connected bool      `json:"connected"`
	IsBackend bool      `json:"is_backend"`
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

// savedAttestationData records the last successful attestation result for persistence.
type savedAttestationData struct {
	Verified      bool      `yaml:"verified"`
	SecurityLevel string    `yaml:"security_level"`
	BootHash      string    `yaml:"boot_hash"`
	BootKeyHash   string    `yaml:"boot_key_hash"`
	BootState     string    `yaml:"boot_state"`
	DeviceLocked  bool      `yaml:"device_locked"`
	Timestamp     time.Time `yaml:"timestamp"`
}

// attestationPolicy defines the expected attestation properties for a device.
// When enabled, subsequent attestations are compared against the policy.
type attestationPolicy struct {
	Enabled       bool      `yaml:"enabled"`
	BootHash      string    `yaml:"boot_hash"`
	BootKeyHash   string    `yaml:"boot_key_hash"`
	BootState     string    `yaml:"boot_state"`
	DeviceLocked  bool      `yaml:"device_locked"`
	SecurityLevel string    `yaml:"min_security_level"`
	SetAt         time.Time `yaml:"set_at"`
}

// phoneConfigDevice mirrors the CLI PairedDevice YAML structure.
type phoneConfigDevice struct {
	Name                      string                `yaml:"name"`
	Address                   string                `yaml:"address"`
	NoisePublicKey            string                `yaml:"noise_public_key"`
	LocalNoisePrivateKey      string                `yaml:"local_noise_private_key"`
	PairedAt                  time.Time             `yaml:"paired_at"`
	LastDeviceAttestationTime time.Time             `yaml:"last_device_attestation_time,omitempty"`
	SecurityLevel             string                `yaml:"security_level,omitempty"`
	BootStateVerified         bool                  `yaml:"boot_state_verified,omitempty"`
	DeviceFingerprint         string                `yaml:"device_fingerprint,omitempty"`
	LastAttestation           *savedAttestationData `yaml:"last_attestation,omitempty"`
	AttestationPolicy         *attestationPolicy    `yaml:"attestation_policy,omitempty"`
	IsBackend                 bool                  `yaml:"is_backend,omitempty"`
}

// phoneConfig mirrors the CLI PhoneConfig YAML structure.
type phoneConfig struct {
	Devices       []phoneConfigDevice `yaml:"devices"`
	DefaultDevice string              `yaml:"default_device"`
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

	// Active BLE connection state (protected by connMu).
	// A mutex is appropriate here because Connect and Disconnect are slow
	// I/O operations that happen infrequently (user-initiated).
	connMu          sync.Mutex
	activeTransport *phone.BLETransport // nil when disconnected
	activeSession   *phone.NoiseSession // nil when disconnected
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
	s.eventEmitter = fn
}

// SetStatusChangeFunc sets the callback invoked when phone connection state changes.
func (s *PhoneService) SetStatusChangeFunc(fn PhoneStatusChangeFunc) {
	s.statusChangeFn = fn
}

// SetTrustStore sets the trust store used for attestation verification.
func (s *PhoneService) SetTrustStore(ts truststore.TrustStore) {
	s.trustStore = ts
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
		devices = append(devices, PairedDevice{
			Name:      d.Name,
			Address:   d.Address,
			PairedAt:  d.PairedAt,
			LastSeen:  d.LastDeviceAttestationTime,
			Connected: connected,
			IsBackend: d.IsBackend,
		})
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
	defer transport.Close()

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
func (s *PhoneService) Pair(address string) (*PairedDevice, error) {
	if address == "" {
		return nil, ErrPhonePairFailed
	}

	s.log.Info("starting pairing", "address", address)

	// Generate a local Noise static key for this pairing.
	localKey, err := phone.GenerateStaticKey()
	if err != nil {
		s.log.Error("failed to generate local key", "error", err)
		return nil, ErrPhonePairFailed
	}

	// Create a Noise session.
	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
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
	defer transport.Close()

	// Connect to the device.
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer connectCancel()

	s.log.Info("connecting to device", "address", address)
	if err := transport.Connect(connectCtx, address); err != nil {
		s.log.Error("BLE connection failed", "address", address, "error", err)
		return nil, ErrPhonePairFailed
	}

	// Perform Noise XX handshake.
	s.log.Info("performing Noise handshake")
	handshakeCfg := &phone.HandshakeConfig{
		Transport:           transport,
		Session:             session,
		Logger:              s.log,
		StripEnvelopeHeader: false,
		EnvelopeHeaderSize:  0,
	}
	if err := phone.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		transport.Disconnect()
		s.log.Error("Noise handshake failed", "error", err)
		return nil, ErrPhonePairFailed
	}

	// Send pairing confirmation to phone.
	s.log.Info("sending pairing confirmation")
	deviceName := hostname()
	pairingReq := phone.NewRequest(phone.MethodPairingConfirm, &phone.PairingConfirmParams{
		DeviceName:   deviceName,
		PublicKeyHex: hex.EncodeToString(session.LocalStaticPublicKey()),
	})
	pairingPlaintext, err := phone.EncodeRequest(pairingReq)
	if err != nil {
		transport.Disconnect()
		return nil, ErrPhonePairFailed
	}
	pairingCiphertext, err := session.Encrypt(pairingPlaintext)
	if err != nil {
		transport.Disconnect()
		return nil, ErrPhonePairFailed
	}
	respCiphertext, err := transport.SendAndReceive(connectCtx, pairingCiphertext)
	if err != nil {
		transport.Disconnect()
		return nil, ErrPhonePairFailed
	}
	respPlaintext, err := session.Decrypt(respCiphertext)
	if err != nil {
		transport.Disconnect()
		return nil, ErrPhonePairFailed
	}
	pairingResp, err := phone.DecodeResponse(respPlaintext)
	if err != nil {
		transport.Disconnect()
		return nil, ErrPhonePairFailed
	}
	if pairingResp.Error != nil {
		transport.Disconnect()
		s.log.Error("phone rejected pairing", "error", pairingResp.Error.Message)
		return nil, ErrPhonePairFailed
	}
	pairingResult, err := phone.DecodeResult[phone.PairingConfirmResult](pairingResp)
	if err != nil {
		transport.Disconnect()
		return nil, ErrPhonePairFailed
	}
	if !pairingResult.Confirmed {
		transport.Disconnect()
		return nil, phone.ErrPairingRejected
	}

	phoneName := pairingResult.DeviceName
	remotePublicKey := session.RemoteStaticPublicKey()

	// Disconnect after pairing (reconnects on demand).
	transport.Disconnect()

	// Save to shared config file.
	now := time.Now().UTC()
	cfgDevice := phoneConfigDevice{
		Name:                 phoneName,
		Address:              address,
		NoisePublicKey:       base64.StdEncoding.EncodeToString(remotePublicKey),
		LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localKey.Private),
		PairedAt:             now,
	}

	cfg, err := s.loadConfig()
	if err != nil {
		cfg = &phoneConfig{Devices: []phoneConfigDevice{}}
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

	s.log.Info("pairing complete", "device", phoneName, "address", address)

	return &PairedDevice{
		Name:     phoneName,
		Address:  address,
		PairedAt: now,
	}, nil
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

	// If the unpaired device is currently connected, close the BLE transport and disconnect.
	if s.connState.connected.Load() && s.ConnectedDeviceName() == name {
		s.connMu.Lock()
		s.closeActiveConnectionLocked()
		s.connMu.Unlock()
		s.setDisconnected(name, "unpaired")
	}

	return s.saveConfig(cfg)
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
		devices = append(devices, PairedDevice{
			Name:      d.Name,
			Address:   d.Address,
			PairedAt:  d.PairedAt,
			LastSeen:  d.LastDeviceAttestationTime,
			Connected: connected,
			IsBackend: true,
		})
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

	// Decode saved Noise keys.
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		s.log.Error("invalid local noise key", "device", name, "error", err)
		return ErrPhoneMissingKeys
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		s.log.Error("invalid phone noise key", "device", name, "error", err)
		return ErrPhoneMissingKeys
	}

	// Reconstruct the local Noise DH key pair.
	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		s.log.Error("failed to load local static key", "device", name, "error", err)
		return ErrPhoneMissingKeys
	}

	// Decode expected device fingerprint if available.
	var expectedFingerprint []byte
	if device.DeviceFingerprint != "" {
		expectedFingerprint, err = hex.DecodeString(device.DeviceFingerprint)
		if err != nil {
			s.log.Warn("invalid device fingerprint, skipping verification", "error", err)
			expectedFingerprint = nil
		}
	}

	// Create Noise session with expected remote static key.
	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
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
		transport.Close()
		s.log.Error("BLE connection failed", "device", name, "address", device.Address, "error", err)
		return ErrPhoneConnectFailed
	}

	// Perform Noise XX handshake with identity exchange for prologue binding.
	s.log.Info("performing Noise handshake", "device", name)
	handshakeCfg := &phone.HandshakeConfig{
		Transport:                 transport,
		Session:                   session,
		Logger:                    s.log,
		StripEnvelopeHeader:       false,
		EnvelopeHeaderSize:        0,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expectedFingerprint,
	}
	if err := phone.PerformHandshake(connectCtx, handshakeCfg); err != nil {
		transport.Disconnect()
		transport.Close()
		s.log.Error("Noise handshake failed", "device", name, "error", err)
		return ErrPhoneHandshakeFailed
	}

	// Store transport + session on PhoneService fields.
	s.connMu.Lock()
	s.closeActiveConnectionLocked()
	s.activeTransport = transport
	s.activeSession = session
	s.connMu.Unlock()

	// Update connection state and emit events.
	s.setConnected(name)

	s.log.Info("connected to device", "device", name, "address", device.Address)

	// Auto-attestation: enforce policy if enabled, or refresh if previously attested.
	s.autoAttest(cfg, device, name)

	return nil
}

// Disconnect terminates the BLE connection to the named device.
func (s *PhoneService) Disconnect(name string) error {
	if name == "" {
		return ErrPhoneDeviceNotFound
	}

	s.connMu.Lock()
	s.closeActiveConnectionLocked()
	s.connMu.Unlock()

	s.setDisconnected(name, "user_requested")

	return nil
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
		return fmt.Errorf("%w: attestation failed: %v", ErrPhonePolicyViolation, err)
	}

	if !result.Verified {
		s.emitPolicyViolationEvent(deviceName, map[string]string{
			"verification": "attestation chain not verified",
		}, "Attestation verification failed")
		return fmt.Errorf("%w: attestation chain not verified", ErrPhonePolicyViolation)
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
		return fmt.Errorf("%w: %s", ErrPhonePolicyViolation, msg)
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

// performAttestation runs the attestation flow using the active BLE connection.
// It sends an attestation challenge over the existing encrypted Noise channel
// and verifies the returned Android hardware certificate chain.
func (s *PhoneService) performAttestation(device *phoneConfigDevice) (*AttestationResult, error) {
	// Grab the active transport and session under lock.
	s.connMu.Lock()
	transport := s.activeTransport
	session := s.activeSession
	s.connMu.Unlock()

	if transport == nil || session == nil {
		return nil, ErrPhoneNotConnected
	}

	// Generate 32-byte random nonce.
	nonce := make([]byte, 32)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: nonce generation failed", ErrPhoneAttestFailed)
	}

	// Send attestation request via encrypted BLE.
	attestReq := phone.NewRequest(phone.MethodLocalAttestKey, &phone.LocalAttestKeyParams{
		KeyID: "device-attest",
		Nonce: nonce,
	})
	reqPlaintext, err := phone.EncodeRequest(attestReq)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request failed", ErrPhoneAttestFailed)
	}
	reqCiphertext, err := session.Encrypt(reqPlaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypt failed", ErrPhoneAttestFailed)
	}

	opCtx, opCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer opCancel()

	respCiphertext, err := transport.SendAndReceive(opCtx, reqCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: send/receive failed", ErrPhoneAttestFailed)
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
		return nil, fmt.Errorf("%w: decrypt failed", ErrPhoneAttestFailed)
	}

	resp, err := phone.DecodeResponse(respPlaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: decode response failed", ErrPhoneAttestFailed)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("%w: %s", ErrPhoneAttestFailed, resp.Error.Message)
	}

	attestResult, err := phone.DecodeResult[phone.LocalAttestKeyResult](resp)
	if err != nil {
		return nil, fmt.Errorf("%w: decode result failed", ErrPhoneAttestFailed)
	}

	// Parse DER certificate chain.
	chain, err := parseDERChain(attestResult.CertificateChain)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid cert chain", ErrPhoneAttestFailed)
	}

	// Build trust pool from embedded roots + local trust store.
	embeddedRoots := truststore.LoadEmbeddedRoots(truststore.PurposeAndroidHardware)

	rootPool, err := s.buildAttestationTrustPool(embeddedRoots)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPhoneAttestFailed, err)
	}

	// Verify attestation chain.
	verifyOpts := &android.VerifyOptions{
		TrustedRoots:  rootPool,
		ExpectedNonce: nonce,
	}

	desc, verifyErr := android.VerifyKeyAttestation(chain, verifyOpts)

	now := time.Now()
	result := &AttestationResult{
		DeviceName:  device.Name,
		Verified:    verifyErr == nil,
		ChainLength: len(chain),
		AttestTime:  now,
	}
	if verifyErr != nil {
		result.ErrorMessage = verifyErr.Error()
	}

	// Build certificate info list.
	result.Certificates = buildCertInfoList(chain, embeddedRoots)

	// Find trust anchor.
	matchedRoot := findMatchingTrustRoot(chain, embeddedRoots)
	if matchedRoot != nil {
		result.TrustAnchorSubject = formatTrustAnchorName(matchedRoot)
		result.TrustAnchorFingerprint = certFP(matchedRoot)
	}

	// Populate extension data if verification succeeded.
	if desc != nil {
		result.AttestVersion = desc.AttestationVersion
		result.SecurityLevel = desc.AttestationSecurityLevel.String()
		result.KeymasterVersion = desc.KeymasterVersion
		result.KeymasterSecurity = desc.KeymasterSecurityLevel.String()

		// TEE enforced authorization.
		tee := &desc.TeeEnforced
		if tee.Algorithm > 0 {
			result.KeyAlgorithm = keymasterAlgorithmName(tee.Algorithm)
		}
		result.KeySize = tee.KeySize
		result.KeyPurposes = keymasterPurposeNameList(tee.Purpose)
		if tee.Origin > 0 {
			result.KeyOrigin = keymasterOriginName(tee.Origin)
		}

		// Root of Trust.
		if tee.RootOfTrust != nil {
			rot := tee.RootOfTrust
			result.BootKeyHash = hex.EncodeToString(rot.VerifiedBootKey)
			result.BootHash = hex.EncodeToString(rot.VerifiedBootHash)
			result.BootState = verifiedBootStateName(rot.VerifiedBootState)
			result.DeviceLocked = rot.DeviceLocked
		}
	}

	return result, nil
}

// buildAttestationTrustPool constructs an x509.CertPool for Android hardware
// attestation verification, merging the local trust store with embedded roots.
func (s *PhoneService) buildAttestationTrustPool(embeddedRoots []*x509.Certificate) (*x509.CertPool, error) {
	if s.trustStore != nil {
		verifier, err := xkeyAttestation.NewVerifier(s.trustStore, truststore.LoadEmbeddedRoots)
		if err != nil {
			return nil, fmt.Errorf("verifier creation failed: %w", err)
		}
		pool, err := verifier.BuildTrustPool(truststore.PurposeAndroidHardware)
		if err != nil {
			return nil, fmt.Errorf("trust pool build failed: %w", err)
		}
		return pool, nil
	}

	// Fallback: use only embedded roots.
	pool := x509.NewCertPool()
	for _, root := range embeddedRoots {
		pool.AddCert(root)
	}
	return pool, nil
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
	device.LastAttestation = &savedAttestationData{
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
			cfg.Devices[i].AttestationPolicy = &attestationPolicy{
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
func (s *PhoneService) GetAttestationPolicy(deviceName string) (*attestationPolicy, error) {
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

// closeActiveConnectionLocked closes the active BLE transport and clears session state.
// Must be called with connMu held.
func (s *PhoneService) closeActiveConnectionLocked() {
	if s.activeTransport != nil {
		s.activeTransport.Disconnect()
		s.activeTransport.Close()
		s.activeTransport = nil
	}
	s.activeSession = nil
}

// autoAttest performs automatic attestation after a successful connection.
// If an attestation policy is enabled, it enforces the policy.
// If the device has been previously attested (but no policy), it refreshes attestation.
func (s *PhoneService) autoAttest(cfg *phoneConfig, device *phoneConfigDevice, name string) {
	// Enforce attestation policy if enabled.
	if device.AttestationPolicy != nil && device.AttestationPolicy.Enabled {
		if err := s.enforceAttestationPolicy(name, device); err != nil {
			s.log.Error("attestation policy enforcement failed on connect", "device", name, "error", err)
			s.connMu.Lock()
			s.closeActiveConnectionLocked()
			s.connMu.Unlock()
			s.setDisconnected(name, "policy_violation")
			return
		}
		s.log.Info("attestation policy enforced successfully", "device", name)
		return
	}

	// If device was previously attested, perform a fresh attestation.
	if device.LastAttestation != nil {
		s.log.Info("auto-attesting previously attested device", "device", name)
		result, err := s.performAttestation(device)
		if err != nil {
			s.log.Warn("auto-attestation failed", "device", name, "error", err)
			s.emitAttestationEvent(name, false, err.Error())
			return
		}
		s.saveAttestationResult(cfg, device, result)
		s.emitAttestationEvent(name, result.Verified, "")
		s.log.Info("auto-attestation complete", "device", name, "verified", result.Verified)
	}
}

// setConnected updates the internal state to reflect a connected phone device.
func (s *PhoneService) setConnected(deviceName string) {
	s.connState.deviceName.Store(deviceName)
	s.connState.connected.Store(true)

	s.log.Info("phone connected", "device", deviceName)

	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventPhoneConnected, events.PhoneConnectedPayload{
			DeviceName: deviceName,
		}))
	}

	if s.statusChangeFn != nil {
		s.statusChangeFn(true, deviceName)
	}
}

// setDisconnected updates the internal state to reflect a disconnected phone device.
func (s *PhoneService) setDisconnected(deviceName string, reason string) {
	s.connState.connected.Store(false)
	s.connState.deviceName.Store("")

	s.log.Info("phone disconnected", "device", deviceName, "reason", reason)

	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventPhoneDisconnected, events.PhoneDisconnectedPayload{
			DeviceName: deviceName,
			Reason:     reason,
		}))
	}

	if s.statusChangeFn != nil {
		s.statusChangeFn(false, "")
	}
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

// phoneConfigPath returns the path to the shared devices config file (~/.xkey/devices.yaml).
// Migrates from legacy phone.yaml if the new file does not exist.
func phoneConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(home, ".xkey")
	newPath := filepath.Join(configDir, devicesConfigFileName)
	legacyPath := filepath.Join(configDir, legacyPhoneConfigFileName)

	// Migrate phone.yaml → devices.yaml if the new file does not exist
	if _, err := os.Stat(newPath); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(legacyPath); err == nil {
			_ = os.Rename(legacyPath, newPath)
		}
	}
	return newPath, nil
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
			return nil, fmt.Errorf("certificate at index %d: %w", i, err)
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
var verifiedBootStateNameMap = map[android.VerifiedBootState]string{
	android.VerifiedBootVerified:   "verified",
	android.VerifiedBootSelfSigned: "self-signed",
	android.VerifiedBootUnverified: "unverified",
	android.VerifiedBootFailed:     "failed",
}

// verifiedBootStateName converts an Android VerifiedBootState to a human-readable name.
func verifiedBootStateName(state android.VerifiedBootState) string {
	if name, ok := verifiedBootStateNameMap[state]; ok {
		return name
	}
	return "unknown"
}
