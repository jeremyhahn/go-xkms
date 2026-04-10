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

//go:build integration && linux

package fido2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
	"github.com/stretchr/testify/require"
)

// CTAP HID commands.
const (
	ctapHIDInit      = 0x86
	ctapHIDMsg       = 0x83
	ctapHIDCBOR      = 0x90
	ctapHIDCancel    = 0x91
	ctapHIDError     = 0xBF
	ctapHIDKeepalive = 0xBB
)

// CTAP2 commands.
const (
	cmdMakeCredential       = 0x01
	cmdGetAssertion         = 0x02
	cmdGetInfo              = 0x04
	cmdClientPIN            = 0x06
	cmdReset                = 0x07
	cmdGetNextAssertion     = 0x08
	cmdCredentialManagement = 0x0A
)

// CTAP2 status codes.
const (
	statusOK                = 0x00
	statusInvalidCommand    = 0x01
	statusInvalidParameter  = 0x02
	statusInvalidLength     = 0x03
	statusInvalidSeq        = 0x04
	statusTimeout           = 0x05
	statusChannelBusy       = 0x06
	statusNoCredentials     = 0x2E
	statusPINInvalid        = 0x31
	statusPINBlocked        = 0x32
	statusPINAuthInvalid    = 0x33
	statusPINAuthBlocked    = 0x34
	statusPINNotSet         = 0x35
	statusOperationDenied   = 0x27
	statusUserActionPending = 0x23
	statusUpRequired        = 0x2B
)

// ClientPIN subcommands.
const (
	pinSubCmdGetRetries                               = 0x01
	pinSubCmdGetKeyAgreement                          = 0x02
	pinSubCmdSetPIN                                   = 0x03
	pinSubCmdChangePIN                                = 0x04
	pinSubCmdGetPINToken                              = 0x05
	pinSubCmdGetPINUvAuthTokenUsingUvWithPermissions  = 0x06
	pinSubCmdGetUVRetries                             = 0x07
	pinSubCmdGetPINUvAuthTokenUsingPinWithPermissions = 0x09
)

// broadcastCID is the broadcast channel ID for CTAPHID_INIT.
var broadcastCID = [4]byte{0xFF, 0xFF, 0xFF, 0xFF}

// TestDevice wraps a virtual FIDO2 device for integration testing.
type TestDevice struct {
	t             *testing.T
	uhid          *uhid.Device
	auth          *authenticator.Authenticator
	hidHandler    *authenticator.CTAPHIDHandler
	storage       authenticator.StatefulCredentialStorage
	socketHandler *authenticator.SocketHandler
	ipcServer     *ipc.Server
	notifier      notify.Notifier
	logger        *slog.Logger
	cid           [4]byte
	running       atomic.Bool
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	responses     chan []byte
	storageDir    string
}

// TestDeviceConfig holds configuration for creating a test device.
type TestDeviceConfig struct {
	EnablePIN           bool
	PIN                 string
	EnableResidentKey   bool
	RequireUserPresence bool
	Interactive         bool
	StorageType         string // "memory" or "file"
	StoragePath         string
	NotifyType          string // "none", "log", "passive", "dialog"
	SocketPath          string
}

// createTestSoftwareBackend creates a software key backend adapter for tests.
func createTestSoftwareBackend(t *testing.T) keybackend.FIDO2KeyBackend {
	t.Helper()
	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err, "failed to create memory backend")
	provider, err := softwarebackend.NewBackend(&softwarebackend.Config{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err, "failed to create software key backend")
	return keybackend.NewBackendAdapter(provider, types.BackendTypeSoftware)
}

// DefaultTestConfig returns a default test configuration.
func DefaultTestConfig() *TestDeviceConfig {
	return &TestDeviceConfig{
		EnablePIN:           false,
		EnableResidentKey:   true,
		RequireUserPresence: false, // Auto-approve for tests
		Interactive:         false,
		StorageType:         "memory",
		NotifyType:          "log",
	}
}

// NewTestDevice creates a new test device with the given configuration.
func NewTestDevice(t *testing.T, cfg *TestDeviceConfig) *TestDevice {
	t.Helper()

	if cfg == nil {
		cfg = DefaultTestConfig()
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create storage
	var storage authenticator.StatefulCredentialStorage
	var storageDir string
	var err error

	switch cfg.StorageType {
	case "file":
		if cfg.StoragePath == "" {
			storageDir = t.TempDir()
		} else {
			storageDir = cfg.StoragePath
		}
		backend, err := file.New(storageDir)
		require.NoError(t, err)
		storage, err = authenticator.NewBackendStorage(backend, "xkey/")
		require.NoError(t, err)
	default:
		storage = authenticator.NewMemoryStorage()
	}

	// Create notifier
	var notifier notify.Notifier
	switch cfg.NotifyType {
	case "none":
		notifier = notify.NewMultiNotifier()
	case "log":
		notifier = notify.NewLogNotifier(logger)
	default:
		notifier = notify.NewLogNotifier(logger)
	}

	// Create user presence handler
	var upHandler authenticator.UserPresenceHandler
	var socketHandler *authenticator.SocketHandler

	if cfg.Interactive {
		upHandler, err = authenticator.NewInteractiveHandler()
		require.NoError(t, err)
	} else if cfg.RequireUserPresence {
		socketHandler = authenticator.NewSocketHandler(notifier, logger)
		upHandler = socketHandler
	} else {
		// Auto-approve for tests
		upHandler = &autoApproveHandler{}
	}

	// Create authenticator config
	authConfig := &authenticator.Config{
		EnablePIN:                  cfg.EnablePIN,
		EnableResidentKey:          cfg.EnableResidentKey,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		Storage:                    storage,
		UserPresenceHandler:        upHandler,
		UserPresenceTimeout:        5 * time.Second,
		RequireUserPresence:        cfg.RequireUserPresence,
		KeyBackend:                 createTestSoftwareBackend(t),
		AttestationFormat:          "none",
		Logger:                     logger,
	}

	auth, err := authenticator.NewAuthenticator(authConfig)
	require.NoError(t, err)

	// Set PIN if configured
	if cfg.EnablePIN && cfg.PIN != "" {
		err = auth.SetPINForTesting(cfg.PIN)
		require.NoError(t, err)
	}

	// Create CTAP-HID handler
	hidHandler := authenticator.NewCTAPHIDHandler(auth)
	hidHandler.SetLogger(logger)

	// Open UHID
	uhidDev, err := uhid.Open()
	require.NoError(t, err)

	td := &TestDevice{
		t:             t,
		uhid:          uhidDev,
		auth:          auth,
		hidHandler:    hidHandler,
		storage:       storage,
		socketHandler: socketHandler,
		notifier:      notifier,
		logger:        logger,
		responses:     make(chan []byte, 100),
		storageDir:    storageDir,
	}

	// Set response handler
	hidHandler.SetResponseHandler(func(packet []byte) {
		packetCopy := make([]byte, len(packet))
		copy(packetCopy, packet)
		select {
		case td.responses <- packetCopy:
		default:
			t.Logf("Response channel full, dropping packet")
		}
	})

	return td
}

// Start creates the virtual HID device and starts the event loop.
func (td *TestDevice) Start(ctx context.Context) error {
	if td.running.Load() {
		return errors.New("device already running")
	}

	// Create unique device name
	deviceName := fmt.Sprintf("xkey-test-%d", time.Now().UnixNano())
	serial := fmt.Sprintf("TEST%d", time.Now().UnixNano()%1000000)

	cfg := &uhid.CreateConfig{
		Name:             deviceName,
		Uniq:             serial,
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	if err := td.uhid.Create(cfg); err != nil {
		return fmt.Errorf("failed to create UHID device: %w", err)
	}

	td.running.Store(true)

	// Create cancellable context
	ctx, td.cancel = context.WithCancel(ctx)

	// Start IPC server if socket handler is configured
	if td.socketHandler != nil {
		socketPath := fmt.Sprintf("/tmp/xkey-test-%d/xkey.sock", os.Getpid())
		srv, err := ipc.NewServer(socketPath, td, td.logger)
		if err == nil {
			td.ipcServer = srv
			td.wg.Add(1)
			go func() {
				defer td.wg.Done()
				srv.Serve(ctx)
			}()
		}
	}

	// Start event loop
	td.wg.Add(1)
	go td.eventLoop(ctx)

	// Initialize channel
	if err := td.initChannel(); err != nil {
		td.Stop()
		return fmt.Errorf("failed to initialize channel: %w", err)
	}

	return nil
}

// Stop shuts down the test device.
func (td *TestDevice) Stop() {
	if !td.running.Load() {
		return
	}

	td.running.Store(false)

	if td.cancel != nil {
		td.cancel()
	}

	if td.ipcServer != nil {
		td.ipcServer.Close()
	}

	td.wg.Wait()

	if td.hidHandler != nil {
		td.hidHandler.Close()
	}

	if td.uhid != nil {
		td.uhid.Close()
	}

	if td.auth != nil {
		td.auth.Close()
	}

	if td.notifier != nil {
		td.notifier.Close()
	}

	close(td.responses)
}

// HandleTouch implements ipc.Handler for test device.
func (td *TestDevice) HandleTouch() (*ipc.Response, error) {
	if td.socketHandler != nil && td.socketHandler.HasPending() {
		td.socketHandler.Approve()
		return ipc.OKResponse(ipc.ActionApprovedUP), nil
	}
	return ipc.OKResponse(ipc.ActionNoPending), nil
}

// HandleTypePassword implements ipc.Handler.
func (td *TestDevice) HandleTypePassword(name string) (*ipc.Response, error) {
	return nil, errors.New("not implemented in test")
}

// HandleStatus implements ipc.Handler.
func (td *TestDevice) HandleStatus() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

// eventLoop processes HID packets from the UHID device.
func (td *TestDevice) eventLoop(ctx context.Context) {
	defer td.wg.Done()

	td.uhid.SetReadTimeout(100 * time.Millisecond)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := td.uhid.ReadOutput()
			if err != nil {
				if errors.Is(err, uhid.ErrTimeout) {
					continue
				}
				if errors.Is(err, uhid.ErrDeviceNotOpen) {
					return
				}
				continue
			}

			if len(packet) >= 64 {
				td.hidHandler.HandleMessage(packet)
			}
		}
	}
}

// initChannel performs CTAPHID_INIT to get a channel ID.
func (td *TestDevice) initChannel() error {
	// Build CTAPHID_INIT packet
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		return err
	}

	packet := make([]byte, 64)
	copy(packet[0:4], broadcastCID[:])
	packet[4] = ctapHIDInit | 0x80 // Init command with init bit
	packet[5] = 0x00               // Length high
	packet[6] = 0x08               // Length low (8 bytes nonce)
	copy(packet[7:15], nonce)

	// Send via HID handler directly (since we're testing internally)
	td.hidHandler.HandleMessage(packet)

	// Wait for response
	select {
	case resp := <-td.responses:
		if len(resp) < 17 {
			return errors.New("CTAPHID_INIT response too short")
		}
		// Extract allocated channel ID from response
		copy(td.cid[:], resp[15:19])
		td.logger.Info("channel initialized", slog.String("cid", fmt.Sprintf("%08X", td.cid)))
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("timeout waiting for CTAPHID_INIT response")
	}
}

// SendCBOR sends a CTAP2 CBOR command and waits for the response.
func (td *TestDevice) SendCBOR(cmd byte, data []byte) ([]byte, error) {
	// Build CTAPHID_CBOR payload (command byte + CBOR data)
	payload := append([]byte{cmd}, data...)
	payloadLen := len(payload)

	// Maximum payload in init packet (64 - 7 header bytes)
	const initPayloadSize = 57
	// Maximum payload in continuation packet (64 - 5 header bytes)
	const contPayloadSize = 59

	// Create initialization packet
	initPacket := make([]byte, 64)
	copy(initPacket[0:4], td.cid[:])
	initPacket[4] = ctapHIDCBOR | 0x80 // CBOR command with init bit
	binary.BigEndian.PutUint16(initPacket[5:7], uint16(payloadLen))

	// Copy what fits in init packet
	initCopyLen := payloadLen
	if initCopyLen > initPayloadSize {
		initCopyLen = initPayloadSize
	}
	copy(initPacket[7:], payload[:initCopyLen])

	// Send init packet
	td.hidHandler.HandleMessage(initPacket)

	// Send continuation packets if needed
	remaining := payload[initCopyLen:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, 64)
		copy(contPacket[0:4], td.cid[:])
		contPacket[4] = seq // Sequence number (no 0x80 bit)

		copyLen := len(remaining)
		if copyLen > contPayloadSize {
			copyLen = contPayloadSize
		}
		copy(contPacket[5:], remaining[:copyLen])

		td.hidHandler.HandleMessage(contPacket)
		remaining = remaining[copyLen:]
		seq++
	}

	// Wait for response (may need multiple packets)
	return td.collectResponse(10 * time.Second)
}

// collectResponse collects a multi-packet response.
func (td *TestDevice) collectResponse(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var result []byte
	var expectedLen int
	var gotInit bool

	for time.Now().Before(deadline) {
		select {
		case resp := <-td.responses:
			if len(resp) < 7 {
				continue
			}

			// Check channel ID
			if resp[0] != td.cid[0] || resp[1] != td.cid[1] ||
				resp[2] != td.cid[2] || resp[3] != td.cid[3] {
				continue
			}

			cmd := resp[4]

			// Check for error response
			if cmd == ctapHIDError|0x80 {
				if len(resp) > 7 {
					return nil, fmt.Errorf("CTAPHID error: 0x%02X", resp[7])
				}
				return nil, errors.New("CTAPHID error")
			}

			// Check for keepalive
			if cmd == ctapHIDKeepalive|0x80 {
				continue
			}

			if cmd&0x80 != 0 {
				// Initialization packet
				gotInit = true
				expectedLen = int(binary.BigEndian.Uint16(resp[5:7]))
				maxData := 64 - 7
				if expectedLen <= maxData {
					result = make([]byte, expectedLen)
					copy(result, resp[7:7+expectedLen])
					return result, nil
				}
				result = make([]byte, 0, expectedLen)
				result = append(result, resp[7:]...)
			} else if gotInit {
				// Continuation packet
				result = append(result, resp[5:]...)
				if len(result) >= expectedLen {
					return result[:expectedLen], nil
				}
			}

		case <-time.After(100 * time.Millisecond):
			continue
		}
	}

	if len(result) > 0 {
		return result, nil
	}
	return nil, errors.New("timeout waiting for response")
}

// MakeCredential performs a CTAP2 MakeCredential operation.
func (td *TestDevice) MakeCredential(rpID, rpName, userName, userDisplayName string, userID []byte, resident bool) (*MakeCredentialResult, error) {
	clientDataHash := make([]byte, 32)
	_, err := rand.Read(clientDataHash)
	if err != nil {
		return nil, err
	}

	req := map[int]interface{}{
		1: clientDataHash,
		2: map[string]interface{}{"id": rpID, "name": rpName},
		3: map[string]interface{}{
			"id":          userID,
			"name":        userName,
			"displayName": userDisplayName,
		},
		4: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": -7}, // ES256
		},
	}

	if resident {
		req[7] = map[string]interface{}{"rk": true}
	}

	data, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := td.SendCBOR(cmdMakeCredential, data)
	if err != nil {
		return nil, err
	}

	if len(resp) == 0 {
		return nil, errors.New("empty response")
	}

	status := resp[0]
	if status != statusOK {
		return nil, fmt.Errorf("MakeCredential failed with status 0x%02X", status)
	}

	// Decode response
	var result map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	authData, ok := result[2].([]byte)
	if !ok {
		return nil, errors.New("missing authData in response")
	}

	// Parse authData to extract credential ID and public key
	if len(authData) < 55 {
		return nil, errors.New("authData too short")
	}

	offset := 37 // rpIdHash(32) + flags(1) + signCount(4)
	offset += 16 // aaguid
	credIDLen := int(authData[offset])<<8 | int(authData[offset+1])
	offset += 2
	credentialID := make([]byte, credIDLen)
	copy(credentialID, authData[offset:offset+credIDLen])
	offset += credIDLen
	publicKeyCOSE := authData[offset:]

	return &MakeCredentialResult{
		CredentialID:   credentialID,
		PublicKeyCOSE:  publicKeyCOSE,
		AuthData:       authData,
		ClientDataHash: clientDataHash,
		RPID:           rpID,
	}, nil
}

// GetAssertion performs a CTAP2 GetAssertion operation.
func (td *TestDevice) GetAssertion(rpID string, credentialID []byte, clientDataHash []byte) (*GetAssertionResult, error) {
	if clientDataHash == nil {
		clientDataHash = make([]byte, 32)
		_, err := rand.Read(clientDataHash)
		if err != nil {
			return nil, err
		}
	}

	req := map[int]interface{}{
		1: rpID,
		2: clientDataHash,
	}

	if credentialID != nil {
		req[3] = []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   credentialID,
			},
		}
	}

	data, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := td.SendCBOR(cmdGetAssertion, data)
	if err != nil {
		return nil, err
	}

	if len(resp) == 0 {
		return nil, errors.New("empty response")
	}

	status := resp[0]
	if status != statusOK {
		return nil, fmt.Errorf("GetAssertion failed with status 0x%02X", status)
	}

	// Decode response
	var result map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	authData, ok := result[2].([]byte)
	if !ok {
		return nil, errors.New("missing authData")
	}

	signature, ok := result[3].([]byte)
	if !ok {
		return nil, errors.New("missing signature")
	}

	return &GetAssertionResult{
		AuthData:       authData,
		Signature:      signature,
		ClientDataHash: clientDataHash,
	}, nil
}

// GetInfo retrieves authenticator information.
func (td *TestDevice) GetInfo() (*GetInfoResult, error) {
	resp, err := td.SendCBOR(cmdGetInfo, nil)
	if err != nil {
		return nil, err
	}

	if len(resp) == 0 {
		return nil, errors.New("empty response")
	}

	status := resp[0]
	if status != statusOK {
		return nil, fmt.Errorf("GetInfo failed with status 0x%02X", status)
	}

	var result map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	info := &GetInfoResult{}

	if versions, ok := result[1].([]interface{}); ok {
		for _, v := range versions {
			if s, ok := v.(string); ok {
				info.Versions = append(info.Versions, s)
			}
		}
	}

	if aaguid, ok := result[3].([]byte); ok {
		copy(info.AAGUID[:], aaguid)
	}

	if options, ok := result[4].(map[interface{}]interface{}); ok {
		info.Options = make(map[string]bool)
		for k, v := range options {
			if ks, ok := k.(string); ok {
				if vb, ok := v.(bool); ok {
					info.Options[ks] = vb
				}
			}
		}
	}

	return info, nil
}

// VerifySignature verifies an assertion signature using the public key.
func VerifySignature(publicKeyCOSE, authData, clientDataHash, signature []byte) (bool, error) {
	pubKey, _, err := authenticator.DecodeCOSEPublicKey(publicKeyCOSE)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("public key is not ECDSA")
	}

	// WebAuthn signature is over authData || clientDataHash
	signData := make([]byte, len(authData)+len(clientDataHash))
	copy(signData, authData)
	copy(signData[len(authData):], clientDataHash)

	digest := sha256.Sum256(signData)
	return ecdsa.VerifyASN1(ecPubKey, digest[:], signature), nil
}

// MakeCredentialResult holds the result of a MakeCredential operation.
type MakeCredentialResult struct {
	CredentialID   []byte
	PublicKeyCOSE  []byte
	AuthData       []byte
	ClientDataHash []byte
	RPID           string
}

// GetAssertionResult holds the result of a GetAssertion operation.
type GetAssertionResult struct {
	AuthData       []byte
	Signature      []byte
	ClientDataHash []byte
	UserID         []byte
}

// GetInfoResult holds the result of a GetInfo operation.
type GetInfoResult struct {
	Versions []string
	AAGUID   [16]byte
	Options  map[string]bool
}

// autoApproveHandler auto-approves all user presence requests (for testing).
type autoApproveHandler struct{}

func (h *autoApproveHandler) RequestUserPresence(ctx context.Context, req *authenticator.UserPresenceRequest) (*authenticator.UserPresenceResult, error) {
	return &authenticator.UserPresenceResult{Approved: true}, nil
}

func (h *autoApproveHandler) RequestUserVerification(ctx context.Context, req *authenticator.UserVerificationRequest) (*authenticator.UserVerificationResult, error) {
	return nil, authenticator.ErrTerminalUnavailable
}

// skipIfNoUHID skips the test if /dev/uhid is not available or not accessible.
func skipIfNoUHID(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("UHID not available: %v", err)
	}
	f.Close()
}

// Compile-time check for ipc.Handler.
var _ ipc.Handler = (*TestDevice)(nil)
