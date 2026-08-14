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

//go:build ble

package phone

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"tinygo.org/x/bluetooth"
)

// handshakeReceiveTimeout bounds how long the peripheral waits for each
// handshake message. An established session has no such bound: it waits for
// the next request until the context is cancelled or the peripheral stops.
const handshakeReceiveTimeout = 30 * time.Second

// BLE Peripheral errors.
var (
	ErrPeripheralAlreadyRunning = errors.New("phone: peripheral already running")
	ErrPeripheralNotRunning     = errors.New("phone: peripheral not running")
	ErrPeripheralStartFailed    = errors.New("phone: failed to start peripheral")
	ErrClientDisconnected       = errors.New("phone: client disconnected")
)

// BLEPeripheralConfig configures the BLE peripheral (server) mode.
type BLEPeripheralConfig struct {
	// LocalStaticKey is the persistent local Noise static key.
	// If nil, a new key will be generated.
	LocalStaticKey *noise.DHKey

	// ExpectedRemoteStatic is the expected phone's static public key.
	// If set, connection will fail if the phone's key doesn't match.
	ExpectedRemoteStatic []byte

	// DeviceName is the advertised device name.
	DeviceName string

	// MTU is the preferred Maximum Transmission Unit. Values below MinMTU
	// fall back to DefaultMTU.
	MTU int

	// AdapterID selects the local Bluetooth adapter (for example "hci1").
	// Empty uses the system default adapter.
	AdapterID string

	// Logger is the structured logger.
	Logger *slog.Logger

	// RequestHandler processes incoming requests from the phone.
	// If nil, requests are logged but not processed.
	RequestHandler PeripheralRequestHandler
}

// PeripheralRequestHandler handles incoming requests from phone.
type PeripheralRequestHandler interface {
	// HandleRequest processes a JSON-RPC request and returns a response.
	HandleRequest(ctx context.Context, request []byte) ([]byte, error)
}

// BLEPeripheral manages BLE peripheral (GATT server) mode.
// This allows the phone to connect to the laptop and send requests.
type BLEPeripheral struct {
	cfg    *BLEPeripheralConfig
	log    *slog.Logger
	closed atomic.Bool

	adapter *bluetooth.Adapter

	// GATT characteristics. The handles are bound by AddService and are what
	// the peripheral writes to in order to notify the connected central.
	controlPoint *bluetooth.Characteristic
	response     *bluetooth.Characteristic
	status       *bluetooth.Characteristic

	// notifier is the writer that carries outbound fragments. It is the
	// response characteristic in production; tests substitute an in-memory
	// writer to exercise the notify path without hardware.
	notifier FragmentWriter

	// sender fragments and notifies outbound messages.
	sender *fragmentSender

	// Session state
	mu         sync.Mutex
	session    *NoiseSession
	connected  atomic.Bool
	clientAddr string
	mtu        int

	// Fragmentation
	fragmenter  *Fragmenter
	reassembler *Reassembler

	// Channels for communication
	incomingData chan []byte
	stopChan     chan struct{}
}

// NewBLEPeripheral creates a new BLE peripheral.
func NewBLEPeripheral(cfg *BLEPeripheralConfig) (*BLEPeripheral, error) {
	if cfg == nil {
		cfg = &BLEPeripheralConfig{}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.DeviceName == "" {
		cfg.DeviceName = "xKey"
	}

	mtu := cfg.MTU
	if mtu < MinMTU {
		mtu = DefaultMTU
	}

	return &BLEPeripheral{
		cfg:          cfg,
		log:          logger.With("component", "ble_peripheral"),
		mtu:          mtu,
		incomingData: make(chan []byte, 100),
		stopChan:     make(chan struct{}),
	}, nil
}

// Start begins advertising and accepting connections.
func (p *BLEPeripheral) Start(ctx context.Context) error {
	if p.closed.Load() {
		return ErrBackendClosed
	}

	p.log.Info("starting BLE peripheral",
		slog.String("device_name", p.cfg.DeviceName),
	)

	// Enable the BLE adapter
	p.adapter = bluetooth.DefaultAdapter
	if p.cfg.AdapterID != "" {
		p.adapter = bluetooth.NewAdapter(p.cfg.AdapterID)
	}
	if err := p.adapter.Enable(); err != nil {
		p.log.Error("failed to enable bluetooth adapter", slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrPeripheralStartFailed, Cause: err}
	}

	// Create the GATT service
	if err := p.setupGATTService(); err != nil {
		return &SentinelCauseError{Sentinel: ErrPeripheralStartFailed, Cause: err}
	}

	// Start advertising
	adv := p.adapter.DefaultAdvertisement()
	if err := adv.Configure(bluetooth.AdvertisementOptions{
		LocalName:    p.cfg.DeviceName,
		ServiceUUIDs: []bluetooth.UUID{XKeyServiceUUID},
	}); err != nil {
		p.log.Error("failed to configure advertisement", slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrPeripheralStartFailed, Cause: err}
	}

	if err := adv.Start(); err != nil {
		p.log.Error("failed to start advertising", slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrPeripheralStartFailed, Cause: err}
	}

	p.log.Info("BLE peripheral started, advertising",
		slog.String("service_uuid", XKeyServiceUUID.String()),
	)

	return nil
}

// setupGATTService creates the GATT service and characteristics.
//
// Every characteristic is registered with a Handle so AddService binds it to
// the exported GATT object. Without a handle the peripheral would have no way
// to notify the central, because writing the handle is what emits the
// notification.
func (p *BLEPeripheral) setupGATTService() error {
	p.controlPoint = &bluetooth.Characteristic{}
	p.response = &bluetooth.Characteristic{}
	p.status = &bluetooth.Characteristic{}

	// Create characteristics
	controlPointChar := bluetooth.CharacteristicConfig{
		Handle: p.controlPoint,
		UUID:   ControlPointUUID,
		Flags:  bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			p.handleWrite(value)
		},
	}

	responseChar := bluetooth.CharacteristicConfig{
		Handle: p.response,
		UUID:   ResponseUUID,
		Flags:  bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission,
	}

	statusChar := bluetooth.CharacteristicConfig{
		Handle: p.status,
		UUID:   StatusUUID,
		Flags:  bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission,
	}

	// Add the service
	err := p.adapter.AddService(&bluetooth.Service{
		UUID: XKeyServiceUUID,
		Characteristics: []bluetooth.CharacteristicConfig{
			controlPointChar,
			responseChar,
			statusChar,
		},
	})
	if err != nil {
		return &WrappedError{Msg: "failed to add service", Err: err}
	}

	// Responses are notified on the response characteristic.
	p.notifier = p.response

	p.log.Debug("GATT service configured")
	return nil
}

// handleWrite processes incoming data on the control point characteristic.
func (p *BLEPeripheral) handleWrite(data []byte) {
	p.log.Debug("received data",
		slog.Int("size", len(data)),
		slog.String("hex_prefix", hex.EncodeToString(safeSlice(data, 0, 16))),
	)

	select {
	case p.incomingData <- data:
	default:
		p.log.Warn("incoming data buffer full, dropping data")
	}
}

// AcceptConnection waits for and handles a client connection.
// This should be called in a loop to handle multiple connections.
func (p *BLEPeripheral) AcceptConnection(ctx context.Context) error {
	p.log.Info("waiting for phone connection...")

	// Initialize fragmentation helpers. Outbound fragments are sized to fit
	// inside a single ATT notification PDU; see bleNotifyOverhead.
	p.fragmenter = NewFragmenter(p.mtu - bleNotifyOverhead)
	p.reassembler = NewReassembler()
	p.sender = newFragmentSender(p.notifier, p.fragmenter, p.log)

	// Create Noise session as responder
	var localStatic noise.DHKey
	if p.cfg.LocalStaticKey != nil {
		localStatic = *p.cfg.LocalStaticKey
	} else {
		key, err := GenerateStaticKey()
		if err != nil {
			return &WrappedError{Msg: "failed to generate static key", Err: err}
		}
		localStatic = *key
	}

	session, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey:       &localStatic,
		ExpectedRemoteStatic: p.cfg.ExpectedRemoteStatic,
		IsInitiator:          false, // We are the responder
	})
	if err != nil {
		return &WrappedError{Msg: "failed to create noise session", Err: err}
	}
	p.session = session

	// Wait for handshake messages
	if err := p.performHandshake(ctx); err != nil {
		return &WrappedError{Msg: "handshake failed", Err: err}
	}

	p.connected.Store(true)
	p.log.Info("phone connected, session established")

	// Handle requests
	return p.handleRequests(ctx)
}

// performHandshake handles the Noise XX handshake as responder.
func (p *BLEPeripheral) performHandshake(ctx context.Context) error {
	p.log.Debug("waiting for handshake message 1")

	if err := p.session.InitHandshake(); err != nil {
		return &WrappedError{Msg: "init handshake", Err: err}
	}

	// Receive message 1 (initiator's ephemeral)
	msg1, err := p.receiveMessage(ctx)
	if err != nil {
		return &WrappedError{Msg: "receive msg1", Err: err}
	}

	p.log.Debug("received handshake message 1", slog.Int("size", len(msg1)))

	// Process msg1 and generate msg2
	msg2, complete, err := p.session.HandshakeMessage(msg1)
	if err != nil {
		return &WrappedError{Msg: "process msg1", Err: err}
	}
	if complete {
		return &MessageError{Msg: "unexpected handshake completion after msg1"}
	}

	// Send message 2
	if err := p.sendMessage(ctx, msg2); err != nil {
		return &WrappedError{Msg: "send msg2", Err: err}
	}

	p.log.Debug("sent handshake message 2", slog.Int("size", len(msg2)))

	// Receive message 3 (initiator's static)
	msg3, err := p.receiveMessage(ctx)
	if err != nil {
		return &WrappedError{Msg: "receive msg3", Err: err}
	}

	p.log.Debug("received handshake message 3", slog.Int("size", len(msg3)))

	// Process msg3 to complete handshake
	_, complete, err = p.session.HandshakeMessage(msg3)
	if err != nil {
		return &WrappedError{Msg: "process msg3", Err: err}
	}
	if !complete {
		return &MessageError{Msg: "handshake not complete after msg3"}
	}

	p.log.Info("Noise handshake completed successfully")
	return nil
}

// receiveMessage reads a complete message from the phone, failing if the
// message does not arrive within handshakeReceiveTimeout.
func (p *BLEPeripheral) receiveMessage(ctx context.Context) ([]byte, error) {
	return p.receiveMessageTimeout(ctx, handshakeReceiveTimeout)
}

// receiveMessageTimeout reassembles the fragments arriving on the control
// point into one complete message. A non-positive timeout waits indefinitely,
// which is what an established session does between requests.
func (p *BLEPeripheral) receiveMessageTimeout(ctx context.Context, timeout time.Duration) ([]byte, error) {
	var expired <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		expired = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.stopChan:
			return nil, ErrPeripheralNotRunning
		case data := <-p.incomingData:
			// Decode fragment
			fragment, err := DecodeFragment(data)
			if err != nil {
				p.log.Warn("failed to decode fragment", slog.String("error", err.Error()))
				continue
			}

			// Add to reassembler
			complete, err := p.reassembler.AddFragment(fragment)
			if err != nil {
				p.log.Warn("fragment reassembly error", slog.String("error", err.Error()))
				p.reassembler.Reset()
				continue
			}

			if complete {
				message, err := p.reassembler.Assemble()
				if err != nil {
					p.log.Warn("fragment assembly error", slog.String("error", err.Error()))
					p.reassembler.Reset()
					continue
				}
				p.reassembler.Reset() // Ready for next message
				return message, nil
			}
		case <-expired:
			return nil, &MessageError{Msg: "receive timeout"}
		}
	}
}

// sendMessage fragments a complete message and notifies every fragment on the
// response characteristic. It returns a typed error - never a silent success -
// when the transport rejects or truncates a fragment.
func (p *BLEPeripheral) sendMessage(ctx context.Context, data []byte) error {
	sender := p.sender
	if sender == nil {
		return ErrNotifyUnavailable
	}
	return sender.send(ctx, data)
}

// handleRequests processes incoming requests from the phone. Requests are
// reassembled from their fragments before they are decrypted: the control
// point delivers BLE-sized fragments, never whole messages.
func (p *BLEPeripheral) handleRequests(ctx context.Context) error {
	for {
		request, err := p.receiveMessageTimeout(ctx, 0)
		if err != nil {
			if errors.Is(err, ErrPeripheralNotRunning) {
				return nil
			}
			return err
		}

		if err := p.processRequest(ctx, request); err != nil {
			p.log.Error("failed to process request", slog.String("error", err.Error()))
		}
	}
}

// processRequest handles a single encrypted request.
func (p *BLEPeripheral) processRequest(ctx context.Context, encryptedData []byte) error {
	// Decrypt the request
	plaintext, err := p.session.Decrypt(encryptedData)
	if err != nil {
		return &WrappedError{Msg: "decrypt failed", Err: err}
	}

	p.log.Debug("received request",
		slog.Int("size", len(plaintext)),
	)

	// Handle the request
	var response []byte
	if p.cfg.RequestHandler != nil {
		response, err = p.cfg.RequestHandler.HandleRequest(ctx, plaintext)
		if err != nil {
			p.log.Error("request handler error", slog.String("error", err.Error()))
			// Create error response
			response = []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"}}`)
		}
	} else {
		p.log.Warn("no request handler configured")
		response = []byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}`)
	}

	// Encrypt and send response
	encrypted, err := p.session.Encrypt(response)
	if err != nil {
		return &WrappedError{Msg: "encrypt response failed", Err: err}
	}

	return p.sendMessage(ctx, encrypted)
}

// Stop stops advertising and closes connections.
func (p *BLEPeripheral) Stop() error {
	if p.closed.Swap(true) {
		return nil
	}

	close(p.stopChan)

	p.log.Info("BLE peripheral stopped")
	return nil
}

// IsConnected returns true if a client is connected.
func (p *BLEPeripheral) IsConnected() bool {
	return p.connected.Load()
}

// LocalStaticPublicKey returns the local static public key.
func (p *BLEPeripheral) LocalStaticPublicKey() []byte {
	if p.session == nil {
		return nil
	}
	return p.session.LocalStaticPublicKey()
}
