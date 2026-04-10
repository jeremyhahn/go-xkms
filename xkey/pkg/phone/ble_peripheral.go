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
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"tinygo.org/x/bluetooth"
)

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

	// GATT characteristics
	controlPoint *bluetooth.Characteristic
	response     *bluetooth.Characteristic
	status       *bluetooth.Characteristic

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

	return &BLEPeripheral{
		cfg:          cfg,
		log:          logger.With("component", "ble_peripheral"),
		mtu:          DefaultMTU,
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
	if err := p.adapter.Enable(); err != nil {
		p.log.Error("failed to enable bluetooth adapter", slog.String("error", err.Error()))
		return fmt.Errorf("%w: %v", ErrPeripheralStartFailed, err)
	}

	// Create the GATT service
	if err := p.setupGATTService(); err != nil {
		return fmt.Errorf("%w: %v", ErrPeripheralStartFailed, err)
	}

	// Start advertising
	adv := p.adapter.DefaultAdvertisement()
	if err := adv.Configure(bluetooth.AdvertisementOptions{
		LocalName:    p.cfg.DeviceName,
		ServiceUUIDs: []bluetooth.UUID{XKeyServiceUUID},
	}); err != nil {
		p.log.Error("failed to configure advertisement", slog.String("error", err.Error()))
		return fmt.Errorf("%w: %v", ErrPeripheralStartFailed, err)
	}

	if err := adv.Start(); err != nil {
		p.log.Error("failed to start advertising", slog.String("error", err.Error()))
		return fmt.Errorf("%w: %v", ErrPeripheralStartFailed, err)
	}

	p.log.Info("BLE peripheral started, advertising",
		slog.String("service_uuid", XKeyServiceUUID.String()),
	)

	return nil
}

// setupGATTService creates the GATT service and characteristics.
func (p *BLEPeripheral) setupGATTService() error {
	// Create characteristics
	controlPointChar := bluetooth.CharacteristicConfig{
		UUID:  ControlPointUUID,
		Flags: bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			p.handleWrite(value)
		},
	}

	responseChar := bluetooth.CharacteristicConfig{
		UUID:  ResponseUUID,
		Flags: bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission,
	}

	statusChar := bluetooth.CharacteristicConfig{
		UUID:  StatusUUID,
		Flags: bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission,
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
		return fmt.Errorf("failed to add service: %w", err)
	}

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

	// Initialize fragmentation helpers
	p.fragmenter = NewFragmenter(p.mtu - 7) // Account for ATT header
	p.reassembler = NewReassembler()

	// Create Noise session as responder
	var localStatic noise.DHKey
	if p.cfg.LocalStaticKey != nil {
		localStatic = *p.cfg.LocalStaticKey
	} else {
		key, err := GenerateStaticKey()
		if err != nil {
			return fmt.Errorf("failed to generate static key: %w", err)
		}
		localStatic = *key
	}

	session, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey:       &localStatic,
		ExpectedRemoteStatic: p.cfg.ExpectedRemoteStatic,
		IsInitiator:          false, // We are the responder
	})
	if err != nil {
		return fmt.Errorf("failed to create noise session: %w", err)
	}
	p.session = session

	// Wait for handshake messages
	if err := p.performHandshake(ctx); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
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
		return fmt.Errorf("init handshake: %w", err)
	}

	// Receive message 1 (initiator's ephemeral)
	msg1, err := p.receiveMessage(ctx)
	if err != nil {
		return fmt.Errorf("receive msg1: %w", err)
	}

	p.log.Debug("received handshake message 1", slog.Int("size", len(msg1)))

	// Process msg1 and generate msg2
	msg2, complete, err := p.session.HandshakeMessage(msg1)
	if err != nil {
		return fmt.Errorf("process msg1: %w", err)
	}
	if complete {
		return fmt.Errorf("unexpected handshake completion after msg1")
	}

	// Send message 2
	if err := p.sendMessage(ctx, msg2); err != nil {
		return fmt.Errorf("send msg2: %w", err)
	}

	p.log.Debug("sent handshake message 2", slog.Int("size", len(msg2)))

	// Receive message 3 (initiator's static)
	msg3, err := p.receiveMessage(ctx)
	if err != nil {
		return fmt.Errorf("receive msg3: %w", err)
	}

	p.log.Debug("received handshake message 3", slog.Int("size", len(msg3)))

	// Process msg3 to complete handshake
	_, complete, err = p.session.HandshakeMessage(msg3)
	if err != nil {
		return fmt.Errorf("process msg3: %w", err)
	}
	if !complete {
		return fmt.Errorf("handshake not complete after msg3")
	}

	p.log.Info("Noise handshake completed successfully")
	return nil
}

// receiveMessage reads a complete message from the phone.
func (p *BLEPeripheral) receiveMessage(ctx context.Context) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
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
		case <-time.After(30 * time.Second):
			return nil, fmt.Errorf("receive timeout")
		}
	}
}

// sendMessage sends a complete message to the phone.
func (p *BLEPeripheral) sendMessage(ctx context.Context, data []byte) error {
	// Fragment the message if needed
	fragments, err := p.fragmenter.Fragment(data)
	if err != nil {
		return fmt.Errorf("fragmentation failed: %w", err)
	}

	for _, fragBytes := range fragments {
		// TODO: Send via notification on response characteristic
		// This requires the TinyGo bluetooth library to support notifications
		// For now, we'll need to implement this when the library supports it
		p.log.Debug("would send fragment",
			slog.Int("size", len(fragBytes)),
			slog.String("hex", hex.EncodeToString(fragBytes)),
		)
	}

	return nil
}

// handleRequests processes incoming requests from the phone.
func (p *BLEPeripheral) handleRequests(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.stopChan:
			return nil
		case data := <-p.incomingData:
			if err := p.processRequest(ctx, data); err != nil {
				p.log.Error("failed to process request", slog.String("error", err.Error()))
			}
		}
	}
}

// processRequest handles a single encrypted request.
func (p *BLEPeripheral) processRequest(ctx context.Context, encryptedData []byte) error {
	// Decrypt the request
	plaintext, err := p.session.Decrypt(encryptedData)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
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
		return fmt.Errorf("encrypt response failed: %w", err)
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

// safeSlice returns a slice of data up to maxLen bytes starting at start,
// or the remaining data if shorter. Used for debug logging of BLE payloads.
func safeSlice(data []byte, start, maxLen int) []byte {
	if start >= len(data) {
		return nil
	}
	end := start + maxLen
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}
