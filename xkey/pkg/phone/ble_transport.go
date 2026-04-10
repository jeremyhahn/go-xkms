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
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"tinygo.org/x/bluetooth"
)

// BLE Service and Characteristic UUIDs for xKey.
var (
	// XKeyServiceUUID is the primary service UUID for xKey phone communication.
	XKeyServiceUUID = bluetooth.NewUUID([16]byte{
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0,
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0,
	})

	// ControlPointUUID is the characteristic for sending commands to the phone.
	ControlPointUUID = bluetooth.NewUUID([16]byte{
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0,
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0x00, 0x01,
	})

	// ResponseUUID is the characteristic for receiving responses from the phone.
	ResponseUUID = bluetooth.NewUUID([16]byte{
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0,
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0x00, 0x02,
	})

	// StatusUUID is the characteristic for receiving status updates from the phone.
	StatusUUID = bluetooth.NewUUID([16]byte{
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0,
		0xf1, 0xd0, 0xf1, 0xd0, 0xf1, 0xd0, 0x00, 0x03,
	})
)

// Compile-time interface checks.
var (
	_ Transport           = (*BLETransport)(nil)
	_ BLECapableTransport = (*BLETransport)(nil)
)

// BLETransportConfig configures the BLE transport.
type BLETransportConfig struct {
	// DeviceAddress is the specific device address to connect to.
	// If empty, will scan for xKey service.
	DeviceAddress string

	// ScanTimeout is the duration to scan for devices.
	ScanTimeout time.Duration

	// ConnectTimeout is the timeout for establishing a connection.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for individual operations.
	OperationTimeout time.Duration

	// MTU is the preferred Maximum Transmission Unit.
	MTU int

	// Logger is the structured logger for debug output.
	Logger *slog.Logger
}

// DefaultBLETransportConfig returns default configuration values.
func DefaultBLETransportConfig() *BLETransportConfig {
	return &BLETransportConfig{
		ScanTimeout:      ScanTimeout,
		ConnectTimeout:   ConnectTimeout,
		OperationTimeout: OperationTimeout,
		MTU:              DefaultMTU,
		Logger:           slog.Default(),
	}
}

// BLETransport manages BLE communication with the xKey phone app.
type BLETransport struct {
	cfg *BLETransportConfig
	log *slog.Logger

	mu      sync.RWMutex
	adapter *bluetooth.Adapter
	device  bluetooth.Device
	service bluetooth.DeviceService

	controlChar  bluetooth.DeviceCharacteristic
	responseChar bluetooth.DeviceCharacteristic
	statusChar   bluetooth.DeviceCharacteristic

	fragmenter   *Fragmenter
	reassembler  *Reassembler
	responseChan chan []byte
	statusChan   chan []byte

	connected        atomic.Bool
	closed           atomic.Bool
	connectedAddress atomic.Value // stores the actual connected address (string)

	// connEpoch is incremented on each new connection. Notification callbacks
	// capture the epoch at registration time and discard notifications when the
	// epoch has advanced, preventing duplicate fragments from stale D-Bus signal
	// handlers that TinyGo/BlueZ fails to unregister on disconnect.
	connEpoch atomic.Uint64
}

// NewBLETransport creates a new BLE transport.
func NewBLETransport(cfg *BLETransportConfig) (*BLETransport, error) {
	if cfg == nil {
		cfg = DefaultBLETransportConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MTU < MinMTU {
		cfg.MTU = DefaultMTU
	}

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, ErrBLEUnavailable
	}

	return &BLETransport{
		cfg:          cfg,
		log:          cfg.Logger.With("component", "ble_transport"),
		adapter:      adapter,
		fragmenter:   NewFragmenter(cfg.MTU),
		reassembler:  NewReassembler(),
		responseChan: make(chan []byte, 16),
		statusChan:   make(chan []byte, 16),
	}, nil
}

// ScanResult represents a discovered BLE device.
type ScanResult struct {
	Address   string
	LocalName string
	RSSI      int16
}

// DisplayName returns a user-friendly name for the device.
// For xKey devices (identified by service UUID), it returns "xKey"
// with the last 4 characters of the address for disambiguation.
func (s ScanResult) DisplayName() string {
	if s.LocalName != "" {
		return s.LocalName
	}
	// No local name advertised - use xKey identifier with address suffix
	if len(s.Address) >= 5 {
		return "xKey (" + s.Address[len(s.Address)-5:] + ")"
	}
	return "xKey"
}

// Scan searches for xKey devices.
// If stopOnFirst is true, scanning stops immediately when a xKey device is found.
func (t *BLETransport) Scan(ctx context.Context) ([]ScanResult, error) {
	return t.ScanWithOptions(ctx, true) // Default: stop on first device found
}

// ScanAll searches for all xKey devices until timeout.
func (t *BLETransport) ScanAll(ctx context.Context) ([]ScanResult, error) {
	return t.ScanWithOptions(ctx, false)
}

// ScanWithOptions searches for xKey devices with configurable behavior.
func (t *BLETransport) ScanWithOptions(ctx context.Context, stopOnFirst bool) ([]ScanResult, error) {
	if t.adapter == nil {
		return nil, ErrBLEUnavailable
	}
	if t.closed.Load() {
		return nil, ErrBackendClosed
	}

	var devices []ScanResult
	var mu sync.Mutex
	found := make(chan struct{}, 1)
	scanErr := make(chan error, 1)

	// Use a fresh context for the scan timeout rather than inheriting the
	// parent context's deadline. This ensures each scan gets the full configured
	// scan window even during Connect() retries where the parent context may
	// have little time remaining. Parent cancellation is still forwarded.
	scanCtx, cancel := context.WithTimeout(context.Background(), t.cfg.ScanTimeout)
	defer cancel()

	// Forward parent context cancellation to the scan context
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-scanCtx.Done():
		}
	}()

	t.log.Debug("starting BLE scan", "timeout", t.cfg.ScanTimeout, "stopOnFirst", stopOnFirst)

	// Start scan in goroutine because Scan() blocks until StopScan() is called
	go func() {
		err := t.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
			// Build list of all advertised service UUIDs for debugging
			var serviceUUIDs []string
			for _, uuid := range result.ServiceUUIDs() {
				serviceUUIDs = append(serviceUUIDs, uuid.String())
			}

			// Log ALL discovered devices for debugging
			t.log.Debug("discovered BLE device",
				"address", result.Address.String(),
				"name", result.LocalName(),
				"serviceUUIDs", serviceUUIDs,
				"expectedUUID", XKeyServiceUUID.String(),
				"hasXKeyService", result.HasServiceUUID(XKeyServiceUUID),
			)

			// NOTE: We no longer try to fix BlueZ cache during scanning.
			// Bonded devices may show cached SDP records instead of BLE services,
			// but removing them would break bonding. The phone app must be running
			// and advertising the xKey service for discovery to work.

			// Check if device advertises xKey service
			if result.HasServiceUUID(XKeyServiceUUID) {
				mu.Lock()
				// Check for duplicates (same address)
				isDuplicate := false
				for _, d := range devices {
					if d.Address == result.Address.String() {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					devices = append(devices, ScanResult{
						Address:   result.Address.String(),
						LocalName: result.LocalName(),
						RSSI:      result.RSSI,
					})
					t.log.Info("found xKey device",
						"address", result.Address.String(),
						"name", result.LocalName(),
					)
					// Signal that we found a device
					if stopOnFirst {
						found <- struct{}{}
					}
				}
				mu.Unlock()
			}
		})
		scanErr <- err
	}()

	// Wait for first device found, context cancellation, or timeout
	select {
	case <-found:
		t.log.Debug("stopping scan - xKey device found")
	case <-scanCtx.Done():
		t.log.Debug("scan timeout reached")
	case err := <-scanErr:
		// Scan returned early (error or adapter issue)
		if err != nil {
			t.log.Error("scan error", "error", err)
			return nil, ErrBLEUnavailable
		}
	}

	t.log.Debug("calling StopScan...")
	if err := t.adapter.StopScan(); err != nil {
		t.log.Warn("failed to stop scan", "error", err)
	}
	t.log.Debug("StopScan completed")

	t.log.Info("scan complete", "devicesFound", len(devices))
	return devices, nil
}

// parseMACAddress parses a MAC address string into a bluetooth.Address.
func parseMACAddress(address string) (bluetooth.Address, error) {
	mac, err := bluetooth.ParseMAC(address)
	if err != nil {
		return bluetooth.Address{}, err
	}
	return bluetooth.Address{
		MACAddress: bluetooth.MACAddress{MAC: mac},
	}, nil
}

// Connect establishes a connection to a xKey device.
// The address parameter is the current advertising address (from scan).
// The bondedAddress parameter (optional) is ignored - device identity is verified via Noise handshake.
func (t *BLETransport) Connect(ctx context.Context, address string) error {
	return t.ConnectWithBondedAddress(ctx, address, "")
}

// ConnectWithBondedAddress connects to a device at the scanned address.
// The bondedAddress parameter is used to clean up stale BlueZ cache entries
// when Android has rotated its RPA to a different address.
// Device identity is verified via the Noise protocol handshake.
func (t *BLETransport) ConnectWithBondedAddress(ctx context.Context, address, bondedAddress string) error {
	if t.adapter == nil {
		return ErrBLEUnavailable
	}
	if t.closed.Load() {
		return ErrBackendClosed
	}
	if t.connected.Load() {
		return nil // Already connected
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Advance the connection epoch so that any stale notification handlers
	// from previous connections will discard their callbacks.
	epoch := t.connEpoch.Add(1)

	t.log.Debug("initiating BLE connection",
		"scanned_address", address,
		"bonded_address", bondedAddress,
		"conn_epoch", epoch)

	// Parse the scanned address
	addr, err := parseMACAddress(address)
	if err != nil {
		t.log.Error("failed to parse MAC address", "address", address, "error", err)
		return ErrDeviceNotFound
	}

	// Clean up BlueZ state before connecting.
	// This helps with Android's RPA rotation where stale device objects
	// can cause D-Bus errors or pairing prompts.
	t.log.Debug("preparing BlueZ state for connection")

	// If the address changed (Android RPA rotation), refresh the old address state
	// but preserve bonding info so we don't need to re-pair
	if bondedAddress != "" && bondedAddress != address {
		t.log.Info("detected address change (Android RPA rotation)",
			"old_address", bondedAddress,
			"new_address", address)
		refreshBlueZDevice(bondedAddress, t.log)
	}

	// Trust the device BEFORE connecting to avoid pairing prompts.
	// For BLE, the pairing happens at the application level (Noise handshake).
	_ = trustBlueZDevice(address)
	time.Sleep(100 * time.Millisecond)

	// Connect with retry logic and D-Bus error recovery
	const connectRetries = 3
	var device bluetooth.Device
	var connectErr error

	for attempt := 1; attempt <= connectRetries; attempt++ {
		t.log.Debug("connection attempt", "attempt", attempt, "address", address)

		device, connectErr = t.adapter.Connect(addr, bluetooth.ConnectionParams{})
		if connectErr == nil {
			break // Success
		}

		// Check if this is a BlueZ D-Bus stale object error
		isDBusError := isBlueZCacheError(connectErr)

		t.log.Warn("connection attempt failed",
			"attempt", attempt,
			"error", connectErr,
			"is_dbus_error", isDBusError)

		if isDBusError {
			// D-Bus stale object: the cached BlueZ object (often from classic BT
			// pairing) is broken. Only a full remove + re-scan fixes this.
			// Classic BT bonding is irrelevant for BLE - our app-level bonding
			// uses the Noise protocol key exchange.
			t.log.Info("BlueZ D-Bus stale object detected, removing device for fresh discovery",
				"address", address)

			_ = t.adapter.StopScan()
			_ = removeBlueZDevice(address)

			// Also remove any stale old bonded address
			if bondedAddress != "" && bondedAddress != address {
				_ = removeBlueZDevice(bondedAddress)
			}

			time.Sleep(500 * time.Millisecond)

			// Return a specific error so the caller can re-scan
			return ErrDBusStaleObject
		}

		// Non D-Bus error: retry with standard cleanup
		if attempt < connectRetries {
			_ = t.adapter.StopScan()
			refreshBlueZDevice(address, t.log)
			_ = trustBlueZDevice(address)
			time.Sleep(300 * time.Millisecond)
		}
	}

	if connectErr != nil {
		t.log.Error("all connection attempts failed", "error", connectErr)
		return ErrConnectionFailed
	}

	// Store the actual connected address
	t.connectedAddress.Store(address)

	t.log.Debug("connected, discovering services", "address", address)

	// Discover services with retry logic (BlueZ may cache stale data)
	const maxRetries = 3
	const retryDelay = 500 * time.Millisecond

	var xkeyService bluetooth.DeviceService
	var foundService bool

	for attempt := 1; attempt <= maxRetries; attempt++ {
		t.log.Debug("service discovery attempt", "attempt", attempt, "maxRetries", maxRetries)

		// First try direct discovery of the xKey service (more reliable on some adapters)
		if attempt == 1 {
			directServices, err := device.DiscoverServices([]bluetooth.UUID{XKeyServiceUUID})
			if err == nil && len(directServices) > 0 {
				for _, svc := range directServices {
					if svc.UUID() == XKeyServiceUUID {
						xkeyService = svc
						foundService = true
						t.log.Info("found xKey service via direct discovery")
						break
					}
				}
			}
			if foundService {
				break
			}
			t.log.Debug("direct service discovery failed, trying full discovery")
		}

		// Discover ALL services (fallback for adapters that don't support filtering)
		allServices, err := device.DiscoverServices(nil)
		if err != nil {
			t.log.Error("failed to discover services", "address", address, "error", err, "attempt", attempt)
			if attempt == maxRetries {
				device.Disconnect()
				return ErrServiceNotFound
			}
			time.Sleep(retryDelay)
			continue
		}

		t.log.Info("discovered services", "count", len(allServices), "attempt", attempt)
		for _, svc := range allServices {
			t.log.Info("found service", "uuid", svc.UUID().String())
		}

		// Find our xKey service
		for _, svc := range allServices {
			if svc.UUID() == XKeyServiceUUID {
				xkeyService = svc
				foundService = true
				break
			}
		}

		if foundService {
			break
		}

		if attempt < maxRetries {
			t.log.Debug("xKey service not found, retrying after delay",
				"attempt", attempt,
				"retryDelay", retryDelay,
				"expected", XKeyServiceUUID.String())
			time.Sleep(retryDelay)
		}
	}

	if !foundService {
		t.log.Error("no xKey service found after retries",
			"address", address,
			"expected", XKeyServiceUUID.String(),
			"maxRetries", maxRetries,
			"hint", "Try: 1) Restart xKey app on phone, 2) Toggle Bluetooth off/on, 3) Run 'bluetoothctl remove "+address+"' to clear cache")
		device.Disconnect()
		return ErrServiceNotFound
	}

	t.log.Debug("found xKey service, discovering characteristics", "address", address)

	// Get characteristics
	chars, err := xkeyService.DiscoverCharacteristics([]bluetooth.UUID{
		ControlPointUUID,
		ResponseUUID,
		StatusUUID,
	})
	if err != nil {
		t.log.Error("failed to discover characteristics", "address", address, "error", err)
		device.Disconnect()
		return ErrCharacteristicNotFound
	}

	t.log.Debug("discovered characteristics", "address", address, "charCount", len(chars))

	// Find each characteristic
	var controlChar, responseChar, statusChar bluetooth.DeviceCharacteristic
	for _, char := range chars {
		switch char.UUID() {
		case ControlPointUUID:
			controlChar = char
			t.log.Debug("found ControlPoint characteristic")
		case ResponseUUID:
			responseChar = char
			t.log.Debug("found Response characteristic")
		case StatusUUID:
			statusChar = char
			t.log.Debug("found Status characteristic")
		}
	}

	if controlChar.UUID() == (bluetooth.UUID{}) || responseChar.UUID() == (bluetooth.UUID{}) {
		t.log.Error("missing required characteristics",
			"hasControl", controlChar.UUID() != (bluetooth.UUID{}),
			"hasResponse", responseChar.UUID() != (bluetooth.UUID{}))
		device.Disconnect()
		return ErrCharacteristicNotFound
	}

	t.log.Debug("enabling response notifications", "conn_epoch", epoch)

	// Subscribe to response notifications.
	// Capture the current epoch so stale handlers from previous connections
	// (which TinyGo/BlueZ leaks via persistent D-Bus signal matches) silently
	// discard their callbacks instead of feeding duplicate fragments into the
	// reassembler.
	if err := responseChar.EnableNotifications(func(data []byte) {
		if t.connEpoch.Load() != epoch {
			return // stale notification from previous connection
		}
		t.handleResponseNotification(data)
	}); err != nil {
		t.log.Error("failed to enable response notifications", "error", err)
		device.Disconnect()
		return ErrCharacteristicNotFound
	}

	// Subscribe to status notifications if available
	if statusChar.UUID() != (bluetooth.UUID{}) {
		t.log.Debug("enabling status notifications", "conn_epoch", epoch)
		_ = statusChar.EnableNotifications(func(data []byte) {
			if t.connEpoch.Load() != epoch {
				return // stale notification from previous connection
			}
			t.handleStatusNotification(data)
		})
	}

	t.device = device
	t.service = xkeyService
	t.controlChar = controlChar
	t.responseChar = responseChar
	t.statusChar = statusChar
	t.connected.Store(true)

	t.log.Info("connected to xKey device", "address", address)

	// Check context cancellation
	select {
	case <-ctx.Done():
		t.disconnectLocked(false)
		return ErrTimeout
	default:
	}

	return nil
}

// handleResponseNotification processes incoming response fragments.
func (t *BLETransport) handleResponseNotification(data []byte) {
	if t.closed.Load() {
		return // transport closed, channel is closed
	}

	t.log.Debug("BLE notification received",
		"raw_size", len(data),
		"raw_hex", fmt.Sprintf("%x", data[:min(len(data), 32)]),
	)

	frag, err := DecodeFragment(data)
	if err != nil {
		t.log.Warn("invalid response fragment",
			"error", err,
			"raw_size", len(data),
			"raw_hex", fmt.Sprintf("%x", data),
		)
		return
	}

	t.log.Debug("fragment decoded",
		"flags", frag.Flags,
		"seq", frag.Sequence,
		"total", frag.Total,
		"length", frag.Length,
		"payload_size", len(frag.Payload),
	)

	complete, err := t.reassembler.AddFragment(frag)
	if err != nil {
		t.log.Warn("fragment reassembly error", "error", err)
		t.reassembler.Reset()
		return
	}

	if complete {
		message, err := t.reassembler.Assemble()
		if err != nil {
			t.log.Warn("message assembly error", "error", err)
		} else {
			t.log.Debug("message reassembled", "size", len(message))
			select {
			case t.responseChan <- message:
			default:
				t.log.Warn("response channel full, dropping message")
			}
		}
		t.reassembler.Reset()
	}
}

// handleStatusNotification processes incoming status updates.
func (t *BLETransport) handleStatusNotification(data []byte) {
	if t.closed.Load() {
		return // transport closed, channel is closed
	}
	select {
	case t.statusChan <- data:
	default:
		t.log.Warn("status channel full, dropping message")
	}
}

// Send transmits a message to the connected phone.
func (t *BLETransport) Send(ctx context.Context, message []byte) error {
	if t.adapter == nil {
		return ErrBLEUnavailable
	}
	if t.closed.Load() {
		return ErrBackendClosed
	}
	if !t.connected.Load() {
		return ErrNotConnected
	}

	t.mu.RLock()
	controlChar := t.controlChar
	t.mu.RUnlock()

	t.log.Debug("Send starting", "message_len", len(message))

	// Fragment the message
	fragments, err := t.fragmenter.Fragment(message)
	if err != nil {
		t.log.Error("failed to fragment message", "error", err)
		return err
	}
	t.log.Debug("message fragmented", "fragment_count", len(fragments))

	// Send each fragment with a per-write timeout.
	// TinyGo's BLE writes go through BlueZ D-Bus and can block indefinitely
	// if the underlying BLE connection has issues (e.g., stale D-Bus state).
	const writeTimeout = 10 * time.Second

	for i, frag := range fragments {
		select {
		case <-ctx.Done():
			t.log.Error("context cancelled during send", "fragment", i)
			return ErrTimeout
		default:
		}

		t.log.Debug("writing fragment", "index", i, "size", len(frag))

		type writeResult struct {
			err error
		}
		resultCh := make(chan writeResult, 1)

		go func() {
			_, err := controlChar.WriteWithoutResponse(frag)
			resultCh <- writeResult{err: err}
		}()

		select {
		case res := <-resultCh:
			if res.err != nil {
				t.log.Error("failed to write fragment", "error", res.err, "index", i)
				return ErrConnectionFailed
			}
		case <-time.After(writeTimeout):
			t.log.Error("BLE write timed out", "index", i, "timeout", writeTimeout)
			return ErrConnectionFailed
		case <-ctx.Done():
			t.log.Error("context cancelled during write", "fragment", i)
			return ErrTimeout
		}

		t.log.Debug("fragment written successfully", "index", i)
	}

	t.log.Debug("Send completed", "fragments_sent", len(fragments))
	return nil
}

// Receive waits for a complete response message.
func (t *BLETransport) Receive(ctx context.Context) ([]byte, error) {
	if t.adapter == nil {
		return nil, ErrBLEUnavailable
	}
	if t.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !t.connected.Load() {
		return nil, ErrNotConnected
	}

	t.log.Debug("Receive waiting for response...")

	select {
	case msg := <-t.responseChan:
		t.log.Debug("Receive got response", "size", len(msg))
		return msg, nil
	case <-ctx.Done():
		t.log.Error("Receive timeout waiting for response")
		return nil, ErrTimeout
	}
}

// SendAndReceive sends a message and waits for a response.
func (t *BLETransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := t.Send(ctx, message); err != nil {
		return nil, err
	}
	return t.Receive(ctx)
}

// Disconnect closes the BLE connection.
func (t *BLETransport) Disconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.disconnectLocked(false)
}

// DisconnectAndRemove closes the BLE connection and removes the device from
// BlueZ entirely. This invalidates all cached D-Bus GATT handles, which is
// necessary after a write timeout leaves stale BlueZ state that blocks future
// operations with "In Progress" errors.
func (t *BLETransport) DisconnectAndRemove() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.disconnectLocked(true)
}

// disconnectLocked disconnects while holding the lock.
// If forceRemove is true, the device is removed from BlueZ entirely to clear
// all stale D-Bus GATT state (cached characteristic handles, pending operations).
func (t *BLETransport) disconnectLocked(forceRemove bool) error {
	if !t.connected.Load() {
		// Even if not connected, force-remove cleans stale BlueZ state.
		if forceRemove {
			if addr := t.connectedAddress.Load(); addr != nil {
				address := addr.(string)
				t.log.Info("force-removing BlueZ device (not connected)", "address", address)
				_ = removeBlueZDevice(address)
				time.Sleep(500 * time.Millisecond)
			}
		}
		return nil
	}

	// Get the address before disconnecting for BlueZ cleanup
	var address string
	if addr := t.connectedAddress.Load(); addr != nil {
		address = addr.(string)
	}

	t.connected.Store(false)

	if t.device != (bluetooth.Device{}) {
		if err := t.device.Disconnect(); err != nil {
			t.log.Warn("disconnect error", "error", err)
		}
		t.device = bluetooth.Device{}
	}

	// Drain pending data from channels to prevent stale fragments from a
	// previous connection being consumed by the next connection's Receive().
	t.drainChannels()

	// Reset the reassembler to discard any partially received message.
	t.reassembler.Reset()

	if address != "" {
		if forceRemove {
			// Remove device entirely from BlueZ to invalidate all cached D-Bus
			// GATT handles. This is needed when a timed-out write goroutine left
			// a pending D-Bus operation that blocks new writes with "In Progress".
			t.log.Info("force-removing BlueZ device to clear stale GATT state", "address", address)
			time.Sleep(200 * time.Millisecond)
			_ = removeBlueZDevice(address)
			time.Sleep(500 * time.Millisecond)
		} else {
			// Just ensure disconnected, don't remove bonding
			t.log.Debug("ensuring BlueZ disconnect state", "address", address)
			time.Sleep(200 * time.Millisecond)
			_ = disconnectBlueZDevice(address)
		}
	}

	t.log.Info("disconnected from xKey device")
	return nil
}

// drainChannels removes all pending messages from the response and status
// channels. This must be called after disconnecting to ensure that stale data
// from the old connection is not consumed by the next connection.
func (t *BLETransport) drainChannels() {
	for {
		select {
		case <-t.responseChan:
		default:
			goto drainStatus
		}
	}
drainStatus:
	for {
		select {
		case <-t.statusChan:
		default:
			return
		}
	}
}

// IsConnected returns true if currently connected.
func (t *BLETransport) IsConnected() bool {
	return t.connected.Load()
}

// ConnectedAddress returns the address of the currently connected device.
// This may differ from the saved/bonded address if Android rotated its RPA.
// Returns empty string if not connected.
func (t *BLETransport) ConnectedAddress() string {
	if addr := t.connectedAddress.Load(); addr != nil {
		return addr.(string)
	}
	return ""
}

// CleanStaleBlueZEntry removes a device from BlueZ if it has stale classic Bluetooth
// state that would interfere with BLE connections. This checks if the device is known
// to BlueZ and has characteristics of a stale classic BT cache (many SDP service UUIDs
// but no active BLE GATT connection). Such entries cause D-Bus errors when trying to
// connect via BLE and must be removed to allow fresh discovery.
func (t *BLETransport) CleanStaleBlueZEntry(address string) {
	if address == "" {
		return
	}

	// Check if BlueZ knows about this device
	cmd := exec.Command("bluetoothctl", "info", address)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return // Device not known to BlueZ, nothing to clean
	}

	outputStr := string(output)
	if contains(outputStr, "not available") {
		return // Device not in BlueZ cache
	}

	// Check if this is a classic BT entry (has many SDP UUIDs from classic pairing)
	// Classic BT entries have UUIDs like 0000110a (A2DP), 00001112 (HSP), etc.
	// These create stale D-Bus objects that break BLE connections.
	hasClassicBT := contains(outputStr, "Audio Sink") ||
		contains(outputStr, "Handsfree") ||
		contains(outputStr, "OBEX") ||
		contains(outputStr, "0000110a-0000-1000-8000-00805f9b34fb") ||
		contains(outputStr, "00001112-0000-1000-8000-00805f9b34fb") ||
		contains(outputStr, "00001105-0000-1000-8000-00805f9b34fb")

	if !hasClassicBT {
		return // Not a classic BT entry, leave it alone
	}

	// Check if currently connected - don't remove connected devices
	if contains(outputStr, "Connected: yes") {
		return
	}

	t.log.Info("removing stale classic Bluetooth cache entry before scan",
		"address", address)
	_ = removeBlueZDevice(address)
	time.Sleep(500 * time.Millisecond)
}

// Close closes the transport and releases resources.
func (t *BLETransport) Close() error {
	if t.closed.Swap(true) {
		return nil // Already closed
	}

	t.Disconnect()

	if t.responseChan != nil {
		close(t.responseChan)
	}
	if t.statusChan != nil {
		close(t.statusChan)
	}

	return nil
}

// StatusChannel returns the channel for status updates.
func (t *BLETransport) StatusChannel() <-chan []byte {
	return t.statusChan
}

// SetMTU updates the MTU for fragmentation.
func (t *BLETransport) SetMTU(mtu int) {
	if mtu >= MinMTU {
		t.fragmenter.SetMTU(mtu)
	}
}

// MTU returns the current MTU.
func (t *BLETransport) MTU() int {
	return t.fragmenter.MTU()
}

// isBlueZCacheError checks if the error is a BlueZ D-Bus cache conflict.
// This happens when a device was previously paired (e.g., via blueman-manager)
// and the cached D-Bus object is in a stale state.
func isBlueZCacheError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// BlueZ returns this error when trying to access properties on a stale device object
	return contains(errStr, "org.freedesktop.DBus.Properties") &&
		contains(errStr, "doesn't exist")
}

// isDevicePaired checks if a device is paired/bonded in BlueZ.
func isDevicePaired(address string) bool {
	cmd := exec.Command("bluetoothctl", "info", address)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	outputStr := string(output)
	return contains(outputStr, "Paired: yes") || contains(outputStr, "Bonded: yes")
}

// disconnectBlueZDevice disconnects a device without removing bonding info.
func disconnectBlueZDevice(address string) error {
	cmd := exec.Command("bluetoothctl", "disconnect", address)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Disconnect can fail if not connected - that's ok
		if !contains(string(output), "not connected") {
			return fmt.Errorf("bluetoothctl disconnect failed: %v, output: %s", err, output)
		}
	}
	return nil
}

// removeBlueZDevice removes a device from the BlueZ cache using bluetoothctl.
// WARNING: This removes bonding info too! Use refreshBlueZDevice for bonded devices.
func removeBlueZDevice(address string) error {
	cmd := exec.Command("bluetoothctl", "remove", address)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bluetoothctl remove failed: %v, output: %s", err, output)
	}
	return nil
}

// refreshBlueZDevice attempts to refresh a device's D-Bus state without removing bonding.
// For bonded devices, this tries disconnect + reconnect to refresh stale state.
// For non-bonded devices, it removes and re-adds.
func refreshBlueZDevice(address string, log *slog.Logger) {
	if isDevicePaired(address) {
		// Device is bonded - don't remove, just disconnect and let it reconnect
		log.Debug("device is bonded, refreshing without removing", "address", address)
		_ = disconnectBlueZDevice(address)
		time.Sleep(300 * time.Millisecond)
	} else {
		// Not bonded - safe to remove stale cache entry
		log.Debug("device is not bonded, removing stale cache entry", "address", address)
		_ = removeBlueZDevice(address)
		time.Sleep(300 * time.Millisecond)
	}
}

// trustBlueZDevice trusts a device in BlueZ, which is required for BLE connections.
func trustBlueZDevice(address string) error {
	cmd := exec.Command("bluetoothctl", "trust", address)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bluetoothctl trust failed: %v, output: %s", err, output)
	}
	return nil
}

// connectViaBluetoothctl uses bluetoothctl to connect to a device.
// This properly handles D-Bus device object creation when the TinyGo library fails.
func connectViaBluetoothctl(address string) error {
	// Use bluetoothctl connect which handles device registration
	cmd := exec.Command("bluetoothctl", "connect", address)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bluetoothctl connect failed: %v, output: %s", err, output)
	}

	// Check if connection was successful
	outputStr := string(output)
	if contains(outputStr, "Connection successful") || contains(outputStr, "Connected: yes") {
		// Disconnect so we can reconnect via the library with proper state
		disconnectCmd := exec.Command("bluetoothctl", "disconnect", address)
		_, _ = disconnectCmd.CombinedOutput()
		time.Sleep(500 * time.Millisecond)
		return nil
	}

	// Connection might have succeeded even without the success message
	// if the device was already connected or the pairing exists
	if contains(outputStr, "already connected") {
		return nil
	}

	return fmt.Errorf("connection not confirmed: %s", outputStr)
}

// pairViaBluetoothctl uses bluetoothctl to pair with a device.
// This initiates OS-level Bluetooth pairing which may require user confirmation.
// Note: This function should be called when the TinyGo adapter is not actively scanning.
func pairViaBluetoothctl(address string) error {
	// Use a script-based approach with expect-like behavior for bluetoothctl
	// This ensures proper timing and avoids conflicts with other Bluetooth stacks

	// Step 1: Power on and set agent
	_ = exec.Command("bluetoothctl", "power", "on").Run()
	_ = exec.Command("bluetoothctl", "agent", "on").Run()
	_ = exec.Command("bluetoothctl", "default-agent").Run()
	time.Sleep(200 * time.Millisecond)

	// Step 2: Start scan and wait for device
	// Run scan in background
	scanCmd := exec.Command("bash", "-c", "bluetoothctl scan on & sleep 5 && bluetoothctl scan off")
	_ = scanCmd.Start()

	// Poll for device availability
	discovered := false
	for i := 0; i < 12; i++ { // 6 seconds total
		time.Sleep(500 * time.Millisecond)

		infoCmd := exec.Command("bluetoothctl", "info", address)
		infoOutput, _ := infoCmd.CombinedOutput()
		infoStr := string(infoOutput)

		if !contains(infoStr, "not available") {
			discovered = true
			break
		}
	}

	// Clean up scan
	_ = exec.Command("bluetoothctl", "scan", "off").Run()
	if scanCmd.Process != nil {
		_ = scanCmd.Process.Kill()
		_, _ = scanCmd.Process.Wait()
	}

	if !discovered {
		return fmt.Errorf("device %s not discovered by BlueZ", address)
	}

	// Step 3: Trust the device first (helps with some devices)
	trustCmd := exec.Command("bluetoothctl", "trust", address)
	_, _ = trustCmd.CombinedOutput()
	time.Sleep(200 * time.Millisecond)

	// Step 4: Try to pair
	pairCmd := exec.Command("bluetoothctl", "pair", address)
	pairOutput, pairErr := pairCmd.CombinedOutput()
	pairStr := string(pairOutput)

	if contains(pairStr, "Pairing successful") ||
		contains(pairStr, "already paired") ||
		contains(pairStr, "AlreadyExists") {
		return nil
	}

	// Step 5: If pair didn't work, try connect (may trigger pairing)
	connectCmd := exec.Command("bluetoothctl", "connect", address)
	connectOutput, _ := connectCmd.CombinedOutput()
	connectStr := string(connectOutput)

	if contains(connectStr, "Connection successful") ||
		contains(connectStr, "Connected: yes") {
		// Disconnect so our library can connect
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("bluetoothctl", "disconnect", address).Run()
		time.Sleep(300 * time.Millisecond)
		return nil
	}

	if pairErr != nil {
		return fmt.Errorf("pairing failed: %v, output: %s", pairErr, pairStr)
	}

	return nil
}

// contains checks if s contains substr (simple helper to avoid strings import).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
