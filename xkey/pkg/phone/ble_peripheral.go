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

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/internal/lifecycle"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
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

	// ErrPeripheralInvalidPin indicates ExpectedRemoteStatic was supplied but
	// is not a usable Noise static public key: empty, or a length other than
	// bootstrap.NoiseKeySize.
	//
	// A caller that means to run unpinned (trust-on-first-connection) leaves
	// ExpectedRemoteStatic nil, which is unaffected by this check. What this
	// refuses is a caller that MEANT to pin a key and got nothing usable --
	// device_listen decoding an empty or corrupt stored NoisePublicKey is
	// exactly that: base64-decoding "" yields a non-nil, zero-length slice,
	// which the Noise session's PeerStaticKey treats as "nothing to pin"
	// rather than as an error, silently downgrading a supposedly pinned
	// connection to an unpinned one. Refusing it here, at construction,
	// means every caller gets the same answer instead of each having to
	// reimplement this check itself.
	ErrPeripheralInvalidPin = errors.New("phone: expected remote static key must be omitted or exactly NoiseKeySize bytes")
)

// BLEPeripheralConfig configures the BLE peripheral (server) mode.
type BLEPeripheralConfig struct {
	// LocalStaticKey is the persistent local Noise static key, held in
	// protected memory. If nil, a new key will be generated.
	LocalStaticKey *bootstrap.NoiseStaticKey

	// OwnsStaticKey transfers ownership of LocalStaticKey to the peripheral,
	// so Stop releases it — and RETAINS it when a connection handler cannot
	// be confirmed finished.
	//
	// Set it whenever the key has no other reader. A caller that keeps
	// ownership has to interpret ErrShutdownIncomplete itself; every caller
	// that forgot destroyed a borrowed key while a handler was still reading
	// it. Transferring ownership puts that decision in one place.
	OwnsStaticKey bool

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

	// LiveAttest, when set, is run once per accepted connection immediately
	// after the Noise handshake completes and before RequestHandler ever
	// sees a request: the peripheral sends this LAPTOP's own challenge to
	// the PHONE (local.attestDevice) over the same connection and requires
	// a verified answer before serving anything else. This is the same
	// #129 liveness proof PhoneKeyBackend.Connect performs when THIS host
	// initiates the connection; a phone-initiated connection (this
	// peripheral's whole purpose) got none of it before, so a copied Noise
	// static key was sufficient to reach the bridge.
	//
	// Required: nil refuses every connection after the handshake
	// (ErrLiveAttestationUnavailable) rather than serving requests with no
	// liveness check. See TCPPairingConfig.LiveAttest, its TCP counterpart.
	LiveAttest pairingproto.LiveAttestFunc

	// LiveAttestTimeout bounds LiveAttest's round trip, which prompts the
	// phone's user for biometric confirmation. Default: DefaultLiveAttestTimeout.
	LiveAttestTimeout time.Duration
}

// PeripheralRequestHandler handles incoming requests from phone.
type PeripheralRequestHandler interface {
	// HandleRequest processes a JSON-RPC request and returns a response.
	// Both may carry key material, so the peripheral wipes the request and
	// the returned response once Noise has encrypted the response: the
	// handler must return a slice it no longer needs and must not keep the
	// request.
	HandleRequest(ctx context.Context, request []byte) ([]byte, error)
}

// BLEPeripheral manages BLE peripheral (GATT server) mode.
// This allows the phone to connect to the laptop and send requests.
type BLEPeripheral struct {
	cfg    *BLEPeripheralConfig
	log    *slog.Logger
	closed atomic.Bool

	// openAdapter resolves AdapterID to the GATT server Start brings up;
	// NewBLEPeripheral sets it to openTinygoAdapter.
	openAdapter func(id string) gattServer
	adapter     gattServer

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
	session   *bootstrap.NoiseSession
	connected atomic.Bool
	mtu       int

	// Fragmentation
	fragmenter  *pairingproto.Fragmenter
	reassembler *pairingproto.Reassembler

	// Channels for communication
	incomingData chan []byte
	stopChan     chan struct{}

	// generatedStaticKey holds the ephemeral static key AcceptConnection
	// generates when the config supplies none. The session reads its
	// protected pages for as long as the connection lives, so it is released
	// in Stop rather than when AcceptConnection returns. A key supplied
	// through the config stays the caller's to destroy.
	//
	// lifeMu guards it, and connWG counts the AcceptConnection calls that may
	// still be reading it. Stop must not free those pages while a handshake
	// or a request loop is using them, so it closes stopChan first, waits for
	// connWG, and only then destroys.
	//
	// lifeMu also pairs the closed check with connWG.Add. A WaitGroup Add that
	// starts from zero must happen before its Wait, so testing closed and
	// registering have to be one atomic step against Stop setting closed:
	// otherwise a connection arriving exactly as Stop begins could Add after
	// Wait had already returned.
	lifeMu sync.Mutex
	connWG sync.WaitGroup

	// registerGate is nil in production and never set outside a test.
	//
	// It exists so a test can stop time between the closed check and the Add
	// and let a Stop race that window, which is the ONLY way to observe
	// whether the two are genuinely one step: with lifeMu held across both, a
	// Stop is parked acquiring it and cannot make progress. Moving the Add out
	// from under lifeMu is otherwise a silent race that no drain test happens
	// to schedule (#40).
	//
	// Per-peripheral rather than a package global so it affects only the
	// peripheral a test owns, cannot be reassigned underneath a concurrent
	// test, and cannot block every peripheral in the process. It is written
	// once at construction time, before any goroutine can reach
	// registerConnection, and only read afterwards.
	registerGate func()

	// connJoiner bounds Stop's wait on connWG with a single waiter goroutine.
	connJoiner lifecycle.Joiner

	// stopOnce/stopErr latch the shutdown outcome so concurrent and repeat
	// callers see one result and only one of them releases the static key.
	stopOnce sync.Once
	stopErr  error

	// acceptMu serializes AcceptConnection. A BLE peripheral serves one
	// central at a time, and the code already assumed that: each call
	// overwrites session, fragmenter, reassembler and sender, and replaces
	// the generated static key, destroying the previous one. Nothing enforced
	// it, so a second caller could free protected pages the first call's
	// session was still reading. This makes the assumption real.
	acceptMu sync.Mutex

	generatedStaticKey *bootstrap.NoiseStaticKey

	// starting is held for the whole of Start, so a second caller is refused
	// before it can reconfigure a peripheral the first is still bringing up.
	starting bool

	// adv is the advertisement Start brought up, retained so Stop can take it
	// down. It used to be a local in Start, which meant Stop reported success
	// while the peripheral carried on advertising a service whose key it had
	// just destroyed.
	adv advertiser

	// adoptedStaticKey is a key the caller transferred with OwnsStaticKey.
	// It is reused for every connection rather than regenerated, and Stop
	// releases it on the same terms as a generated one: destroyed on a
	// confirmed join, retained otherwise.
	adoptedStaticKey *bootstrap.NoiseStaticKey

	// localStaticPublic is a plain copy of the current connection's static
	// public half, taken when the session is built. The public key is not
	// secret and copying it decouples the accessor from both the session
	// pointer and the protected private pages, so LocalStaticPublicKey cannot
	// race AcceptConnection publishing a session or Stop destroying a key.
	localStaticPublic []byte

	// writeMu guards boundCentral and centralBound.
	writeMu sync.Mutex

	// boundCentral identifies the central handleWrite accepts control-point
	// writes from for the current session, and centralBound records whether
	// a central has bound yet. The GATT server exposes one control point to
	// every central that is connected, not one per session, so without this a
	// second central -- accidental or hostile -- could write fragments into
	// the same incomingData channel and reassembler the legitimate phone's
	// handshake or request stream is using. handleWrite binds to whichever
	// central's write arrives first and drops every write reporting a
	// different one; resetCentralBinding clears it so the next session starts
	// unbound instead of inheriting the previous one's central.
	//
	// This binds correctly wherever bluetooth.Connection identifies the
	// writer, which tinygo's hci/ninafw/cyw43439 backends do. It does NOT on
	// the BlueZ D-Bus backend (gatts_linux.go, what every desktop Linux build
	// of xkey compiles): BlueZ does not tell the GATT application which
	// central performed a write, so that backend reports Connection(0) for
	// every write regardless of source, and every central lands in the same
	// bucket there. Rejecting a second central at the connection layer would
	// close that gap and is tracked in #1307's follow-up; this is still worth
	// doing now because it binds correctly on every backend that reports real
	// per-connection identity, and it is the seam a connection-layer check
	// would extend rather than replace.
	boundCentral bluetooth.Connection
	centralBound bool
}

// advertiser is the part of bluetooth.Advertisement the peripheral's lifecycle
// depends on: raising the advertisement and taking it back down.
//
// It is an interface for one reason — whether the peripheral is still
// discoverable decides whether Stop can report a COMPLETE shutdown, and that
// decision was untestable while the field held a concrete
// *bluetooth.Advertisement. Bringing a real advertisement up needs a Bluetooth
// adapter, which CI does not have, so the branch that reports an incomplete
// shutdown when advertising cannot be stopped had no way to fail.
//
// It does NOT decide the key's fate. Nothing reads the protected pages but
// AcceptConnection and the session it builds, and `closed` is set under lifeMu
// before the drain, so a central arriving at a still-advertising peripheral
// cannot register. A confirmed join is what frees the key; see Stop.
//
// *bluetooth.Advertisement satisfies it; Configure is not part of it because
// the lifecycle does not call it.
type advertiser interface {
	Start() error
	Stop() error
}

// gattServer is the part of *bluetooth.Adapter Start uses to bring the
// peripheral up: enabling the adapter, registering the xKey GATT service and
// handing out the advertisement. It is an interface for the same reason as
// advertiser: without an adapter in CI, the service Start registers, the
// advertisement it configures and every way it can fail had no test.
// tinygoGATTServer adapts the real adapter.
type gattServer interface {
	Enable() error
	AddService(service *bluetooth.Service) error
	DefaultAdvertisement() configurableAdvertiser
}

// configurableAdvertiser is an advertiser Start can also configure.
type configurableAdvertiser interface {
	advertiser
	Configure(options bluetooth.AdvertisementOptions) error
}

// tinygoGATTServer adapts *bluetooth.Adapter to gattServer.
type tinygoGATTServer struct {
	adapter *bluetooth.Adapter
}

func (s tinygoGATTServer) Enable() error {
	return s.adapter.Enable()
}

func (s tinygoGATTServer) AddService(service *bluetooth.Service) error {
	return s.adapter.AddService(service)
}

func (s tinygoGATTServer) DefaultAdvertisement() configurableAdvertiser {
	return s.adapter.DefaultAdvertisement()
}

// openTinygoAdapter returns the adapter named id, or the system default
// adapter when id is empty.
func openTinygoAdapter(id string) gattServer {
	if id == "" {
		return tinygoGATTServer{adapter: bluetooth.DefaultAdapter}
	}
	return tinygoGATTServer{adapter: bluetooth.NewAdapter(id)}
}

// Compile-time check that the concrete advertisement still fits the two
// methods the lifecycle uses.
var (
	_ advertiser             = (*bluetooth.Advertisement)(nil)
	_ configurableAdvertiser = (*bluetooth.Advertisement)(nil)
	_ gattServer             = tinygoGATTServer{}
)

// NewBLEPeripheral creates a new BLE peripheral.
func NewBLEPeripheral(cfg *BLEPeripheralConfig) (*BLEPeripheral, error) {
	if cfg == nil {
		cfg = &BLEPeripheralConfig{}
	}

	// Validated before anything below takes ownership of the caller's key:
	// a refused construction must not leave a transferred key adopted with
	// nothing to release it. nil means "run unpinned", left alone below;
	// anything else must be a usable Noise static public key. See
	// ErrPeripheralInvalidPin.
	if cfg.ExpectedRemoteStatic != nil && len(cfg.ExpectedRemoteStatic) != bootstrap.NoiseKeySize {
		return nil, ErrPeripheralInvalidPin
	}

	// A transferred key is adopted as the peripheral's own, and consumed from
	// the config so a reused config cannot hand the next peripheral a second
	// owner for the same protected pages.
	var owned *bootstrap.NoiseStaticKey
	if cfg.OwnsStaticKey && cfg.LocalStaticKey != nil {
		owned = cfg.LocalStaticKey
		cfg.LocalStaticKey = nil
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.DeviceName == "" {
		cfg.DeviceName = "xKey"
	}

	if cfg.LiveAttestTimeout == 0 {
		cfg.LiveAttestTimeout = DefaultLiveAttestTimeout
	}

	mtu := cfg.MTU
	if mtu < pairingproto.MinMTU {
		mtu = DefaultMTU
	}

	return &BLEPeripheral{
		cfg:              cfg,
		adoptedStaticKey: owned,
		log:              logger.With("component", "ble_peripheral"),
		openAdapter:      openTinygoAdapter,
		mtu:              mtu,
		incomingData:     make(chan []byte, 100),
		stopChan:         make(chan struct{}),
	}, nil
}

// Start begins advertising and accepting connections.
//
// It is not safe to call twice, and it now says so before doing any damage
// rather than after. Everything below re-enables the adapter, replaces the
// GATT characteristic handles and re-registers the service — on a peripheral
// that may be running — so discovering "already started" at the publication
// step at the end was far too late: a repeated Start had already mutated the
// live peripheral, and often failed with a start error rather than the
// already-running one.
func (p *BLEPeripheral) Start(ctx context.Context) error {
	if p.closed.Load() {
		return ErrBackendClosed
	}
	if err := p.reserveStart(); err != nil {
		return err
	}
	defer p.releaseStart()

	p.log.Info("starting BLE peripheral",
		slog.String("device_name", p.cfg.DeviceName),
	)

	// Enable the BLE adapter
	p.adapter = p.openAdapter(p.cfg.AdapterID)
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

	if err := p.publishAdvertisement(adv); err != nil {
		return err
	}

	p.log.Info("BLE peripheral started, advertising",
		slog.String("service_uuid", XKeyServiceUUID.String()),
	)

	return nil
}

// publishAdvertisement installs adv as the peripheral's advertisement and
// raises it, without releasing lifeMu in between.
//
// Start was not serialized against Stop at all: a Stop running concurrently
// could destroy the static key and return while Start carried on bringing
// advertising up, leaving the peripheral advertising a service whose key had
// been freed. Taking the lifecycle lock closed most of that, but not the part
// that mattered — advertising was raised BEFORE the handle was published, so a
// Stop landing in that window saw no advertisement to take down, destroyed the
// key, and returned success while Start went on advertising a service backed
// by freed pages until it noticed the closed flag.
//
// Publication and the side effect it describes are one step under lifeMu, so a
// Stop either runs entirely before this — and nothing is ever advertised — or
// entirely after, and finds the handle it has to take down.
//
// A SECOND START IS REFUSED rather than allowed to overwrite the handle. The
// adapter hands out a cached advertisement object, so two Starts get the SAME
// one: the second raise fails with an already-started error, and rolling the
// handle back on that failure would drop the first call's live advertisement —
// after which Stop finds nothing to take down and reports success while the
// peripheral is still discoverable. One owner, one handle.
//
// AND A FAILED RAISE KEEPS ITS HANDLE. The error says the raise did not
// complete, not that nothing was registered — on Linux the advertisement is
// registered first and later steps can still fail. Assuming it is down is the
// unsafe direction, so the handle stays for Stop to take down, and Stop reports
// whether that succeeded.
//
// LIMIT, stated because it is a real one: adv.Start is called with lifeMu held,
// so a controller call that hangs blocks Stop from even setting closed. Making
// the raise happen outside the lock needs a starting/active/failed state with a
// bounded join for Stop to wait on, which is wider than this change; it is
// filed for v0.7.7. The lock is held here because the alternative available
// today is the defect above — advertising a service whose key has been freed —
// and a hung controller is the lesser failure.
func (p *BLEPeripheral) publishAdvertisement(adv advertiser) error {
	err := p.raiseAdvertisement(adv)
	if err != nil && !errors.Is(err, ErrBackendClosed) {
		p.log.Error("failed to start advertising", slog.String("error", err.Error()))
	}
	return err
}

// reserveStart claims the exclusive right to bring this peripheral up, and
// reports ErrPeripheralAlreadyRunning to anyone who arrives while it is held or
// while an advertisement is already published.
//
// A CHECK IS NOT ENOUGH HERE, which is what the first attempt got wrong. Two
// concurrent Starts could both pass a check and then race each other through
// assigning the adapter, replacing the characteristic handles and registering
// the GATT service — with the authoritative check at the publication step
// rejecting one of them only after all that damage was done. The reservation
// spans the whole of Start, so the second caller never begins.
//
// releaseStart drops it. The publication step keeps its own check, which stays
// the authoritative one for the advertisement handle itself.
func (p *BLEPeripheral) reserveStart() error {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	if p.closed.Load() {
		return ErrBackendClosed
	}
	if p.starting || p.adv != nil {
		return ErrPeripheralAlreadyRunning
	}
	p.starting = true
	return nil
}

// releaseStart drops the reservation taken by reserveStart.
func (p *BLEPeripheral) releaseStart() {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	p.starting = false
}

// raiseAdvertisement is publishAdvertisement's critical section, split out so
// the logger — which is caller-supplied and could re-enter — runs with lifeMu
// released.
func (p *BLEPeripheral) raiseAdvertisement(adv advertiser) error {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	if p.closed.Load() {
		return ErrBackendClosed
	}
	if p.adv != nil {
		return ErrPeripheralAlreadyRunning
	}

	p.adv = adv
	if err := adv.Start(); err != nil {
		return &SentinelCauseError{Sentinel: ErrPeripheralStartFailed, Cause: err}
	}
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
			p.handleWrite(client, value)
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
//
// It binds the session to whichever central client identifies on the first
// write, and drops every write from a different client rather than queuing
// it — see boundCentral for why one central's fragments must never reach
// another's reassembler.
func (p *BLEPeripheral) handleWrite(client bluetooth.Connection, data []byte) {
	p.writeMu.Lock()
	switch {
	case !p.centralBound:
		p.boundCentral = client
		p.centralBound = true
	case client != p.boundCentral:
		p.writeMu.Unlock()
		p.log.Debug("dropping write from unbound central",
			slog.Int("client", int(client)),
			slog.Int("bound_client", int(p.boundCentral)),
		)
		return
	}
	p.writeMu.Unlock()

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

// resetCentralBinding clears the central handleWrite is currently bound to.
//
// AcceptConnection calls it before waiting on a new connection, so a fresh
// session does not inherit the previous session's binding, and again when
// the session ends, so a stale binding cannot outlive it and refuse the next
// legitimate central's first write.
func (p *BLEPeripheral) resetCentralBinding() {
	p.writeMu.Lock()
	p.centralBound = false
	p.boundCentral = 0
	p.writeMu.Unlock()
}

// registerConnection admits a connection into the drain set, or refuses it
// because the peripheral is stopping.
//
// The check and the registration are ONE STEP under lifeMu, and that is the
// whole point: a connection that takes the lock after Stop sees closed and
// never registers, and one that takes it before has registered by the time
// Stop reaches Wait. Splitting them -- or moving the Add out from under
// lifeMu -- restores an Add-after-Wait, and with it a Stop that frees the
// static key while a live connection is still reading those pages.
//
// It exists as its own method so tests can enter the drain set through the
// PRODUCTION path. A test that hand-rolls the same three lines keeps passing
// when this sequence is broken, because it is no longer testing this
// sequence; that is exactly what it was doing before (#40).
//
// The caller owns the matching connWG.Done.
func (p *BLEPeripheral) registerConnection() error {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	if p.closed.Load() {
		return ErrBLEPeripheralStopped
	}
	p.addPendingConnection()
	return nil
}

// addPendingConnection registers one in-flight connection on connWG.
//
// It exists so the test seam fires at the ADD, inseparably from it, rather
// than merely somewhere inside registerConnection. That distinction is the
// whole value of the seam: an earlier version called the gate a few lines
// above the Add, so a regression that released lifeMu BETWEEN them still
// looked correct -- the gate observed the lock held, and the Add then ran
// outside it. Verified: that mutant passed the race test three times out of
// three, under -race.
//
// The caller must hold lifeMu. The Add and the closed check have to be one
// atomic step against Stop (see lifeMu), and an Add that lands after Stop's
// Wait is the key-release hazard this whole path exists to prevent.
func (p *BLEPeripheral) addPendingConnection() {
	if p.registerGate != nil {
		p.registerGate()
	}
	p.connWG.Add(1)
}

// AcceptConnection waits for and handles a client connection.
// This should be called in a loop to handle multiple connections.
func (p *BLEPeripheral) AcceptConnection(ctx context.Context) error {
	// One connection at a time; see acceptMu.
	p.acceptMu.Lock()
	defer p.acceptMu.Unlock()

	if err := p.registerConnection(); err != nil {
		return err
	}
	defer p.connWG.Done()

	// See boundCentral: a session's control-point writes are bound to
	// whichever central sends the first one, and that binding must not leak
	// across sessions in either direction.
	p.resetCentralBinding()
	defer p.resetCentralBinding()

	p.log.Info("waiting for phone connection...")

	// Initialize fragmentation helpers. Outbound fragments are sized to fit
	// inside a single ATT notification PDU; see bleNotifyOverhead.
	p.fragmenter = pairingproto.NewFragmenter(p.mtu - bleNotifyOverhead)
	p.reassembler = pairingproto.NewReassembler()
	p.sender = newFragmentSender(p.notifier, p.fragmenter, p.log)

	// Create Noise session as responder.
	//
	// A key transferred with OwnsStaticKey lives in adoptedStaticKey, and is
	// consulted here so a transferred key behaves exactly like a supplied
	// borrowed one: reused for every connection, never regenerated.
	//
	// It is deliberately NOT generatedStaticKey. That field holds the
	// per-connection key this peripheral makes when no key is supplied at
	// all, and whether that should instead be one stable per-peripheral
	// identity is an open owner decision — per-connection keys give
	// unlinkability, a stable key gives the peer something to pin. Folding
	// the two fields together would have silently decided it.
	p.lifeMu.Lock()
	localStatic := p.cfg.LocalStaticKey
	if localStatic == nil {
		localStatic = p.adoptedStaticKey
	}
	p.lifeMu.Unlock()

	if localStatic == nil {
		key, err := bootstrap.GenerateNoiseStaticKey()
		if err != nil {
			return &WrappedError{Msg: "failed to generate static key", Err: err}
		}
		// acceptMu guarantees the previous connection has returned, so the
		// key it used has no remaining reader by the time this replaces it.
		p.lifeMu.Lock()
		p.generatedStaticKey.Destroy()
		p.generatedStaticKey = key
		p.lifeMu.Unlock()
		localStatic = key
	}

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey:       localStatic,
		ExpectedRemoteStatic: p.cfg.ExpectedRemoteStatic,
		IsInitiator:          false, // We are the responder
	})
	if err != nil {
		return &WrappedError{Msg: "failed to create noise session", Err: err}
	}
	p.publishSession(session)

	// Wait for handshake messages
	if err := p.performHandshake(ctx); err != nil {
		return &WrappedError{Msg: "handshake failed", Err: err}
	}

	p.connected.Store(true)
	p.log.Info("phone connected, session established")

	// The #129 live attestation gate, before ANY request is served. Without
	// it, possession of a copied Noise static key was sufficient to reach
	// the bridge on a phone-initiated connection -- unlike a
	// laptop-initiated one, which PhoneKeyBackend.Connect already proves
	// liveness on. See BLEPeripheralConfig.LiveAttest.
	if err := p.performLiveAttestation(ctx, session); err != nil {
		return &WrappedError{Msg: "live attestation refused", Err: err}
	}

	// Handle requests
	return p.handleRequests(ctx)
}

// performLiveAttestation runs the peripheral's configured LiveAttest
// verifier once, immediately after the handshake and before any request is
// served. Required: a nil LiveAttest refuses the connection rather than
// serving requests with no liveness check (ErrLiveAttestationUnavailable),
// matching PhoneKeyBackend.proveLiveness's own fail-closed contract for the
// same proof on the initiator side.
func (p *BLEPeripheral) performLiveAttestation(ctx context.Context, session *bootstrap.NoiseSession) error {
	if p.cfg.LiveAttest == nil {
		return ErrLiveAttestationUnavailable
	}

	channelBinding, err := pairingproto.AttestChannelBinding(session)
	if err != nil {
		return err
	}

	attestCtx, cancel := context.WithTimeout(ctx, p.cfg.LiveAttestTimeout)
	defer cancel()

	exchange := pairing.InlineExchange(session,
		func(ctx context.Context, ciphertext []byte) error {
			return p.sendMessage(ctx, ciphertext)
		},
		func(ctx context.Context) ([]byte, error) {
			// attestCtx already carries LiveAttestTimeout as a deadline, so
			// the receive waits on ctx.Done() rather than a second, redundant
			// timer of its own.
			return p.receiveMessageTimeout(ctx, 0)
		},
	)

	return p.cfg.LiveAttest(attestCtx, exchange, channelBinding)
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
			fragment, err := pairingproto.DecodeFragment(data)
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

	// Encrypt and send response. The request and response plaintexts can
	// carry key material (a decrypted plaintext, a derived shared secret),
	// so both are wiped once Noise has consumed them. The response is
	// encrypted before the request is wiped in case the handler returned a
	// slice of the request.
	encrypted, err := p.session.Encrypt(response)
	secure.Wipe(response)
	secure.Wipe(plaintext)
	if err != nil {
		return &WrappedError{Msg: "encrypt response failed", Err: err}
	}

	return p.sendMessage(ctx, encrypted)
}

// publishSession installs session as the peripheral's current one and takes
// the public-key snapshot in the same step.
//
// The two must move together. LocalStaticPublicKey reads the snapshot rather
// than the session precisely so it cannot touch pages Stop may have freed —
// which only works if every path that publishes a session also fills the
// snapshot. Assigning p.session directly is how that pair silently came
// apart: the test helper kept doing it after the snapshot was introduced, and
// LocalStaticPublicKey started returning nothing on a peripheral with a live
// session. There is now one way to publish, so the pair cannot diverge again.
func (p *BLEPeripheral) publishSession(session *bootstrap.NoiseSession) {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	p.session = session
	p.localStaticPublic = append([]byte(nil), session.LocalStaticPublicKey()...)
}

// Stop stops advertising and closes connections.
//
// It returns ErrShutdownIncomplete when shutdown could not be confirmed
// complete — an accepted connection that did not finish within
// peripheralShutdownTimeout, or an advertisement that could not be taken down.
// The peripheral is stopped regardless and accepts no further connections.
//
// THE ERROR DOES NOT BY ITSELF MEAN THE KEY WAS RETAINED, and reading it that
// way makes a borrowed key's owner hold locked pages it could free. The two
// answers have different conditions: the key is retained only when the
// CONNECTION JOIN could not be confirmed, because nothing but AcceptConnection
// and its session reads those pages. An advertisement that would not come down
// leaves the peripheral possibly discoverable — so the shutdown is genuinely
// incomplete and says so — but it cannot reach the key, which is freed on the
// join alone.
//
// MUST NOT be called from a RequestHandler. Stop waits for handlers to
// finish, and the latch makes a re-entrant caller wait for Stop — so a
// handler that calls it guarantees the full shutdown window elapses and the
// key is retained. This is the classic self-deadlock of any Shutdown that
// drains its own callbacks (net/http.Server.Shutdown behaves the same way),
// and it is bounded rather than permanent because the join has a timeout.
// The alternative — answering a re-entrant caller early — is the defect the
// latch exists to fix: two callers reaching different conclusions about
// whether the protected key is safe to free.
func (p *BLEPeripheral) Stop() error {
	// Latched, so every caller observes the SAME outcome. A concurrent Stop
	// used to return nil the instant the first set closed — telling the owner
	// of a borrowed key that destroying it was safe while the first Stop was
	// still waiting on a handler that reads it.
	p.stopOnce.Do(func() { p.stopErr = p.stop() })
	return p.stopErr
}

func (p *BLEPeripheral) stop() error {
	// Set closed under lifeMu so that any AcceptConnection which passed its
	// check has already registered on connWG before Wait runs below.
	p.lifeMu.Lock()
	alreadyClosed := p.closed.Swap(true)
	p.lifeMu.Unlock()

	if alreadyClosed {
		return nil
	}

	close(p.stopChan)

	// Stop advertising before draining. A peripheral that is still
	// discoverable can accept a new connection while Stop waits, and that
	// connection would read the key Stop is about to release.
	p.lifeMu.Lock()
	adv := p.adv
	p.adv = nil
	p.lifeMu.Unlock()

	// Whether the peripheral is provably no longer discoverable. A failure
	// here used to be logged and dropped, so Stop reported success while the
	// peripheral carried on advertising — a shutdown that had not finished,
	// reported as one that had.
	//
	// It does NOT decide the key's fate. A central arriving at a peripheral
	// that is still advertising cannot register, because closed was set under
	// lifeMu before the drain, so it cannot reach the protected pages. The
	// join decides the key; this decides whether the shutdown is complete.
	quiet := true
	if adv != nil {
		if err := adv.Stop(); err != nil {
			quiet = false
			p.log.Error("failed to stop advertising; the peripheral may still be "+
				"discoverable", slog.String("error", err.Error()))
		}
	}

	// Unblock the request loop, then wait for every AcceptConnection to
	// return before freeing the key it was reading.
	//
	// Bounded, because AcceptConnection can be sitting inside a
	// caller-supplied RequestHandler.HandleRequest, on a context this
	// peripheral neither owns nor cancels. An unbounded wait here makes a
	// third party's slow handler into a Stop that never returns.
	joined := p.connJoiner.Join(&p.connWG, peripheralShutdownTimeout)

	// TWO DECISIONS, NOT ONE, and they do not share a condition.
	//
	// The key may be freed once `joined` holds. What reads these pages is
	// AcceptConnection and the session it builds, and nothing else — the
	// advertisement carries a service UUID and a device name, not key
	// material. `joined` proves every accepted connection returned, and
	// `closed` was set under lifeMu before the drain, so AcceptConnection
	// refuses to register a new one. A central arriving at a peripheral that
	// is still advertising therefore cannot reach the key.
	//
	// Coupling the two was over-conservative in a way that costs something
	// real: it retained protected pages for the life of the process every time
	// an advertisement failed to come down, which is neither necessary nor
	// free.
	//
	// Shutdown SUCCESS still needs both. A peripheral that is still
	// discoverable has not finished stopping, whatever the key's fate, and
	// saying otherwise is the fail-open this release exists to remove.
	p.lifeMu.Lock()
	if joined {
		p.generatedStaticKey.Destroy()
		p.generatedStaticKey = nil
		p.adoptedStaticKey.Destroy()
		p.adoptedStaticKey = nil
	} else {
		// Retained, not freed: a handler still running may be encrypting
		// through these pages. The peripheral is stopped either way.
		//
		// The reference stays on the peripheral rather than being cleared.
		// Nothing can reach it — Stop is terminal — but "retained" and "we
		// dropped the only pointer" should not look the same in the source,
		// and keeping the owner is what would let a reclamation path exist.
		p.log.Warn("retaining the peripheral static key: a connection did not "+
			"finish within the shutdown window",
			"timeout", peripheralShutdownTimeout)
	}
	p.localStaticPublic = nil
	p.lifeMu.Unlock()

	p.log.Info("BLE peripheral stopped",
		"connections_joined", joined, "advertising_stopped", quiet)

	if !joined || !quiet {
		return ErrShutdownIncomplete
	}
	return nil
}

// peripheralShutdownTimeout bounds how long Stop waits for in-flight
// connections to finish. A connection is running a caller-supplied request
// handler that may be waiting on a user, so the window is generous; what it
// must not be is absent.
//
// A var rather than a const so tests can exercise the timeout branch without
// spending the production window on it. Nothing else writes it.
var peripheralShutdownTimeout = 30 * time.Second

// IsConnected returns true if a client is connected.
func (p *BLEPeripheral) IsConnected() bool {
	return p.connected.Load()
}

// LocalStaticPublicKey returns a copy of the current connection's static
// public key, or nil before the first connection and after Stop.
//
// It reads a snapshot rather than the session, so it neither races
// AcceptConnection publishing a new session nor touches the protected private
// pages Stop destroys.
func (p *BLEPeripheral) LocalStaticPublicKey() []byte {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()

	if p.localStaticPublic == nil {
		return nil
	}
	return append([]byte(nil), p.localStaticPublic...)
}
