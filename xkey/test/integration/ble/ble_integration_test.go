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

//go:build integration && linux && ble

package ble

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

const (
	// peripheralAdapter is the controller the xKey GATT server advertises on;
	// centralAdapter is the one the client connects from. btvirt attaches
	// them in order and tinygo's DefaultAdapter is hci0.
	peripheralAdapter = "hci1"
	centralAdapter    = "hci0"

	// bluetoothSysPath lists the controllers the kernel knows about.
	bluetoothSysPath = "/sys/class/bluetooth"

	// responseSize forces the peripheral response across several BLE
	// fragments: the negotiated payload is at most a couple hundred bytes.
	responseSize = 4096
)

// airLinkDiagnosis is printed verbatim whenever the platform cannot carry BLE
// traffic between the two controllers. It is deliberately loud and specific:
// this suite must never look green while proving nothing.
const airLinkDiagnosis = `
================================ BLE AIR LINK UNAVAILABLE ================================
The virtual-hardware harness came up correctly (hci_vhci loaded, two btvirt
controllers attached, both registered and powered by bluetoothd), but this
platform cannot carry BLE packets between the two controllers, so the
peripheral <-> central round trip cannot be exercised here.

What was measured on a 6.x/7.x kernel with BlueZ 5.72 btvirt controllers:

  1. Registering a GATT application (GattManager1.RegisterApplication)
     SUCCEEDS: the xKey service and its characteristics are accepted by a
     real bluetoothd on a real (emulated) controller.
  2. Registering an advertisement (LEAdvertisingManager1.RegisterAdvertisement)
     FAILS. bluetoothd logs:
         src/advertising.c:add_client_complete()
         Failed to add advertisement: Invalid Parameters (0x0d)
     The kernel management interface rejects Add Advertising on btdev-emulated
     controllers. Reproduced with "btvirt -l2" (dual mode) and with
     "btvirt -L -l2" (LE only), with and without a local name, and with and
     without the 128-bit service UUID, so it is not an advertising-data length
     problem.
  3. Falling back to bluetoothd's own advertising (Adapter1.Discoverable=true,
     a different kernel code path that IS accepted) and running a 20 second
     active LE scan from the other controller discovers ZERO devices. BlueZ's
     btvirt controllers do not exchange advertising PDUs with each other
     through the kernel HCI path; BlueZ's own emulator tests drive btdev
     in-process over bt_phy rather than through two independent vhci
     controllers.

To run the full round trip you need a platform where the two controllers can
actually see each other:

  * two real Bluetooth adapters (or one adapter plus a phone/second machine),
    with the container run privileged, --network host and /run/dbus mounted; or
  * a controller emulator that links the two radios, which btvirt over
    /dev/vhci does not do today.

Everything below the radio - fragmentation, the notify path, Noise framing and
reassembly - is covered without hardware by the unit tests in pkg/phone
(TestFragmentSender_*, TestBLEPeripheral_*), which assert the exact bytes that
this test would have put on the air.
==========================================================================================
`

// echoHandler answers every request with a JSON-RPC result that repeats the
// request, padded so the response cannot fit in a single BLE fragment.
type echoHandler struct {
	padding string
}

func (h *echoHandler) HandleRequest(_ context.Context, request []byte) ([]byte, error) {
	return []byte(`{"jsonrpc":"2.0","result":"` + string(request) + h.padding + `"}`), nil
}

// testLogger returns a debug logger so the fragment-level traffic (sizes and
// hex prefixes on both sides) lands in the test output as evidence.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// failNoAirLink reports the exact stage that could not be reached and fails
// the test with the full diagnosis. This suite runs in the privileged BLE
// docker-compose stack, which provisions the virtual HCI controllers, so a
// missing air link is an environment fault rather than a reason to drop the
// coverage silently.
func failNoAirLink(t *testing.T, stage string, err error) {
	t.Helper()
	t.Logf("BLE air link unavailable at stage %q: %v", stage, err)
	t.Log(airLinkDiagnosis)
	t.Fatalf("no BLE air link between %s and %s (stage: %s); run this suite via "+
		"make integration-test-ble, which brings up the virtual HCI controllers",
		centralAdapter, peripheralAdapter, stage)
}

// controllers returns the HCI controllers the kernel currently exposes.
func controllers(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(bluetoothSysPath)
	if err != nil {
		t.Fatalf("BLE HARNESS BROKEN: cannot read %s: %v\n"+
			"The 'bluetooth' kernel module is not loaded. The container entrypoint "+
			"(test/integration/ble/entrypoint.sh) must run privileged with "+
			"/lib/modules mounted so it can modprobe bluetooth and hci_vhci.",
			bluetoothSysPath, err)
	}

	var found []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "hci") {
			found = append(found, entry.Name())
		}
	}
	return found
}

// requireVirtualControllers fails with an explicit, actionable reason when the
// virtual HCI controllers are missing. Without them nothing about BLE can be
// proven, and the suite must say so rather than pass.
func requireVirtualControllers(t *testing.T) {
	t.Helper()

	found := controllers(t)
	if len(found) < 2 {
		t.Fatalf("BLE HARNESS BROKEN: found %d controller(s) %v, need %s and %s.\n"+
			"btvirt must be running with two emulated controllers attached to "+
			"/dev/vhci. Check /tmp/btvirt.log in the container.",
			len(found), found, centralAdapter, peripheralAdapter)
	}
	t.Logf("virtual controllers present: %v", found)
}

// TestVirtualHCIHarness asserts the virtual hardware is genuinely up: two
// emulated controllers exist and a real bluetoothd has registered and powered
// both of them. Every later test depends on this, so a failure here is a
// harness failure, never a skip.
func TestVirtualHCIHarness(t *testing.T) {
	requireVirtualControllers(t)

	conn, err := dbus.SystemBus()
	if err != nil {
		t.Fatalf("BLE HARNESS BROKEN: cannot reach the D-Bus system bus: %v", err)
	}

	for _, hci := range []string{centralAdapter, peripheralAdapter} {
		obj := conn.Object("org.bluez", dbus.ObjectPath("/org/bluez/"+hci))

		address, err := obj.GetProperty("org.bluez.Adapter1.Address")
		if err != nil {
			t.Fatalf("BLE HARNESS BROKEN: bluetoothd has not registered /org/bluez/%s: %v\n"+
				"Only one bluetoothd can run per machine (it binds the ATT and SDP L2CAP "+
				"sockets on BDADDR_ANY, and Bluetooth sockets only work in the initial "+
				"network namespace). See test/integration/ble/entrypoint.sh.", hci, err)
		}

		powered, err := obj.GetProperty("org.bluez.Adapter1.Powered")
		if err != nil {
			t.Fatalf("BLE HARNESS BROKEN: cannot read Powered on /org/bluez/%s: %v", hci, err)
		}
		if on, ok := powered.Value().(bool); !ok || !on {
			t.Fatalf("BLE HARNESS BROKEN: /org/bluez/%s is not powered", hci)
		}

		// A GATT server needs GattManager1 on the adapter it serves from.
		if _, err := obj.GetProperty("org.bluez.LEAdvertisingManager1.SupportedInstances"); err != nil {
			t.Logf("%s: LEAdvertisingManager1 is not usable: %v", hci, err)
		}

		t.Logf("%s ready: address=%v powered=true", hci, address.Value())
	}
}

// startPeripheral brings up the xKey GATT server on the peripheral controller
// and serves one connection for the duration of the test. When the platform
// refuses to advertise, the test is stopped with the full diagnosis instead of
// reporting a hollow pass.
func startPeripheral(ctx context.Context, t *testing.T, handler phone.PeripheralRequestHandler) {
	t.Helper()

	peripheral, err := phone.NewBLEPeripheral(&phone.BLEPeripheralConfig{
		DeviceName:     "xKey",
		AdapterID:      peripheralAdapter,
		RequestHandler: handler,
		Logger:         testLogger(t),
	})
	if err != nil {
		t.Fatalf("NewBLEPeripheral failed: %v", err)
	}

	if err := peripheral.Start(ctx); err != nil {
		// The GATT application registers before the advertisement does, so an
		// advertising failure means BlueZ accepted the xKey service and the
		// radio is the only thing missing.
		if strings.Contains(err.Error(), "advertisement") {
			failNoAirLink(t, "advertisement registration", err)
		}
		t.Fatalf("peripheral failed to start on %s: %v", peripheralAdapter, err)
	}
	t.Cleanup(func() {
		if err := peripheral.Stop(); err != nil {
			t.Logf("peripheral stop: %v", err)
		}
	})

	go func() {
		if err := peripheral.AcceptConnection(ctx); err != nil && ctx.Err() == nil {
			t.Logf("peripheral stopped serving: %v", err)
		}
	}()
}

// connectCentral scans from the central controller, connects to the advertised
// xKey service and completes the Noise XX handshake.
func connectCentral(ctx context.Context, t *testing.T) (*phone.BLETransport, *bootstrap.NoiseSession) {
	t.Helper()

	cfg := phone.DefaultBLETransportConfig()
	cfg.Logger = testLogger(t)
	cfg.ScanTimeout = 20 * time.Second

	central, err := phone.NewBLETransport(cfg)
	if err != nil {
		t.Fatalf("central failed to open %s: %v", centralAdapter, err)
	}
	t.Cleanup(func() {
		if err := central.Close(); err != nil {
			t.Logf("central close: %v", err)
		}
	})

	results, err := central.Scan(ctx)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(results) == 0 {
		failNoAirLink(t, "discovery", &noAdvertisementError{})
	}
	t.Logf("central discovered %s (%s)", results[0].DisplayName(), results[0].Address)

	if err := central.Connect(ctx, results[0].Address); err != nil {
		t.Fatalf("connect to %s failed: %v", results[0].Address, err)
	}

	staticKey, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("generate static key: %v", err)
	}
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey: staticKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("new noise session: %v", err)
	}

	if err := pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport: central,
		Session:   session,
		Logger:    testLogger(t),
	}); err != nil {
		t.Fatalf("noise handshake over BLE failed: %v", err)
	}

	return central, session
}

// noAdvertisementError reports that a scan completed without seeing the
// peripheral's advertisement.
type noAdvertisementError struct{}

// Error implements the error interface.
func (e *noAdvertisementError) Error() string {
	return "the peripheral's advertisement was never seen by the central controller"
}

// TestBLEPeripheral_VirtualHCIRoundTrip drives the shipped GATT server and the
// shipped BLE client against two controllers and asserts that a fragmented
// response really crosses the air interface and reassembles byte-identically.
// Before the notify path was implemented, sendMessage transmitted nothing and
// this test could not pass.
func TestBLEPeripheral_VirtualHCIRoundTrip(t *testing.T) {
	requireVirtualControllers(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	handler := &echoHandler{padding: strings.Repeat("P", responseSize)}
	startPeripheral(ctx, t, handler)

	central, session := connectCentral(ctx, t)

	request := []byte(`{"jsonrpc":"2.0","method":"ping","id":1}`)
	ciphertext, err := session.Encrypt(request)
	if err != nil {
		t.Fatalf("encrypt request: %v", err)
	}

	response, err := central.SendAndReceive(ctx, ciphertext)
	if err != nil {
		t.Fatalf("no response reached the central: %v", err)
	}

	plaintext, err := session.Decrypt(response)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}

	want := `{"jsonrpc":"2.0","result":"` + string(request) + handler.padding + `"}`
	if string(plaintext) != want {
		t.Fatalf("response did not round trip byte-identically: got %d bytes, want %d bytes",
			len(plaintext), len(want))
	}
	if len(plaintext) <= phone.DefaultMTU {
		t.Fatalf("response of %d bytes was not large enough to require fragmentation", len(plaintext))
	}

	t.Logf("round trip verified: %d byte response reassembled byte-identically over HCI",
		len(plaintext))
}

// TestBLEPeripheral_VirtualHCIRepeatedRequests proves the session survives
// consecutive requests: the peripheral must keep reassembling inbound
// fragments and notifying outbound ones after the first exchange.
func TestBLEPeripheral_VirtualHCIRepeatedRequests(t *testing.T) {
	requireVirtualControllers(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	handler := &echoHandler{padding: strings.Repeat("Q", responseSize)}
	startPeripheral(ctx, t, handler)

	central, session := connectCentral(ctx, t)

	for i := range 3 {
		request := []byte(`{"jsonrpc":"2.0","method":"ping","id":` + string(rune('1'+i)) + `}`)
		ciphertext, err := session.Encrypt(request)
		if err != nil {
			t.Fatalf("request %d: encrypt: %v", i, err)
		}

		response, err := central.SendAndReceive(ctx, ciphertext)
		if err != nil {
			t.Fatalf("request %d: no response reached the central: %v", i, err)
		}

		plaintext, err := session.Decrypt(response)
		if err != nil {
			t.Fatalf("request %d: decrypt: %v", i, err)
		}
		want := `{"jsonrpc":"2.0","result":"` + string(request) + handler.padding + `"}`
		if string(plaintext) != want {
			t.Fatalf("request %d: response did not round trip byte-identically", i)
		}
	}
}
