// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"strings"
	"sync"

	"tinygo.org/x/bluetooth"
)

// In-memory stand-ins for the GATT client seams in ble_transport.go. They
// model what the transport relies on from tinygo/BlueZ: Scan delivers
// advertisements and blocks until StopScan, Connect yields a device whose
// discovery returns services and characteristics, and notifications arrive
// through the callback EnableNotifications registered.

// fakeBluetoothctl records bluetoothctl invocations and answers each verb
// (info, trust, remove, disconnect) with a configured reply; an unconfigured
// verb succeeds with no output.
type fakeBluetoothctl struct {
	mu      sync.Mutex
	calls   []string
	replies map[string]ctlReply
}

type ctlReply struct {
	output string
	err    error
}

func newFakeBluetoothctl() *fakeBluetoothctl {
	return &fakeBluetoothctl{replies: map[string]ctlReply{}}
}

func (f *fakeBluetoothctl) reply(verb, output string, err error) *fakeBluetoothctl {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[verb] = ctlReply{output: output, err: err}
	return f
}

func (f *fakeBluetoothctl) run(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	r := f.replies[args[0]]
	return []byte(r.output), r.err
}

// called reports how many times bluetoothctl ran with exactly these args.
func (f *fakeBluetoothctl) called(args ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := strings.Join(args, " ")
	n := 0
	for _, c := range f.calls {
		if c == want {
			n++
		}
	}
	return n
}

// fakeCentral stands in for the system adapter.
type fakeCentral struct {
	enableErr   error
	results     []bluetooth.ScanResult
	scanErr     error
	stopScanErr error
	// connectErrs holds the error for each Connect attempt in turn; once it
	// is exhausted Connect returns device.
	connectErrs []error
	device      *fakeDevice

	mu            sync.Mutex
	connectCalls  int
	stopScanCalls int
	scanning      chan struct{}
	scanDone      chan struct{}
	// stopPending records a StopScan that arrived before Scan started, so
	// the late Scan returns instead of blocking forever.
	stopPending bool
}

func newFakeCentral() *fakeCentral {
	return &fakeCentral{}
}

func (c *fakeCentral) Enable() error {
	return c.enableErr
}

// Scan delivers every configured advertisement, then returns scanErr if set
// or blocks until StopScan, as the BlueZ backend does.
func (c *fakeCentral) Scan(callback func(*bluetooth.Adapter, bluetooth.ScanResult)) error {
	c.mu.Lock()
	if c.stopPending {
		c.stopPending = false
		c.mu.Unlock()
		return nil
	}
	c.scanning = make(chan struct{})
	c.scanDone = make(chan struct{})
	scanning, done := c.scanning, c.scanDone
	c.mu.Unlock()
	defer close(done)

	for _, r := range c.results {
		callback(nil, r)
	}
	if c.scanErr != nil {
		return c.scanErr
	}
	<-scanning
	return nil
}

// StopScan ends a running Scan and waits for it to return, so everything the
// scan callback did happens before StopScan returns.
func (c *fakeCentral) StopScan() error {
	c.mu.Lock()
	c.stopScanCalls++
	scanning, done := c.scanning, c.scanDone
	c.scanning = nil
	if scanning == nil {
		c.stopPending = true
	}
	c.mu.Unlock()
	if scanning != nil {
		close(scanning)
		<-done
	}
	return c.stopScanErr
}

func (c *fakeCentral) Connect(bluetooth.Address) (bleDevice, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	attempt := c.connectCalls
	c.connectCalls++
	if attempt < len(c.connectErrs) && c.connectErrs[attempt] != nil {
		return nil, c.connectErrs[attempt]
	}
	return c.device, nil
}

func (c *fakeCentral) counts() (connects, stopScans int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectCalls, c.stopScanCalls
}

// fakeDevice answers DiscoverServices from discoveries, one reply per call;
// the last reply repeats once the list is exhausted.
type fakeDevice struct {
	discoveries   []discoverReply
	disconnectErr error

	mu            sync.Mutex
	discoverCalls int
	disconnects   int
}

type discoverReply struct {
	services []bleService
	err      error
}

func (d *fakeDevice) DiscoverServices([]bluetooth.UUID) ([]bleService, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	i := min(d.discoverCalls, len(d.discoveries)-1)
	d.discoverCalls++
	return d.discoveries[i].services, d.discoveries[i].err
}

func (d *fakeDevice) Disconnect() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.disconnects++
	return d.disconnectErr
}

func (d *fakeDevice) disconnectCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.disconnects
}

type fakeService struct {
	uuid  bluetooth.UUID
	chars []bleCharacteristic
	err   error
}

func (s *fakeService) UUID() bluetooth.UUID {
	return s.uuid
}

func (s *fakeService) DiscoverCharacteristics([]bluetooth.UUID) ([]bleCharacteristic, error) {
	return s.chars, s.err
}

// fakeCharacteristic records writes and keeps the notification callback the
// transport registered so a test can play the phone's side.
type fakeCharacteristic struct {
	uuid      bluetooth.UUID
	enableErr error
	writeErr  error
	// release, when set, holds every write until it is closed.
	release chan struct{}
	// onWrite, when set, sees each written fragment (the phone receiving it).
	onWrite func(frag []byte)

	mu     sync.Mutex
	writes [][]byte
	notify func([]byte)
}

func (c *fakeCharacteristic) UUID() bluetooth.UUID {
	return c.uuid
}

func (c *fakeCharacteristic) WriteWithoutResponse(p []byte) (int, error) {
	if c.release != nil {
		<-c.release
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	if c.onWrite != nil {
		c.onWrite(p)
	}
	return len(p), nil
}

func (c *fakeCharacteristic) EnableNotifications(callback func(buf []byte)) error {
	if c.enableErr != nil {
		return c.enableErr
	}
	c.mu.Lock()
	c.notify = callback
	c.mu.Unlock()
	return nil
}

func (c *fakeCharacteristic) notifier() func([]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.notify
}

func (c *fakeCharacteristic) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// fakePhone is an xKey GATT server: one service carrying the control point,
// response and status characteristics.
type fakePhone struct {
	device   *fakeDevice
	service  *fakeService
	control  *fakeCharacteristic
	response *fakeCharacteristic
	status   *fakeCharacteristic
}

// newFakePhone builds a phone whose xKey service is found by the first,
// filtered discovery.
func newFakePhone() *fakePhone {
	p := &fakePhone{
		control:  &fakeCharacteristic{uuid: ControlPointUUID},
		response: &fakeCharacteristic{uuid: ResponseUUID},
		status:   &fakeCharacteristic{uuid: StatusUUID},
	}
	p.service = &fakeService{
		uuid:  XKeyServiceUUID,
		chars: []bleCharacteristic{p.control, p.response, p.status},
	}
	p.device = &fakeDevice{discoveries: []discoverReply{{services: []bleService{p.service}}}}
	return p
}

// fakeAdvertisement is an advertisement payload carrying a local name and
// service UUIDs.
type fakeAdvertisement struct {
	name     string
	services []bluetooth.UUID
}

func (a fakeAdvertisement) LocalName() string {
	return a.name
}

func (a fakeAdvertisement) HasServiceUUID(uuid bluetooth.UUID) bool {
	for _, s := range a.services {
		if s == uuid {
			return true
		}
	}
	return false
}

func (a fakeAdvertisement) ServiceUUIDs() []bluetooth.UUID {
	return a.services
}

func (a fakeAdvertisement) Bytes() []byte {
	return nil
}

func (a fakeAdvertisement) ManufacturerData() []bluetooth.ManufacturerDataElement {
	return nil
}

func (a fakeAdvertisement) ServiceData() []bluetooth.ServiceDataElement {
	return nil
}
