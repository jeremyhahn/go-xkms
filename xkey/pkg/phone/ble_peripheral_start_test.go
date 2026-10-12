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
	"context"
	"errors"
	"testing"
	"time"

	"tinygo.org/x/bluetooth"
)

// fakeGATTServer stands in for the adapter Start brings up. It keeps the
// service Start registered so a test can inspect it and play the central by
// calling the control point's WriteEvent.
type fakeGATTServer struct {
	enableErr error
	addErr    error
	adv       *fakeGATTAdvertiser

	service *bluetooth.Service
}

func (s *fakeGATTServer) Enable() error {
	return s.enableErr
}

func (s *fakeGATTServer) AddService(service *bluetooth.Service) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.service = service
	return nil
}

func (s *fakeGATTServer) DefaultAdvertisement() configurableAdvertiser {
	return s.adv
}

// fakeGATTAdvertiser records how the advertisement was configured, raised and
// taken down.
type fakeGATTAdvertiser struct {
	configureErr error
	startErr     error

	options *bluetooth.AdvertisementOptions
	starts  int
	stops   int
}

func (a *fakeGATTAdvertiser) Configure(options bluetooth.AdvertisementOptions) error {
	if a.configureErr != nil {
		return a.configureErr
	}
	a.options = &options
	return nil
}

func (a *fakeGATTAdvertiser) Start() error {
	a.starts++
	return a.startErr
}

func (a *fakeGATTAdvertiser) Stop() error {
	a.stops++
	return nil
}

// startablePeripheral returns a test peripheral whose adapter is server, and
// records the adapter ID Start asked for in *openedID.
func startablePeripheral(t *testing.T, server *fakeGATTServer, openedID *string) *BLEPeripheral {
	t.Helper()
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	p.openAdapter = func(id string) gattServer {
		*openedID = id
		return server
	}
	return p
}

func TestStart_RegistersTheXKeyServiceAndAdvertisesIt(t *testing.T) {
	server := &fakeGATTServer{adv: &fakeGATTAdvertiser{}}
	var openedID string
	p := startablePeripheral(t, server, &openedID)
	p.cfg.AdapterID = "hci1"

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if openedID != "hci1" {
		t.Fatalf("Start opened adapter %q, want the configured hci1", openedID)
	}

	svc := server.service
	if svc == nil || svc.UUID != XKeyServiceUUID {
		t.Fatalf("registered service = %+v, want the xKey service", svc)
	}
	want := []struct {
		uuid   bluetooth.UUID
		handle *bluetooth.Characteristic
		flags  bluetooth.CharacteristicPermissions
	}{
		{ControlPointUUID, p.controlPoint, bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission},
		{ResponseUUID, p.response, bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission},
		{StatusUUID, p.status, bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission},
	}
	if len(svc.Characteristics) != len(want) {
		t.Fatalf("service has %d characteristics, want %d", len(svc.Characteristics), len(want))
	}
	for i, w := range want {
		got := svc.Characteristics[i]
		if got.UUID != w.uuid || got.Flags != w.flags {
			t.Errorf("characteristic %d = %v flags %v, want %v flags %v", i, got.UUID, got.Flags, w.uuid, w.flags)
		}
		// Without a handle the peripheral cannot notify through it.
		if got.Handle == nil || got.Handle != w.handle {
			t.Errorf("characteristic %v is not bound to the peripheral's handle", w.uuid)
		}
	}
	if p.notifier != FragmentWriter(p.response) {
		t.Error("responses are not notified on the response characteristic")
	}

	opts := server.adv.options
	if opts == nil || opts.LocalName != "xKey-test" ||
		len(opts.ServiceUUIDs) != 1 || opts.ServiceUUIDs[0] != XKeyServiceUUID {
		t.Fatalf("advertisement options = %+v, want the device name and the xKey service", opts)
	}
	if server.adv.starts != 1 {
		t.Fatalf("advertising raised %d times, want 1", server.adv.starts)
	}

	// A central's write on the control point reaches the request loop.
	svc.Characteristics[0].WriteEvent(bluetooth.Connection(1), 0, []byte("frame"))
	select {
	case got := <-p.incomingData:
		if string(got) != "frame" {
			t.Fatalf("incomingData = %q, want the written frame", got)
		}
	case <-time.After(time.Second):
		t.Fatal("a control point write did not reach incomingData")
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if server.adv.stops != 1 {
		t.Fatalf("Stop took advertising down %d times, want 1", server.adv.stops)
	}
}

func TestStart_FailuresReportPeripheralStartFailed(t *testing.T) {
	cause := errors.New("controller refused")
	tests := []struct {
		name   string
		server *fakeGATTServer
		// raised is whether advertising was asked to come up.
		raised bool
	}{
		{"enable", &fakeGATTServer{enableErr: cause, adv: &fakeGATTAdvertiser{}}, false},
		{"add service", &fakeGATTServer{addErr: cause, adv: &fakeGATTAdvertiser{}}, false},
		{"configure advertisement", &fakeGATTServer{adv: &fakeGATTAdvertiser{configureErr: cause}}, false},
		{"start advertising", &fakeGATTServer{adv: &fakeGATTAdvertiser{startErr: cause}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var openedID string
			p := startablePeripheral(t, tt.server, &openedID)

			err := p.Start(context.Background())
			if !errors.Is(err, ErrPeripheralStartFailed) || !errors.Is(err, cause) {
				t.Fatalf("Start = %v, want ErrPeripheralStartFailed carrying the cause", err)
			}
			if openedID != "" {
				t.Fatalf("Start opened adapter %q, want the default adapter", openedID)
			}
			if raised := tt.server.adv.starts > 0; raised != tt.raised {
				t.Fatalf("advertising raised = %v, want %v", raised, tt.raised)
			}
		})
	}
}

// TestStart_RetriesAfterTheAdapterFailsToEnable checks that a failed Start
// releases its reservation, so the caller can try again once the adapter is
// available.
func TestStart_RetriesAfterTheAdapterFailsToEnable(t *testing.T) {
	server := &fakeGATTServer{enableErr: errors.New("adapter powered off"), adv: &fakeGATTAdvertiser{}}
	var openedID string
	p := startablePeripheral(t, server, &openedID)

	if err := p.Start(context.Background()); !errors.Is(err, ErrPeripheralStartFailed) {
		t.Fatalf("first Start = %v, want ErrPeripheralStartFailed", err)
	}

	server.enableErr = nil
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start after the adapter came up: %v", err)
	}
	if server.adv.starts != 1 {
		t.Fatalf("advertising raised %d times, want 1", server.adv.starts)
	}
}

func TestOpenTinygoAdapter_SelectsTheNamedAdapter(t *testing.T) {
	def, ok := openTinygoAdapter("").(tinygoGATTServer)
	if !ok || def.adapter != bluetooth.DefaultAdapter {
		t.Fatal("an empty adapter ID did not select the system default adapter")
	}

	named, ok := openTinygoAdapter("hci7").(tinygoGATTServer)
	if !ok || named.adapter == nil || named.adapter == bluetooth.DefaultAdapter {
		t.Fatal("a named adapter ID fell back to the system default adapter")
	}
}
