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

package netguard

import (
	"errors"
	"net/netip"
	"testing"
)

func TestCheckDialAddress_AllowsAcceptedAddress(t *testing.T) {
	t.Parallel()
	if err := CheckDialAddress("8.8.8.8:80", AllowAll); err != nil {
		t.Fatalf("CheckDialAddress() error = %v, want nil", err)
	}
	if err := CheckDialAddress("8.8.8.8:80", DenyReserved); err != nil {
		t.Fatalf("CheckDialAddress() error = %v, want nil", err)
	}
}

func TestCheckDialAddress_RefusesDisallowedOrUnparseable(t *testing.T) {
	t.Parallel()
	for _, address := range []string{
		"127.0.0.1:80",
		"[::ffff:127.0.0.1]:80", // an IPv4-mapped loopback is still loopback
		"no-port",
		"not-an-ip:80",
	} {
		err := CheckDialAddress(address, DenyReserved)
		var refused *AddressNotPermittedError
		if !errors.As(err, &refused) {
			t.Errorf("CheckDialAddress(%q) error = %v, want *AddressNotPermittedError", address, err)
		}
	}
}

func TestDialControl_DefaultsToDenyReserved(t *testing.T) {
	t.Parallel()
	control := DialControl(nil)
	if err := control("tcp", "127.0.0.1:80", nil); err == nil {
		t.Fatal("DialControl(nil) accepted a loopback address, want refused")
	}
	if err := control("tcp", "8.8.8.8:80", nil); err != nil {
		t.Fatalf("DialControl(nil) refused a public address: %v", err)
	}
}

func TestDialControl_UsesCustomAllowFunc(t *testing.T) {
	t.Parallel()
	only203 := func(addr netip.Addr) bool { return addr == netip.MustParseAddr("203.0.113.5") }
	control := DialControl(only203)
	if err := control("tcp", "203.0.113.5:443", nil); err != nil {
		t.Fatalf("DialControl(only203) refused the allowed address: %v", err)
	}
	if err := control("tcp", "203.0.113.6:443", nil); err == nil {
		t.Fatal("DialControl(only203) accepted an address the AllowFunc rejects")
	}
}
