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

// Package transport_test lives outside package transport specifically so it
// can import every concrete transport implementation (each of which imports
// pkg/api/transport) without an import cycle, while still proving facts
// about pkg/api/transport's own exported interfaces.
package transport_test

import (
	"reflect"
	"testing"

	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/embedded"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/grpc"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/unix"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/usb"
)

// The embedded transport is the sole implementation of EscrowServicer
// (go-xkms#692): external key escrow's RBAC model is undecided, so it was
// split out of XKMSServicer/Client into its own interface that only the
// embedded transport composes in (embedded.XKMSServicer). These are genuine
// compile-time assertions: the file fails to build if embedded.Transport
// ever loses an Escrow method.
var (
	_ pkgtransport.EscrowServicer = (*embedded.Transport)(nil)
	_ pkgtransport.EscrowService  = (*embedded.Transport)(nil)
)

// escrowServicerType is the reflect.Type of pkgtransport.EscrowServicer,
// used to check "does NOT implement" below. Go has no way to spell that
// negative as a compile-time assertion (there is no "var _ ifc = (*T)(nil)"
// that succeeds when T does NOT satisfy ifc), so the negative case is
// necessarily a runtime reflection check instead.
var escrowServicerType = reflect.TypeOf((*pkgtransport.EscrowServicer)(nil)).Elem()

// TestNetworkTransportsDoNotImplementEscrowServicer proves every network
// transport (rest, grpc, quic, unix, mcp, usb) lost its Escrow stub methods
// when EscrowServicer was split out of XKMSServicer/Client: none of them
// implements the four-method escrow surface any more, so a caller cannot
// silently reach escrow through a value typed as transport.Client on any of
// these transports. Regressing a stub back onto any of them — the exact
// failure mode go-xkms#692 fixed — would flip this test to fail.
func TestNetworkTransportsDoNotImplementEscrowServicer(t *testing.T) {
	transports := []struct {
		name string
		typ  reflect.Type
	}{
		{"rest", reflect.TypeOf((*rest.Transport)(nil))},
		{"grpc", reflect.TypeOf((*grpc.Transport)(nil))},
		{"quic", reflect.TypeOf((*quic.Transport)(nil))},
		{"unix", reflect.TypeOf((*unix.Transport)(nil))},
		{"mcp", reflect.TypeOf((*mcp.Transport)(nil))},
		{"usb", reflect.TypeOf((*usb.Transport)(nil))},
	}

	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			if tr.typ.Implements(escrowServicerType) {
				t.Errorf("%s.Transport still implements transport.EscrowServicer; "+
					"escrow must stay embedded-only (go-xkms#692)", tr.name)
			}
		})
	}
}

// TestEmbeddedTransportImplementsEscrowServicer is the positive counterpart
// to TestNetworkTransportsDoNotImplementEscrowServicer, spelled the same way
// (reflection, not the package-level var assertions above) so the two tests
// read as one proof about where the boundary actually sits.
func TestEmbeddedTransportImplementsEscrowServicer(t *testing.T) {
	typ := reflect.TypeOf((*embedded.Transport)(nil))
	if !typ.Implements(escrowServicerType) {
		t.Fatal("embedded.Transport no longer implements transport.EscrowServicer")
	}
}

// TestXKMSServicerAndClientExcludeEscrow proves the two umbrella interfaces
// (XKMSServicer for the embedded transport's own service dependency, Client
// for every transport's SDK-facing surface) no longer require the four
// escrow methods: a minimal type implementing only the pared-down method
// sets still satisfies both, which it could not if EscrowServicer/
// EscrowService were still embedded.
func TestXKMSServicerAndClientExcludeEscrow(t *testing.T) {
	escrowMethods := []string{"EscrowKey", "RecoverKey", "ListEscrowed", "RevokeEscrow"}

	xkmsServicerType := reflect.TypeOf((*pkgtransport.XKMSServicer)(nil)).Elem()
	for _, name := range escrowMethods {
		if _, ok := xkmsServicerType.MethodByName(name); ok {
			t.Errorf("transport.XKMSServicer still declares %s; escrow must be split out (go-xkms#692)", name)
		}
	}

	clientType := reflect.TypeOf((*pkgtransport.Client)(nil)).Elem()
	for _, name := range escrowMethods {
		if _, ok := clientType.MethodByName(name); ok {
			t.Errorf("transport.Client still declares %s; escrow must be split out (go-xkms#692)", name)
		}
	}

	// embedded.XKMSServicer is the one place escrow is still required.
	embeddedServicerType := reflect.TypeOf((*embedded.XKMSServicer)(nil)).Elem()
	for _, name := range escrowMethods {
		if _, ok := embeddedServicerType.MethodByName(name); !ok {
			t.Errorf("embedded.XKMSServicer is missing %s; the embedded transport must still require escrow from its service", name)
		}
	}
}
