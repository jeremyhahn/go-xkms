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

package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	qrdbv1 "github.com/jeremyhahn/go-qrdb/pkg/api/grpc/proto/qrdbv1"
)

// keystoreServiceFullName is the proto full name of the service whose method
// options carry the unified server's permission annotations.
const keystoreServiceFullName = "xkms.v1.KeystoreService"

// goldenProtoPermissions expands the golden gate table onto proto RPC names.
// The table keys gates by the method that HOLDS the authorize call, and
// setUserEnabled is the shared helper gating both the EnableUser and
// DisableUser RPCs — so that one key fans out to two annotated RPCs. Every
// other key is the RPC name itself.
func goldenProtoPermissions(t *testing.T) map[string]string {
	t.Helper()
	expanded := make(map[string]string, len(goldenRPCPermissions)+1)
	for method, perm := range goldenRPCPermissions {
		if method == "setUserEnabled" {
			expanded["EnableUser"] = perm
			expanded["DisableUser"] = perm
			continue
		}
		expanded[method] = perm
	}
	require.Len(t, expanded, len(goldenRPCPermissions)+1,
		"setUserEnabled must expand onto exactly EnableUser and DisableUser")
	return expanded
}

// keystoreMethodDescriptors returns every RPC method descriptor of the
// KeystoreService via the protobuf registry — the same reflection path the
// unified server's authorization interceptor resolves permissions through.
func keystoreMethodDescriptors(t *testing.T) protoreflect.MethodDescriptors {
	t.Helper()
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(keystoreServiceFullName)
	require.NoError(t, err, "KeystoreService must be resolvable via protoregistry")
	svc, ok := desc.(protoreflect.ServiceDescriptor)
	require.True(t, ok, "%s must be a service descriptor", keystoreServiceFullName)
	return svc.Methods()
}

// methodPermissionOption reads the qrdb.v1.permission method option, returning
// ("", false) when the RPC is unannotated.
func methodPermissionOption(t *testing.T, m protoreflect.MethodDescriptor) (string, bool) {
	t.Helper()
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil {
		return "", false
	}
	if !proto.HasExtension(opts, qrdbv1.E_Permission) {
		return "", false
	}
	perm, ok := proto.GetExtension(opts, qrdbv1.E_Permission).(string)
	require.True(t, ok, "method %s: qrdb.v1.permission must be a string option", m.Name())
	return perm, true
}

// TestRPCPermissions_ProtoOptionMatchesGoldenTable locks the proto
// option (qrdb.v1.permission) annotations to the golden in-handler gate table,
// in both directions:
//
//   - every golden gate's RPC carries the option with the SAME
//     resource:action value (the unified server's reflection interceptor
//     enforces exactly what the legacy in-handler gate enforces), and
//   - every annotated RPC has a golden entry (an annotation cannot appear or
//     drift without the wire contract recording it).
//
// This is the descriptor-side counterpart of
// TestRPCPermissions_MatchWireContract: that test pins the in-handler gates to
// the golden table; this one pins the proto annotations to the same table, so
// the two enforcement paths cannot diverge. On mismatch the failure names the
// method.
func TestRPCPermissions_ProtoOptionMatchesGoldenTable(t *testing.T) {
	golden := goldenProtoPermissions(t)
	methods := keystoreMethodDescriptors(t)

	annotated := make(map[string]string, methods.Len())
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if perm, ok := methodPermissionOption(t, m); ok {
			annotated[string(m.Name())] = perm
		}
	}

	require.Len(t, annotated, len(golden),
		"annotated RPC count must match the golden gate table (an option was added or removed without updating the wire contract)")

	for method, want := range golden {
		got, ok := annotated[method]
		require.True(t, ok, "method %q has a golden gate but no option (qrdb.v1.permission) annotation", method)
		assert.Equal(t, want, got, "method %q: proto option diverges from the golden gate", method)
	}

	for method, got := range annotated {
		want, ok := golden[method]
		require.True(t, ok, "method %q carries option (qrdb.v1.permission) = %q without a golden gate entry", method, got)
		assert.Equal(t, want, got, "method %q", method)
	}
}

// TestRPCPermissions_UnannotatedRPCsAreTheUngatedOnes pins the complement: the
// RPCs WITHOUT the proto option are exactly the RPCs without an in-handler
// authorization gate. On the unified server an unannotated RPC is DEFAULT-DENY
// until deliberately annotated, so this list is the explicit register of that
// exposure — an RPC cannot silently join it.
func TestRPCPermissions_UnannotatedRPCsAreTheUngatedOnes(t *testing.T) {
	// The ungated surface: health/discovery, secure-ECDH session RPCs, and
	// the WebAuthn ceremony (which authenticates by ceremony, not by RBAC
	// permission). The key-version RPCs left it when they were implemented.
	wantUnannotated := map[string]struct{}{
		"Health":                {},
		"Algorithms":            {},
		"DeriveKeyECDHSecure":   {},
		"GenerateEphemeralECDH": {},
		"UseResidentKey":        {},
		"DestroyResidentKey":    {},
		"BeginRegistration":     {},
		"FinishRegistration":    {},
		"BeginAuthentication":   {},
		"FinishAuthentication":  {},
	}

	methods := keystoreMethodDescriptors(t)
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		_, hasOption := methodPermissionOption(t, m)
		_, expectedUngated := wantUnannotated[name]
		if expectedUngated {
			assert.False(t, hasOption,
				"method %q is registered as ungated but carries option (qrdb.v1.permission); update the register", name)
		} else {
			assert.True(t, hasOption,
				"method %q lost its option (qrdb.v1.permission) annotation (it would be DEFAULT-DENY on the unified server)", name)
		}
	}
}
