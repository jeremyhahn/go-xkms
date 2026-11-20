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

package xkms

import (
	"reflect"
	"testing"
	"unsafe"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// fakeNodeUsers is a node user source the SDK test can identify.
type fakeNodeUsers struct{ id string }

func (*fakeNodeUsers) UserService() qrdbsdk.UserServicer { return nil }

// nodeUsersOf reads the module's wired node user source (an unexported
// field) so the test asserts the option's effect, not only that it compiles.
func nodeUsersOf(t *testing.T, module any) ServiceModuleNodeUserSource {
	t.Helper()
	field := reflect.ValueOf(module).Elem().FieldByName("nodeUsers")
	require.True(t, field.IsValid(), "module has no nodeUsers field")
	value := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
	if value == nil {
		return nil
	}
	return value.(ServiceModuleNodeUserSource)
}

// TestWithServiceModuleNodeUsers_WiresNodeUserSource proves a host building
// on the SDK can hand the embedded node's user service to the module, so the
// public WebAuthn and invite routes resolve users through it.
func TestWithServiceModuleNodeUsers_WiresNodeUserSource(t *testing.T) {
	fake := &fakeNodeUsers{id: "node"}
	module, err := NewServiceModule(func() *pkgxkms.XKMSService { return nil },
		WithServiceModuleNodeUsers(fake))
	require.NoError(t, err)

	got := nodeUsersOf(t, module)
	require.NotNil(t, got)
	assert.Same(t, fake, got.(*fakeNodeUsers))
}

// TestWithServiceModuleNodeUsers_UnsetLeavesNone is the negative case: a
// module built without the option has no node user source.
func TestWithServiceModuleNodeUsers_UnsetLeavesNone(t *testing.T) {
	module, err := NewServiceModule(func() *pkgxkms.XKMSService { return nil })
	require.NoError(t, err)
	assert.Nil(t, nodeUsersOf(t, module))
}
