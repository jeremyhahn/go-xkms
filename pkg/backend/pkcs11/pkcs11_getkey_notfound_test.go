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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackend_GetKey_NotFound_801 is the go-xkms#801 sentinel-alignment
// check for pkcs11: a genuine absent key must satisfy
// errors.Is(err, backend.ErrKeyNotFound). pkcs11 has no local ErrKeyNotFound
// sentinel of its own -- it returns backend.ErrKeyNotFound directly -- so
// this pins that contract for the package that still uses it.
func TestBackend_GetKey_NotFound_801(t *testing.T) {
	b := newProvisionedBackend(t, "getkey-notfound-801")

	_, err := b.GetKey(context.Background(), ecdsaKeyAttrs("absent-801", elliptic.P256()))
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_GetKey_DeviceFailureNotClassifiedAsNotFound_801 is the
// go-xkms#801 regression check for pkcs11: a device/session failure (here,
// the session pool has failed) must NOT satisfy
// errors.Is(err, backend.ErrKeyNotFound). Collapsing a login or transport
// failure into "not found" would let getOrGenerateCAKey silently replace an
// HSM-backed CA signing key the backend merely failed to reach.
func TestBackend_GetKey_DeviceFailureNotClassifiedAsNotFound_801(t *testing.T) {
	b := newProvisionedBackend(t, "getkey-device-failure-801")

	b.Pool().Close()

	_, err := b.GetKey(context.Background(), ecdsaKeyAttrs("any-801", elliptic.P256()))
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a session pool failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrSessionPoolClosed), "expected errors.Is(err, ErrSessionPoolClosed), got %v", err)
}
