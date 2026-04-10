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

package pairing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileSharingPolicyStore_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	// Create an empty file.
	err := os.WriteFile(path, []byte(""), 0600)
	require.NoError(t, err)

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)
	require.NotNil(t, store)

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestNewFileSharingPolicyStore_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)
	require.NotNil(t, store)

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestNewFileSharingPolicyStore_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")

	err := os.WriteFile(path, []byte("{not valid json"), 0600)
	require.NoError(t, err)

	store, err := NewFileSharingPolicyStore(path)
	assert.Error(t, err)
	assert.Nil(t, store)
}

func TestFileSharingPolicyStore_SetAndGetPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	policy := &SharingPolicy{
		KeyID:          "signing-key-001",
		Backend:        "tpm2",
		AllowShare:     true,
		SharePublic:    true,
		SharePrivate:   false,
		ShareSymmetric: false,
		AllowedDevices: []string{"device-fingerprint-abc"},
	}

	err = store.SetPolicy(policy)
	require.NoError(t, err)

	retrieved, err := store.GetPolicy("tpm2", "signing-key-001")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, policy.KeyID, retrieved.KeyID)
	assert.Equal(t, policy.Backend, retrieved.Backend)
	assert.True(t, retrieved.AllowShare)
	assert.True(t, retrieved.SharePublic)
	assert.False(t, retrieved.SharePrivate)
	assert.False(t, retrieved.ShareSymmetric)
	assert.Equal(t, []string{"device-fingerprint-abc"}, retrieved.AllowedDevices)
}

func TestFileSharingPolicyStore_SetPolicy_NilPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.SetPolicy(nil)
	assert.Equal(t, ErrBridgeInvalidParams, err)
}

func TestFileSharingPolicyStore_SetPolicy_EmptyBackend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{KeyID: "k1"})
	assert.Equal(t, ErrBridgeInvalidParams, err)
}

func TestFileSharingPolicyStore_SetPolicy_EmptyKeyID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{Backend: "tpm2"})
	assert.Equal(t, ErrBridgeInvalidParams, err)
}

func TestFileSharingPolicyStore_SetPolicy_UpdateExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// Create initial policy.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:       "key-1",
		Backend:     "software",
		AllowShare:  true,
		SharePublic: true,
	})
	require.NoError(t, err)

	// Update the same policy.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:          "key-1",
		Backend:        "software",
		AllowShare:     true,
		SharePublic:    true,
		ShareSymmetric: true,
	})
	require.NoError(t, err)

	retrieved, err := store.GetPolicy("software", "key-1")
	require.NoError(t, err)
	assert.True(t, retrieved.ShareSymmetric)
}

func TestFileSharingPolicyStore_DeletePolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// Create a policy.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "delete-me",
		Backend:    "software",
		AllowShare: true,
	})
	require.NoError(t, err)

	// Verify it exists.
	_, err = store.GetPolicy("software", "delete-me")
	require.NoError(t, err)

	// Delete it.
	err = store.DeletePolicy("software", "delete-me")
	require.NoError(t, err)

	// Verify it no longer exists.
	_, err = store.GetPolicy("software", "delete-me")
	assert.Equal(t, ErrSharePolicyNotFound, err)
}

func TestFileSharingPolicyStore_DeletePolicy_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.DeletePolicy("software", "nonexistent")
	assert.Equal(t, ErrSharePolicyNotFound, err)
}

func TestFileSharingPolicyStore_ListPolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// Add multiple policies.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "key-1",
		Backend:    "tpm2",
		AllowShare: true,
	})
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "key-2",
		Backend:    "software",
		AllowShare: false,
	})
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "key-3",
		Backend:    "pkcs11",
		AllowShare: true,
	})
	require.NoError(t, err)

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 3)

	// Build a map for order-independent assertion.
	policyMap := make(map[string]*SharingPolicy)
	for _, p := range policies {
		policyMap[policyKey(p.Backend, p.KeyID)] = p
	}

	assert.Contains(t, policyMap, "tpm2:key-1")
	assert.Contains(t, policyMap, "software:key-2")
	assert.Contains(t, policyMap, "pkcs11:key-3")
}

func TestFileSharingPolicyStore_IsShareAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// Policy with allowed devices.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:          "restricted-key",
		Backend:        "tpm2",
		AllowShare:     true,
		SharePublic:    true,
		AllowedDevices: []string{"device-aaa", "device-bbb"},
	})
	require.NoError(t, err)

	t.Run("allowed device", func(t *testing.T) {
		allowed, err := store.IsShareAllowed("tpm2", "restricted-key", "device-aaa")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("another allowed device", func(t *testing.T) {
		allowed, err := store.IsShareAllowed("tpm2", "restricted-key", "device-bbb")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("denied device", func(t *testing.T) {
		allowed, err := store.IsShareAllowed("tpm2", "restricted-key", "device-ccc")
		require.NoError(t, err)
		assert.False(t, allowed)
	})
}

func TestFileSharingPolicyStore_IsShareAllowed_NoDeviceFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// Policy without device filtering -- any device is allowed.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "open-key",
		Backend:    "software",
		AllowShare: true,
	})
	require.NoError(t, err)

	allowed, err := store.IsShareAllowed("software", "open-key", "any-device")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestFileSharingPolicyStore_IsShareAllowed_NotAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// Policy with AllowShare=false.
	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "denied-key",
		Backend:    "software",
		AllowShare: false,
	})
	require.NoError(t, err)

	allowed, err := store.IsShareAllowed("software", "denied-key", "any-device")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestFileSharingPolicyStore_DefaultDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	// No policy set for this key -- default is deny.
	allowed, err := store.IsShareAllowed("tpm2", "unknown-key", "device-aaa")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestFileSharingPolicyStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	// Create store and add policies.
	store1, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store1.SetPolicy(&SharingPolicy{
		KeyID:          "persist-key-1",
		Backend:        "tpm2",
		AllowShare:     true,
		SharePublic:    true,
		SharePrivate:   false,
		ShareSymmetric: true,
		AllowedDevices: []string{"device-x", "device-y"},
	})
	require.NoError(t, err)

	err = store1.SetPolicy(&SharingPolicy{
		KeyID:      "persist-key-2",
		Backend:    "software",
		AllowShare: false,
	})
	require.NoError(t, err)

	// Verify the file was written.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(data), "expected valid JSON in policy file")

	// Create a new store from the same file and verify policies loaded.
	store2, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	policies, err := store2.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	p1, err := store2.GetPolicy("tpm2", "persist-key-1")
	require.NoError(t, err)
	assert.True(t, p1.AllowShare)
	assert.True(t, p1.SharePublic)
	assert.False(t, p1.SharePrivate)
	assert.True(t, p1.ShareSymmetric)
	assert.Equal(t, []string{"device-x", "device-y"}, p1.AllowedDevices)

	p2, err := store2.GetPolicy("software", "persist-key-2")
	require.NoError(t, err)
	assert.False(t, p2.AllowShare)
}

func TestFileSharingPolicyStore_PolicyNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	_, err = store.GetPolicy("nonexistent-backend", "nonexistent-key")
	assert.Equal(t, ErrSharePolicyNotFound, err)
}

func TestFileSharingPolicyStore_GetPolicy_ReturnsCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{
		KeyID:          "copy-test",
		Backend:        "software",
		AllowShare:     true,
		AllowedDevices: []string{"device-a"},
	})
	require.NoError(t, err)

	// Get and mutate the returned policy.
	p1, err := store.GetPolicy("software", "copy-test")
	require.NoError(t, err)
	p1.AllowShare = false
	p1.AllowedDevices = append(p1.AllowedDevices, "device-b")

	// Original should be unchanged.
	p2, err := store.GetPolicy("software", "copy-test")
	require.NoError(t, err)
	assert.True(t, p2.AllowShare)
	assert.Equal(t, []string{"device-a"}, p2.AllowedDevices)
}

func TestFileSharingPolicyStore_SetPolicy_StoresCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	devices := []string{"device-a"}
	policy := &SharingPolicy{
		KeyID:          "copy-test-set",
		Backend:        "software",
		AllowShare:     true,
		AllowedDevices: devices,
	}

	err = store.SetPolicy(policy)
	require.NoError(t, err)

	// Mutate the original slice after setting.
	devices[0] = "mutated"
	policy.AllowedDevices = devices

	// Stored policy should be unchanged.
	retrieved, err := store.GetPolicy("software", "copy-test-set")
	require.NoError(t, err)
	assert.Equal(t, []string{"device-a"}, retrieved.AllowedDevices)
}

func TestFileSharingPolicyStore_ListPolicies_ReturnsCopies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{
		KeyID:          "list-copy-test",
		Backend:        "software",
		AllowShare:     true,
		AllowedDevices: []string{"device-a"},
	})
	require.NoError(t, err)

	policies, err := store.ListPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)

	// Mutate returned list entry.
	policies[0].AllowShare = false

	// Original should be unchanged.
	retrieved, err := store.GetPolicy("software", "list-copy-test")
	require.NoError(t, err)
	assert.True(t, retrieved.AllowShare)
}

func TestFileSharingPolicyStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	store, err := NewFileSharingPolicyStore(path)
	require.NoError(t, err)

	err = store.SetPolicy(&SharingPolicy{
		KeyID:      "perm-test",
		Backend:    "software",
		AllowShare: true,
	})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)

	// Verify file is created with 0600 permissions.
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// --- SharingPolicy JSON tests ---

func TestSharingPolicy_JSONRoundTrip(t *testing.T) {
	original := &SharingPolicy{
		KeyID:          "test-key",
		Backend:        "tpm2",
		AllowShare:     true,
		SharePublic:    true,
		SharePrivate:   false,
		ShareSymmetric: true,
		AllowedDevices: []string{"device-1", "device-2"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SharingPolicy
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Backend, decoded.Backend)
	assert.Equal(t, original.AllowShare, decoded.AllowShare)
	assert.Equal(t, original.SharePublic, decoded.SharePublic)
	assert.Equal(t, original.SharePrivate, decoded.SharePrivate)
	assert.Equal(t, original.ShareSymmetric, decoded.ShareSymmetric)
	assert.Equal(t, original.AllowedDevices, decoded.AllowedDevices)
}

func TestSharingPolicy_JSONFieldNames(t *testing.T) {
	policy := SharingPolicy{
		KeyID:          "k1",
		Backend:        "sw",
		AllowShare:     true,
		SharePublic:    true,
		SharePrivate:   false,
		ShareSymmetric: false,
		AllowedDevices: []string{"d1"},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"key_id", "backend", "allow_share", "share_public",
		"share_private", "share_symmetric", "allowed_devices",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestSharingPolicy_OmitEmptyAllowedDevices(t *testing.T) {
	policy := SharingPolicy{
		KeyID:      "k1",
		Backend:    "sw",
		AllowShare: true,
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "allowed_devices")
}

func TestNewFileSharingPolicyStore_ReadError(t *testing.T) {
	// Use a directory path -- os.ReadFile on a directory returns an error
	// that is not os.IsNotExist, covering line 65.
	_, err := NewFileSharingPolicyStore(t.TempDir())
	require.Error(t, err)
}
