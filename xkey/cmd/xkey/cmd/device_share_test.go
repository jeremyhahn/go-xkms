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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// --- Command structure tests ---

func TestPhoneShareCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceShareCmd)
	assert.Equal(t, "share <backend> <key-id>", deviceShareCmd.Use)
	assert.NotEmpty(t, deviceShareCmd.Short)
	assert.NotEmpty(t, deviceShareCmd.Long)
	assert.NotNil(t, deviceShareCmd.RunE)
}

func TestPhoneShareCmd_Args(t *testing.T) {
	// ExactArgs(2) should be set
	err := deviceShareCmd.Args(deviceShareCmd, []string{"software"})
	assert.Error(t, err, "share should require exactly 2 args")

	err = deviceShareCmd.Args(deviceShareCmd, []string{"software", "my-key"})
	assert.NoError(t, err, "share should accept exactly 2 args")

	err = deviceShareCmd.Args(deviceShareCmd, []string{"software", "my-key", "extra"})
	assert.Error(t, err, "share should reject more than 2 args")
}

func TestPhoneShareCmd_Flags(t *testing.T) {
	flags := []string{"device", "label", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceShareCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on share command", name)
		})
	}
}

func TestPhoneShareCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := deviceShareCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("label_default_empty", func(t *testing.T) {
		flag := deviceShareCmd.Flags().Lookup("label")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := deviceShareCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

func TestPhoneImportCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceImportCmd)
	assert.Equal(t, "import <key-id>", deviceImportCmd.Use)
	assert.NotEmpty(t, deviceImportCmd.Short)
	assert.NotEmpty(t, deviceImportCmd.Long)
	assert.NotNil(t, deviceImportCmd.RunE)
}

func TestPhoneImportCmd_Args(t *testing.T) {
	err := deviceImportCmd.Args(deviceImportCmd, []string{})
	assert.Error(t, err, "import should require exactly 1 arg")

	err = deviceImportCmd.Args(deviceImportCmd, []string{"my-key"})
	assert.NoError(t, err, "import should accept exactly 1 arg")

	err = deviceImportCmd.Args(deviceImportCmd, []string{"key1", "key2"})
	assert.Error(t, err, "import should reject more than 1 arg")
}

func TestPhoneImportCmd_Flags(t *testing.T) {
	flags := []string{"backend", "device", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceImportCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on import command", name)
		})
	}
}

func TestPhoneImportCmd_FlagDefaults(t *testing.T) {
	t.Run("backend_default_software", func(t *testing.T) {
		flag := deviceImportCmd.Flags().Lookup("backend")
		require.NotNil(t, flag)
		assert.Equal(t, "software", flag.DefValue)
	})

	t.Run("device_default_empty", func(t *testing.T) {
		flag := deviceImportCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})
}

// --- Share policy command structure tests ---

func TestPhoneSharePolicyCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSharePolicyCmd)
	assert.Equal(t, "share-policy", deviceSharePolicyCmd.Use)
	assert.NotEmpty(t, deviceSharePolicyCmd.Short)
	assert.NotEmpty(t, deviceSharePolicyCmd.Long)
}

func TestPhoneSharePolicyListCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSharePolicyListCmd)
	assert.Equal(t, "list", deviceSharePolicyListCmd.Use)
	assert.NotEmpty(t, deviceSharePolicyListCmd.Short)
	assert.NotNil(t, deviceSharePolicyListCmd.RunE)
}

func TestPhoneSharePolicySetCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSharePolicySetCmd)
	assert.Equal(t, "set <backend> <key-id>", deviceSharePolicySetCmd.Use)
	assert.NotEmpty(t, deviceSharePolicySetCmd.Short)
	assert.NotEmpty(t, deviceSharePolicySetCmd.Long)
	assert.NotNil(t, deviceSharePolicySetCmd.RunE)
}

func TestPhoneSharePolicySetCmd_Args(t *testing.T) {
	err := deviceSharePolicySetCmd.Args(deviceSharePolicySetCmd, []string{"software"})
	assert.Error(t, err, "set should require exactly 2 args")

	err = deviceSharePolicySetCmd.Args(deviceSharePolicySetCmd, []string{"software", "my-key"})
	assert.NoError(t, err, "set should accept exactly 2 args")
}

func TestPhoneSharePolicySetCmd_Flags(t *testing.T) {
	flags := []string{"allow", "share-public", "share-symmetric", "share-private", "devices"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceSharePolicySetCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on share-policy set command", name)
		})
	}
}

func TestPhoneSharePolicySetCmd_FlagDefaults(t *testing.T) {
	t.Run("allow_default_false", func(t *testing.T) {
		flag := deviceSharePolicySetCmd.Flags().Lookup("allow")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("share_public_default_true", func(t *testing.T) {
		flag := deviceSharePolicySetCmd.Flags().Lookup("share-public")
		require.NotNil(t, flag)
		assert.Equal(t, "true", flag.DefValue)
	})

	t.Run("share_symmetric_default_false", func(t *testing.T) {
		flag := deviceSharePolicySetCmd.Flags().Lookup("share-symmetric")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("share_private_default_false", func(t *testing.T) {
		flag := deviceSharePolicySetCmd.Flags().Lookup("share-private")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("devices_default_empty", func(t *testing.T) {
		flag := deviceSharePolicySetCmd.Flags().Lookup("devices")
		require.NotNil(t, flag)
		assert.Equal(t, "[]", flag.DefValue)
	})
}

func TestPhoneSharePolicyRemoveCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSharePolicyRemoveCmd)
	assert.Equal(t, "remove <backend> <key-id>", deviceSharePolicyRemoveCmd.Use)
	assert.NotEmpty(t, deviceSharePolicyRemoveCmd.Short)
	assert.NotNil(t, deviceSharePolicyRemoveCmd.RunE)
}

func TestPhoneSharePolicyRemoveCmd_Args(t *testing.T) {
	err := deviceSharePolicyRemoveCmd.Args(deviceSharePolicyRemoveCmd, []string{"software"})
	assert.Error(t, err, "remove should require exactly 2 args")

	err = deviceSharePolicyRemoveCmd.Args(deviceSharePolicyRemoveCmd, []string{"software", "my-key"})
	assert.NoError(t, err, "remove should accept exactly 2 args")
}

// --- Share policy command execution tests ---

func TestSharePolicyList_Empty(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Create the .xkey directory
	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	var buf bytes.Buffer
	deviceSharePolicyListCmd.SetOut(&buf)

	err = runSharePolicyList(deviceSharePolicyListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No sharing policies configured")
}

func TestSharePolicySet_AndList(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Create the .xkey directory and phone.yaml so getDevicesConfigPath works
	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	// Set policy via direct store (bypassing command flag parsing)
	policyPath := filepath.Join(xkeyDir, sharingPoliciesFileName)
	store, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)

	policy := &phone.SharingPolicy{
		KeyID:          "test-key",
		Backend:        "software",
		AllowShare:     true,
		SharePublic:    true,
		ShareSymmetric: false,
		SharePrivate:   false,
	}
	err = store.SetPolicy(policy)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(policyPath)
	require.NoError(t, err)

	// List policies
	var buf bytes.Buffer
	deviceSharePolicyListCmd.SetOut(&buf)

	err = runSharePolicyList(deviceSharePolicyListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Sharing Policies (1)")
	assert.Contains(t, output, "software")
	assert.Contains(t, output, "test-key")
}

func TestSharePolicyRemove_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	var buf bytes.Buffer
	deviceSharePolicyRemoveCmd.SetOut(&buf)

	err = runSharePolicyRemove(deviceSharePolicyRemoveCmd, []string{"software", "nonexistent"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSharePolicyRemoveFailed)
}

func TestSharePolicySet_AndRemove(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	// Set a policy via the store
	policyPath := filepath.Join(xkeyDir, sharingPoliciesFileName)
	store, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)

	err = store.SetPolicy(&phone.SharingPolicy{
		KeyID:      "removal-key",
		Backend:    "tpm2",
		AllowShare: true,
	})
	require.NoError(t, err)

	// Verify the policy exists
	p, err := store.GetPolicy("tpm2", "removal-key")
	require.NoError(t, err)
	assert.True(t, p.AllowShare)

	// Remove via command handler
	var buf bytes.Buffer
	deviceSharePolicyRemoveCmd.SetOut(&buf)

	err = runSharePolicyRemove(deviceSharePolicyRemoveCmd, []string{"tpm2", "removal-key"})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Sharing policy removed for tpm2/removal-key")

	// Verify removal persisted
	store2, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)
	_, err = store2.GetPolicy("tpm2", "removal-key")
	assert.ErrorIs(t, err, phone.ErrSharePolicyNotFound)
}

// --- Share policy store persistence tests ---

func TestSharePolicyStore_Persistence(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policies.json")

	// Create store and add policies
	store1, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)

	err = store1.SetPolicy(&phone.SharingPolicy{
		KeyID:          "key-a",
		Backend:        "software",
		AllowShare:     true,
		SharePublic:    true,
		ShareSymmetric: true,
		AllowedDevices: []string{"fp-1", "fp-2"},
	})
	require.NoError(t, err)

	err = store1.SetPolicy(&phone.SharingPolicy{
		KeyID:      "key-b",
		Backend:    "tpm2",
		AllowShare: false,
	})
	require.NoError(t, err)

	// Load from new store instance to verify persistence
	store2, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)

	policies, err := store2.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	policyA, err := store2.GetPolicy("software", "key-a")
	require.NoError(t, err)
	assert.True(t, policyA.AllowShare)
	assert.True(t, policyA.SharePublic)
	assert.True(t, policyA.ShareSymmetric)
	assert.Equal(t, []string{"fp-1", "fp-2"}, policyA.AllowedDevices)

	policyB, err := store2.GetPolicy("tpm2", "key-b")
	require.NoError(t, err)
	assert.False(t, policyB.AllowShare)
}

func TestSharePolicyStore_IsShareAllowed(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policies.json")

	store, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)

	// No policy => denied
	allowed, err := store.IsShareAllowed("software", "no-policy", "any-fp")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Policy with AllowShare=false => denied
	err = store.SetPolicy(&phone.SharingPolicy{
		KeyID:      "denied-key",
		Backend:    "software",
		AllowShare: false,
	})
	require.NoError(t, err)
	allowed, err = store.IsShareAllowed("software", "denied-key", "any-fp")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Policy with AllowShare=true, no device filter => allowed for any device
	err = store.SetPolicy(&phone.SharingPolicy{
		KeyID:      "open-key",
		Backend:    "software",
		AllowShare: true,
	})
	require.NoError(t, err)
	allowed, err = store.IsShareAllowed("software", "open-key", "any-fp")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Policy with device filter => only specific devices allowed
	err = store.SetPolicy(&phone.SharingPolicy{
		KeyID:          "restricted-key",
		Backend:        "software",
		AllowShare:     true,
		AllowedDevices: []string{"trusted-fp"},
	})
	require.NoError(t, err)

	allowed, err = store.IsShareAllowed("software", "restricted-key", "trusted-fp")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = store.IsShareAllowed("software", "restricted-key", "untrusted-fp")
	require.NoError(t, err)
	assert.False(t, allowed)
}

// --- Error tests ---

func TestPhoneShareErrors(t *testing.T) {
	shareErrors := []struct {
		err      error
		contains string
	}{
		{ErrSharePolicyDenied, "device: sharing denied by policy"},
		{ErrShareConnectFailed, "device: share connection failed"},
		{ErrShareRequestFailed, "device: share request failed"},
		{ErrShareImportFailed, "device: share import failed"},
		{ErrSharePolicyStoreFailed, "device: sharing policy store failed"},
		{ErrSharePolicyLoadFailed, "device: failed to load sharing policy store"},
		{ErrSharePolicySetFailed, "device: failed to set sharing policy"},
		{ErrSharePolicyRemoveFailed, "device: failed to remove sharing policy"},
	}

	for _, tc := range shareErrors {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.Contains(t, tc.err.Error(), "device:")
		})
	}
}

func TestPhoneShareErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrSharePolicyDenied,
		ErrShareConnectFailed,
		ErrShareRequestFailed,
		ErrShareImportFailed,
		ErrSharePolicyStoreFailed,
		ErrSharePolicyLoadFailed,
		ErrSharePolicySetFailed,
		ErrSharePolicyRemoveFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- Helper function tests ---

func TestGetSharePolicyPath(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	path, err := getSharePolicyPath()
	require.NoError(t, err)

	expected := filepath.Join(tempDir, ".xkey", sharingPoliciesFileName)
	assert.Equal(t, expected, path)
}

func TestTruncatePolicyKeyID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short_key", "my-key", "my-key"},
		{"exactly_20", "12345678901234567890", "12345678901234567890"},
		{"long_key", "this-is-a-very-long-key-id-value", "this-is-a-very-lo..."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := truncatePolicyKeyID(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSharePolicyList_MultiplePolicies(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	xkeyDir := filepath.Join(tempDir, ".xkey")
	err := os.MkdirAll(xkeyDir, 0700)
	require.NoError(t, err)

	policyPath := filepath.Join(xkeyDir, sharingPoliciesFileName)
	store, err := phone.NewFileSharingPolicyStore(policyPath)
	require.NoError(t, err)

	// Add multiple policies
	for _, p := range []*phone.SharingPolicy{
		{KeyID: "key-1", Backend: "software", AllowShare: true, SharePublic: true},
		{KeyID: "key-2", Backend: "tpm2", AllowShare: true, ShareSymmetric: true},
		{KeyID: "key-3", Backend: "software", AllowShare: false},
	} {
		err = store.SetPolicy(p)
		require.NoError(t, err)
	}

	var buf bytes.Buffer
	deviceSharePolicyListCmd.SetOut(&buf)

	err = runSharePolicyList(deviceSharePolicyListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Sharing Policies (3)")
	assert.Contains(t, output, "BACKEND")
	assert.Contains(t, output, "KEY ID")
	assert.Contains(t, output, "ALLOW")
}
