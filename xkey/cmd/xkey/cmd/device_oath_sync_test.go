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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// --- OATH sync command structure tests ---

func TestOATHSyncPhoneCmd_Structure(t *testing.T) {
	assert.NotNil(t, oathSyncPhoneCmd)
	assert.Equal(t, "sync", oathSyncPhoneCmd.Use)
	assert.NotEmpty(t, oathSyncPhoneCmd.Short)
	assert.NotEmpty(t, oathSyncPhoneCmd.Long)
	assert.NotNil(t, oathSyncPhoneCmd.RunE)
}

func TestOATHSyncPhoneCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout", "store"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := oathSyncPhoneCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on sync command", name)
		})
	}
}

func TestOATHSyncPhoneCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := oathSyncPhoneCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := oathSyncPhoneCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})

	t.Run("store_default", func(t *testing.T) {
		flag := oathSyncPhoneCmd.Flags().Lookup("store")
		require.NotNil(t, flag)
		assert.Equal(t, defaultOATHStorePath, flag.DefValue)
	})
}

// --- OATH push command structure tests ---

func TestOATHPushPhoneCmd_Structure(t *testing.T) {
	assert.NotNil(t, oathPushPhoneCmd)
	assert.Equal(t, "push <name-or-id>", oathPushPhoneCmd.Use)
	assert.NotEmpty(t, oathPushPhoneCmd.Short)
	assert.NotEmpty(t, oathPushPhoneCmd.Long)
	assert.NotNil(t, oathPushPhoneCmd.RunE)
}

func TestOATHPushPhoneCmd_Args(t *testing.T) {
	err := oathPushPhoneCmd.Args(oathPushPhoneCmd, []string{})
	assert.Error(t, err, "push should require exactly 1 arg")

	err = oathPushPhoneCmd.Args(oathPushPhoneCmd, []string{"GitHub"})
	assert.NoError(t, err, "push should accept exactly 1 arg")

	err = oathPushPhoneCmd.Args(oathPushPhoneCmd, []string{"GitHub", "extra"})
	assert.Error(t, err, "push should reject more than 1 arg")
}

func TestOATHPushPhoneCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout", "store"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := oathPushPhoneCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on push command", name)
		})
	}
}

func TestOATHPushPhoneCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := oathPushPhoneCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := oathPushPhoneCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- OATH pull command structure tests ---

func TestOATHPullPhoneCmd_Structure(t *testing.T) {
	assert.NotNil(t, oathPullPhoneCmd)
	assert.Equal(t, "pull", oathPullPhoneCmd.Use)
	assert.NotEmpty(t, oathPullPhoneCmd.Short)
	assert.NotEmpty(t, oathPullPhoneCmd.Long)
	assert.NotNil(t, oathPullPhoneCmd.RunE)
}

func TestOATHPullPhoneCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout", "store"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := oathPullPhoneCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on pull command", name)
		})
	}
}

func TestOATHPullPhoneCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := oathPullPhoneCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := oathPullPhoneCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- Command hierarchy tests ---

func TestOATHCmd_PhoneSyncSubcommands(t *testing.T) {
	subcommands := OATHCmd.Commands()

	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["sync"], "oath should have sync subcommand")
	assert.True(t, names["push"], "oath should have push subcommand")
	assert.True(t, names["pull"], "oath should have pull subcommand")
}

// --- OATH phone sync error tests ---

func TestOATHPhoneSyncErrors(t *testing.T) {
	syncErrors := []struct {
		err      error
		contains string
	}{
		{ErrOATHSyncFailed, "oath: phone sync failed"},
		{ErrOATHPushFailed, "oath: push to phone failed"},
		{ErrOATHPullFailed, "oath: pull from phone failed"},
	}

	for _, tc := range syncErrors {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.Contains(t, tc.err.Error(), "oath:")
		})
	}
}

func TestOATHPhoneSyncErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrOATHSyncFailed,
		ErrOATHPushFailed,
		ErrOATHPullFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- Credential conversion tests ---

func TestCredentialToPhoneInfo(t *testing.T) {
	cred := &oath.Credential{
		ID:          "github:user@example.com",
		Name:        "GitHub",
		Issuer:      "GitHub",
		AccountName: "user@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        oath.TypeTOTP,
		Algorithm:   oath.AlgorithmSHA1,
		Digits:      6,
		Period:      30,
		Counter:     0,
		CreatedAt:   time.Now(),
	}

	info := credentialToPhoneInfo(cred)

	assert.Equal(t, cred.Name, info.Name)
	assert.Equal(t, cred.Issuer, info.Issuer)
	assert.Equal(t, cred.AccountName, info.AccountName)
	assert.Equal(t, cred.Secret, info.Secret)
	assert.Equal(t, cred.Type, info.Type)
	assert.Equal(t, cred.Algorithm, info.Algorithm)
	assert.Equal(t, cred.Digits, info.Digits)
	assert.Equal(t, cred.Period, info.Period)
	assert.Equal(t, cred.Counter, info.Counter)
}

func TestCredentialToPhoneInfo_HOTP(t *testing.T) {
	cred := &oath.Credential{
		ID:      "myservice",
		Name:    "MyService",
		Secret:  "JBSWY3DPEHPK3PXP",
		Type:    oath.TypeHOTP,
		Digits:  8,
		Counter: 42,
	}

	info := credentialToPhoneInfo(cred)

	assert.Equal(t, oath.TypeHOTP, info.Type)
	assert.Equal(t, 8, info.Digits)
	assert.Equal(t, uint64(42), info.Counter)
}

func TestPhoneInfoToCredential(t *testing.T) {
	info := phone.OATHCredentialInfo{
		Name:        "AWS",
		Issuer:      "Amazon",
		AccountName: "admin@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        "totp",
		Algorithm:   "SHA256",
		Digits:      8,
		Period:      60,
	}

	cred := deviceInfoToCredential(info)

	assert.Equal(t, "amazon:admin@example.com", cred.ID)
	assert.Equal(t, info.Name, cred.Name)
	assert.Equal(t, info.Issuer, cred.Issuer)
	assert.Equal(t, info.AccountName, cred.AccountName)
	assert.Equal(t, info.Secret, cred.Secret)
	assert.Equal(t, info.Type, cred.Type)
	assert.Equal(t, info.Algorithm, cred.Algorithm)
	assert.Equal(t, info.Digits, cred.Digits)
	assert.Equal(t, info.Period, cred.Period)
	assert.False(t, cred.CreatedAt.IsZero())
}

func TestPhoneInfoToCredential_Defaults(t *testing.T) {
	info := phone.OATHCredentialInfo{
		Name:   "Simple",
		Secret: "JBSWY3DPEHPK3PXP",
	}

	cred := deviceInfoToCredential(info)

	assert.Equal(t, "simple", cred.ID)
	assert.Equal(t, "Simple", cred.Name)
	assert.Equal(t, oath.DefaultAlgorithm, cred.Algorithm)
	assert.Equal(t, oath.DefaultDigits, cred.Digits)
	assert.Equal(t, oath.DefaultPeriod, cred.Period)
	assert.Equal(t, oath.TypeTOTP, cred.Type)
}

func TestPhoneInfoToCredential_EmptyNameWithIssuer(t *testing.T) {
	info := phone.OATHCredentialInfo{
		Issuer: "TestIssuer",
		Secret: "JBSWY3DPEHPK3PXP",
	}

	cred := deviceInfoToCredential(info)

	assert.Equal(t, "TestIssuer", cred.Name)
	assert.Equal(t, "testissuer", cred.ID)
}

func TestPhoneInfoToCredential_WithIssuerAndAccount(t *testing.T) {
	info := phone.OATHCredentialInfo{
		Name:        "GitHub",
		Issuer:      "GitHub",
		AccountName: "user@test.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        "totp",
	}

	cred := deviceInfoToCredential(info)

	assert.Equal(t, "github:user@test.com", cred.ID)
	assert.Equal(t, "GitHub", cred.Name)
}

func TestPhoneInfoToCredential_HOTP(t *testing.T) {
	info := phone.OATHCredentialInfo{
		Name:    "HotpService",
		Secret:  "JBSWY3DPEHPK3PXP",
		Type:    "hotp",
		Counter: 100,
	}

	cred := deviceInfoToCredential(info)

	assert.Equal(t, oath.TypeHOTP, cred.Type)
	assert.Equal(t, uint64(100), cred.Counter)
}

// --- Roundtrip conversion test ---

func TestCredentialConversion_Roundtrip(t *testing.T) {
	original := &oath.Credential{
		ID:          "test:user@example.com",
		Name:        "TestService",
		Issuer:      "Test",
		AccountName: "user@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        oath.TypeTOTP,
		Algorithm:   oath.AlgorithmSHA256,
		Digits:      8,
		Period:      60,
		Counter:     0,
		CreatedAt:   time.Now(),
	}

	// Convert to phone info and back
	info := credentialToPhoneInfo(original)
	roundtrip := deviceInfoToCredential(info)

	assert.Equal(t, original.Name, roundtrip.Name)
	assert.Equal(t, original.Issuer, roundtrip.Issuer)
	assert.Equal(t, original.AccountName, roundtrip.AccountName)
	assert.Equal(t, original.Secret, roundtrip.Secret)
	assert.Equal(t, original.Type, roundtrip.Type)
	assert.Equal(t, original.Algorithm, roundtrip.Algorithm)
	assert.Equal(t, original.Digits, roundtrip.Digits)
	assert.Equal(t, original.Period, roundtrip.Period)
}
