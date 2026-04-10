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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- deviceSyncCmd structure tests ---

func TestPhoneSyncCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSyncCmd)
	assert.Equal(t, "sync", deviceSyncCmd.Use)
	assert.NotEmpty(t, deviceSyncCmd.Short)
	assert.NotEmpty(t, deviceSyncCmd.Long)
	assert.NotNil(t, deviceSyncCmd.RunE)
}

func TestPhoneSyncCmd_Flags(t *testing.T) {
	flags := []string{"trust-store", "oath", "passwords", "all", "device", "dry-run", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceSyncCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on sync command", name)
		})
	}
}

func TestPhoneSyncCmd_FlagDefaults(t *testing.T) {
	t.Run("trust_store_default_false", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("trust-store")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("oath_default_false", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("oath")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("passwords_default_false", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("passwords")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("all_default_true", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("all")
		require.NotNil(t, flag)
		assert.Equal(t, "true", flag.DefValue)
	})

	t.Run("device_default_empty", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("dry_run_default_false", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("dry-run")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := deviceSyncCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- deviceSyncStatusCmd structure tests ---

func TestPhoneSyncStatusCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSyncStatusCmd)
	assert.Equal(t, "sync-status", deviceSyncStatusCmd.Use)
	assert.NotEmpty(t, deviceSyncStatusCmd.Short)
	assert.NotEmpty(t, deviceSyncStatusCmd.Long)
	assert.NotNil(t, deviceSyncStatusCmd.RunE)
}

func TestPhoneSyncStatusCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceSyncStatusCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on sync-status command", name)
		})
	}
}

func TestPhoneSyncStatusCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := deviceSyncStatusCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := deviceSyncStatusCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- deviceSyncPushCmd structure tests ---

func TestPhoneSyncPushCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSyncPushCmd)
	assert.Equal(t, "sync-push", deviceSyncPushCmd.Use)
	assert.NotEmpty(t, deviceSyncPushCmd.Short)
	assert.NotEmpty(t, deviceSyncPushCmd.Long)
	assert.NotNil(t, deviceSyncPushCmd.RunE)
}

func TestPhoneSyncPushCmd_Flags(t *testing.T) {
	flags := []string{"trust-store", "oath", "passwords", "all", "device", "dry-run", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceSyncPushCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on sync-push command", name)
		})
	}
}

func TestPhoneSyncPushCmd_FlagDefaults(t *testing.T) {
	t.Run("all_default_true", func(t *testing.T) {
		flag := deviceSyncPushCmd.Flags().Lookup("all")
		require.NotNil(t, flag)
		assert.Equal(t, "true", flag.DefValue)
	})

	t.Run("dry_run_default_false", func(t *testing.T) {
		flag := deviceSyncPushCmd.Flags().Lookup("dry-run")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("device_default_empty", func(t *testing.T) {
		flag := deviceSyncPushCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := deviceSyncPushCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- deviceSyncPullCmd structure tests ---

func TestPhoneSyncPullCmd_Structure(t *testing.T) {
	assert.NotNil(t, deviceSyncPullCmd)
	assert.Equal(t, "sync-pull", deviceSyncPullCmd.Use)
	assert.NotEmpty(t, deviceSyncPullCmd.Short)
	assert.NotEmpty(t, deviceSyncPullCmd.Long)
	assert.NotNil(t, deviceSyncPullCmd.RunE)
}

func TestPhoneSyncPullCmd_Flags(t *testing.T) {
	flags := []string{"trust-store", "oath", "passwords", "all", "device", "dry-run", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := deviceSyncPullCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on sync-pull command", name)
		})
	}
}

func TestPhoneSyncPullCmd_FlagDefaults(t *testing.T) {
	t.Run("all_default_true", func(t *testing.T) {
		flag := deviceSyncPullCmd.Flags().Lookup("all")
		require.NotNil(t, flag)
		assert.Equal(t, "true", flag.DefValue)
	})

	t.Run("dry_run_default_false", func(t *testing.T) {
		flag := deviceSyncPullCmd.Flags().Lookup("dry-run")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("device_default_empty", func(t *testing.T) {
		flag := deviceSyncPullCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := deviceSyncPullCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- Command hierarchy tests ---

func TestPhoneCmd_SyncSubcommands(t *testing.T) {
	subcommands := deviceCmd.Commands()

	names := make(map[string]bool, len(subcommands))
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["sync"], "phone should have sync subcommand")
	assert.True(t, names["sync-status"], "phone should have sync-status subcommand")
	assert.True(t, names["sync-push"], "phone should have sync-push subcommand")
	assert.True(t, names["sync-pull"], "phone should have sync-pull subcommand")
}

// --- Error type tests ---

func TestPhoneSyncErrors(t *testing.T) {
	syncErrors := []struct {
		err      error
		contains string
	}{
		{ErrDeviceSyncFailed, "device: sync operation failed"},
		{ErrDeviceSyncNoScope, "device: no sync scope specified"},
	}

	for _, tc := range syncErrors {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.Contains(t, tc.err.Error(), "device:")
		})
	}
}

func TestPhoneSyncErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrDeviceSyncFailed,
		ErrDeviceSyncNoScope,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

func TestPhoneSyncStub_AllCommandsHaveRunE(t *testing.T) {
	commands := []*struct {
		name string
		cmd  interface{ RunE() }
	}{}
	_ = commands

	// Verify RunE is set on all sync commands
	assert.NotNil(t, deviceSyncCmd.RunE, "sync RunE should be set")
	assert.NotNil(t, deviceSyncStatusCmd.RunE, "sync-status RunE should be set")
	assert.NotNil(t, deviceSyncPushCmd.RunE, "sync-push RunE should be set")
	assert.NotNil(t, deviceSyncPullCmd.RunE, "sync-pull RunE should be set")
}
