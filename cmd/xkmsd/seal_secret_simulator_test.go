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

//go:build tpm_simulator

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// TestPresealSecretCommand_SealsWhatTheBootReleases proves each verb seals
// its secret where the boot looks for it: in the pre-barrier store of the
// configured datastore, under the configured TPM, under the secret's own name.
func TestPresealSecretCommand_SealsWhatTheBootReleases(t *testing.T) {
	for _, s := range presealSecrets {
		t.Run(s.verb, func(t *testing.T) {
			dataDir := t.TempDir()
			configPath := filepath.Join(t.TempDir(), "xkmsd.yaml")
			yaml := "datastore:\n  path: " + dataDir + "\n" +
				"protocols:\n  unix: true\n" +
				"logging:\n  level: info\n  format: json\n" +
				"default_backend: pkcs8\n" +
				"backends:\n  pkcs8:\n    enabled: true\n    path: " + filepath.Join(dataDir, "pkcs8") + "\n  tpm2:\n    use_simulator: true\n"
			require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0o600))

			err := s.command([]string{"--config", configPath},
				strings.NewReader("secret-"+s.strategy+"\n"), sealSecretTestLogger())
			require.NoError(t, err)

			cfg := &config.Config{
				Datastore: config.DatastoreConfig{Path: dataDir},
				Backends:  config.BackendsConfig{TPM2: &config.TPM2Config{UseSimulator: true}},
			}
			store, closeStore, err := embeddednode.OpenPreseal(cfg, sealSecretTestLogger())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, closeStore()) })
			secret, err := store.Get(context.Background(), s.key)
			require.NoError(t, err)
			require.Equal(t, []byte("secret-"+s.strategy), secret)
		})
	}
}
