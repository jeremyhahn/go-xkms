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

package main

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// presealSecrets is every secret an `xkmsd seal-*` verb seals.
var presealSecrets = []presealSecret{pkcs11PINSecret, vaultTokenSecret}

func sealSecretTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestReadSecret_TrimsTheTrailingNewline(t *testing.T) {
	secret, err := readSecret(strings.NewReader("1234\r\n"))
	require.NoError(t, err)
	require.Equal(t, []byte("1234"), secret)
}

func TestReadSecret_RejectsEmptyAndUnreadableInput(t *testing.T) {
	_, err := readSecret(strings.NewReader("\n"))
	require.ErrorIs(t, err, ErrSealSecretEmpty)

	_, err = readSecret(iotest.ErrReader(errors.New("closed")))
	require.ErrorIs(t, err, ErrSealSecretReadFailed)
}

func TestPresealSecretCommand_RejectsBadInvocations(t *testing.T) {
	logger := sealSecretTestLogger()
	for _, s := range presealSecrets {
		t.Run(s.verb, func(t *testing.T) {
			err := s.command(nil, strings.NewReader("1234"), logger)
			require.ErrorIs(t, err, ErrSealSecretConfigRequired)

			err = s.command([]string{"--secret", "1234"}, strings.NewReader(""), logger)
			require.Error(t, err, "a secret flag must not exist")

			missing := filepath.Join(t.TempDir(), "missing.yaml")
			err = s.command([]string{"--config", missing}, strings.NewReader("1234"), logger)
			require.ErrorIs(t, err, ErrConfigLoad)
		})
	}
}

func TestPresealSecretSeal_RequiresTheTPMBackend(t *testing.T) {
	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: t.TempDir()}}
	for _, s := range presealSecrets {
		err := s.seal(cfg, sealSecretTestLogger(), []byte("1234"))
		var nodeErr *embeddednode.NodeSealError
		require.ErrorAs(t, err, &nodeErr, s.verb)
	}
}

func TestPresealSecretRun_ExitsNonZeroOnFailure(t *testing.T) {
	for _, s := range presealSecrets {
		require.Equal(t, 1, s.run(nil), s.verb)
	}
}

func TestSubcommands_RegisterEverySealVerb(t *testing.T) {
	for _, s := range presealSecrets {
		require.Contains(t, subcommands, s.verb)
	}
}
