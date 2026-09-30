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

package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestResolveTPM2KeyDir_EmptyStoragePath is the regression test for #609: an
// unconfigured storage path must never resolve the TPM2 key directory
// relative to the process's working directory (some callers of this package,
// e.g. an embedded/programmatic *config.Config, never run
// config.Config.Validate, so this cannot be assumed already rejected).
func TestResolveTPM2KeyDir_EmptyStoragePath(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Path: ""},
	})

	wd, err := os.Getwd()
	require.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(wd, embeddednode.KeyDirSubdir))
	require.True(t, os.IsNotExist(statErr), "precondition: no stray tpm2-keys dir in the working directory")

	dir, err := s.resolveTPM2KeyDir()
	require.Error(t, err)
	assert.Empty(t, dir)

	var pathErr *embeddednode.ErrDatastorePathRequired
	require.True(t, errors.As(err, &pathErr), "error must unwrap to *embeddednode.ErrDatastorePathRequired, got %v", err)

	_, statErr = os.Stat(filepath.Join(wd, embeddednode.KeyDirSubdir))
	assert.True(t, os.IsNotExist(statErr), "resolving the key directory must never create it under the working directory")
}

// TestResolveTPM2KeyDir_Success verifies the key directory is derived from
// the configured storage path.
func TestResolveTPM2KeyDir_Success(t *testing.T) {
	storagePath := t.TempDir()
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Path: storagePath},
	})

	dir, err := s.resolveTPM2KeyDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(storagePath, "tpm2-keys"), dir)
}

// TestInitTPM2Backend_EmptyStoragePath verifies that enabling the TPM2
// backend without a configured storage path fails closed with a typed error
// instead of writing key material under the process's working directory.
func TestInitTPM2Backend_EmptyStoragePath(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Path: ""},
		Backends: config.BackendsConfig{
			TPM2: &config.TPM2Config{
				Enabled:      true,
				UseSimulator: true,
			},
		},
	})
	s.keyProviders = map[string]types.KeyProvider{}

	err := s.initTPM2Backend()
	require.Error(t, err)
	assert.Empty(t, s.keyProviders)

	var createErr *ErrBackendCreate
	require.True(t, errors.As(err, &createErr), "error must unwrap to *ErrBackendCreate, got %v", err)

	var pathErr *embeddednode.ErrDatastorePathRequired
	require.True(t, errors.As(err, &pathErr), "error must unwrap to *embeddednode.ErrDatastorePathRequired, got %v", err)
}
