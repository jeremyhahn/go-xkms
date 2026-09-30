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

package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestNew_EmptyStoragePath_RejectedBeforeAnyFilesystemWrite is the go-xkms#666
// regression: before this fix, New never called config.Validate, so a
// hand-built *config.Config with an empty Storage.Path reached
// initializePINManager, which built its state directory by string
// concatenation (Storage.Path + "/pin") -- an empty path resolved to the
// filesystem root's own "/pin" directory. New now calls cfg.Validate()
// before touching the filesystem or storage at all, so this configuration is
// refused immediately and nothing pin/password/software-shaped is ever
// created relative to the process's working directory.
func TestNew_EmptyStoragePath_RejectedBeforeAnyFilesystemWrite(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	wd, err := os.Getwd()
	require.NoError(t, err)

	// Precondition: no stray directory from a previous failed run of this
	// or any other test would make a false negative below.
	watched := []string{"pin", "passwords", "software", "certs"}
	for _, sub := range watched {
		_, statErr := os.Stat(filepath.Join(wd, sub))
		require.True(t, os.IsNotExist(statErr), "precondition: no stray %q dir in the working directory", sub)
	}

	cfg := createMinimalConfig(t)
	cfg.Datastore.Path = ""
	// PIN.Enabled is the subsystem that used to build its state directory by
	// raw string concatenation against Storage.Path -- see
	// initializePINManager's guard.
	cfg.PIN.Enabled = true

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv, "a failed construction must not hand back a partially-built server")

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "configuration", svcErr.Service)
	assert.Contains(t, err.Error(), "datastore.path must be specified")

	for _, sub := range watched {
		_, statErr := os.Stat(filepath.Join(wd, sub))
		assert.True(t, os.IsNotExist(statErr),
			"New must not create %q under the working directory when storage.path is empty", sub)
	}
}

// TestNew_InvalidConfig_RejectedWithTypedError proves New surfaces any
// config.Validate failure -- not just the storage-path shape above -- as
// *ErrServiceInit{Service: "configuration"} wrapping Validate's own typed
// error, so every embedder gets the same fail-closed check config.Load
// already applied to a file-loaded configuration.
func TestNew_InvalidConfig_RejectedWithTypedError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Logging.Level = "not-a-real-level"

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "configuration", svcErr.Service)
	assert.Contains(t, err.Error(), "invalid log level")
}

// TestNew_ValidConfig_Succeeds is the companion positive case: a config
// config.Validate accepts still constructs normally through New, proving the
// Validate call added by go-xkms#666 does not reject configurations that
// were already correct.
func TestNew_ValidConfig_Succeeds(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)

	srv, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)
	defer func() { _ = srv.Shutdown() }()
}
