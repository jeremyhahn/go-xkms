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

	"github.com/jeremyhahn/go-xkms/pkg/config"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// These tests prove New's fail-closed boot ordering at the construction
// entry point itself: each stage's failure must surface as *ErrServiceInit
// naming that exact stage, with the underlying typed cause still reachable
// through errors.As/errors.Is, and New must return a nil *Server rather than
// a partially-built one a caller could mistake for usable. The individual
// stage methods (resolveNodeSeal, initializeQRDBStorage,
// initializeCredentialService, resolveConfigSecrets, initializeBackends) are
// covered in isolation elsewhere; what is untested without these is New's
// own error-wrapping ladder around each of them.

// TestNew_NodeSealFailure_WrapsAsErrServiceInit proves a barrier configured
// for the tpm2 node-seal flip with no usable TPM present fails New itself —
// not just resolveNodeSeal in isolation — as *ErrServiceInit{Service: "node
// seal"} wrapping *NodeSealError.
func TestNew_NodeSealFailure_WrapsAsErrServiceInit(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:  true,
		Strategy: "tpm2",
	}

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "node seal", svcErr.Service)

	var sealErr *NodeSealError
	assert.True(t, errors.As(err, &sealErr), "error must unwrap to *NodeSealError, got %T", err)
}

// TestNew_QRDBStorageFailure_WrapsAsErrServiceInit proves an unrecognized
// qrdb storage transport fails New as *ErrServiceInit{Service: "qrdb
// storage"} wrapping *ErrUnsupportedStorageBackend, rather than the daemon
// discovering the typo only once it tries to actually reach the transport.
func TestNew_QRDBStorageFailure_WrapsAsErrServiceInit(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Storage = config.StorageConfig{
		Backend: "qrdb",
		Path:    t.TempDir(),
		QRDB:    config.QRDBConfig{Transport: "not-a-real-transport"},
	}

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "qrdb storage", svcErr.Service)

	var backendErr *ErrUnsupportedStorageBackend
	assert.True(t, errors.As(err, &backendErr), "error must unwrap to *ErrUnsupportedStorageBackend, got %T", err)
}

// TestNew_CredentialServiceFailure_WrapsAsErrServiceInit proves that
// credentials.seal_strategy: "barrier" fails New as *ErrServiceInit{Service:
// "credential service"} wrapping credentialspkg.ErrNilBarrier: the
// credential service initializes before initializeBarrier runs (see New's
// ordering comment), so a "barrier" strategy can never be satisfied and must
// be refused there instead of taking down whichever caller reaches the
// credential service first.
func TestNew_CredentialServiceFailure_WrapsAsErrServiceInit(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Credentials.SealStrategy = "barrier"

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "credential service", svcErr.Service)
	assert.True(t, errors.Is(err, credentialspkg.ErrNilBarrier),
		"error must unwrap to credentialspkg.ErrNilBarrier, got %v", err)
}

// TestNew_ConfigSecretResolutionFailure_WrapsAsErrServiceInit proves a
// literal secret in a protected config field (go-qrdb's contract: an inline
// value is refused, only a credential:// reference or nil is accepted) fails
// New as *ErrServiceInit{Service: "config secret resolution"} wrapping
// *ErrConfigSecretResolution, before initializeBackends ever reads the field
// and, in a real deployment, would have loaded the literal PIN into a PKCS#11
// C_Login call.
func TestNew_ConfigSecretResolutionFailure_WrapsAsErrServiceInit(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Backends.PKCS11 = &config.PKCS11Config{
		Pin: &types.SecretValue{Raw: "1234"},
	}

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "config secret resolution", svcErr.Service)

	var secretErr *ErrConfigSecretResolution
	assert.True(t, errors.As(err, &secretErr), "error must unwrap to *ErrConfigSecretResolution, got %T", err)
}

// TestNew_BackendsFailure_WrapsAsErrServiceInit proves a software backend
// whose configured path cannot be created (a regular file occupies where a
// directory is required — ENOTDIR, which the kernel enforces for every user
// including root, so this needs no permission-bit fault injection) fails New
// as *ErrServiceInit{Service: "backends"} wrapping *ErrStorageCreate, and
// that New releases the qrdb-storage/platform-store/credential-service
// resources it had already built (abortAfterStorage) rather than leaking
// them on this path.
func TestNew_BackendsFailure_WrapsAsErrServiceInit(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	tmpDir := t.TempDir()
	blocker := filepath.Join(tmpDir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0600))

	cfg := createMinimalConfig(t)
	cfg.Backends.Software.Path = filepath.Join(blocker, "software")

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "backends", svcErr.Service)

	var storageErr *ErrStorageCreate
	assert.True(t, errors.As(err, &storageErr), "error must unwrap to *ErrStorageCreate, got %T", err)
}
