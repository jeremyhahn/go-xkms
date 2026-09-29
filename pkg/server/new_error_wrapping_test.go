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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
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
// remote datastore transport fails New as *ErrServiceInit{Service:
// "configuration"} wrapping config.Validate's own typed error, rather than
// the daemon discovering the typo only once it tries to actually reach the
// transport: since go-xkms#666, New() calls Validate() before touching
// storage, and Validate already rejects an unrecognized
// datastore.remote.transport (config.go's "invalid datastore.remote.transport"
// check), so initializeQRDBStorage's own *ErrUnsupportedStorageBackend
// wrapping for this same typo is now unreachable through New() -- see
// TestInitializeQRDBStorage_InvalidTransport for that stage tested directly.
func TestNew_QRDBStorageFailure_WrapsAsErrServiceInit(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Datastore = config.DatastoreConfig{
		Mode:   "remote",
		Remote: config.DatastoreRemoteConfig{Address: "https://qrdb.example.com:63002", Transport: "ftp"},
	}

	srv, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, srv)

	var svcErr *ErrServiceInit
	require.True(t, errors.As(err, &svcErr), "error must unwrap to *ErrServiceInit, got %T", err)
	assert.Equal(t, "configuration", svcErr.Service)
	assert.Contains(t, err.Error(), "invalid datastore.remote.transport")
}

// TestNew_CredentialServiceFailure_WrapsAsErrServiceInit proves that
// credentials.seal_strategy: "barrier" fails New as *ErrServiceInit{Service:
// "configuration"} wrapping config.Validate's own typed error: since
// go-xkms#666, New() calls Validate() before touching storage, and Validate
// already refuses "barrier" outside the one supported shape
// (CredentialsBarrierStrategySupported), so initializeCredentialService's own
// credentialspkg.ErrNilBarrier for this same misconfiguration is now
// unreachable through New() -- see
// TestNew_CredentialBarrierStrategy_UnsupportedConfigurationRefusedCleanly
// for that stage tested directly.
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
	assert.Equal(t, "configuration", svcErr.Service)
	assert.Contains(t, err.Error(), "credentials.seal_strategy \"barrier\"")
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

// TestNew_BackendsFailure_WrapsAsErrServiceInit used to prove a software
// backend whose configured path could not be created (a regular file
// occupying where a directory was required) failed New as
// *ErrServiceInit{Service: "backends"} wrapping *ErrStorageCreate. That
// fault injection is no longer reachable: createStorageAt
// (pkg/server/storage_factory.go) no longer touches the filesystem at all
// -- it derives a key namespace from filepath.Base(path) over the one
// shared datastore, which cannot fail once initializeQRDBStorage has
// already succeeded earlier in New's boot ordering (go-xkms#1345). The
// "backends" stage's own error-wrapping ladder still exists
// (ErrServiceInit{Service: "backends"} wrapping ErrBackendCreate, when a
// backend constructor itself rejects its config) and New's
// abortAfterStorage cleanup-on-failure path this test also covered remains
// exercised by its siblings in this file (e.g.
// TestNew_CredentialServiceFailure_WrapsAsErrServiceInit,
// TestNew_ConfigSecretResolutionFailure_WrapsAsErrServiceInit).
