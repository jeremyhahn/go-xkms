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
)

// This file exercises the Error()/Unwrap() methods of small typed errors
// (errors.go, firstboot.go, node_seal.go, sealed_window.go) that production
// code constructs and returns, but that no other test's assertions actually
// call .Error() on (errors.As/errors.Is never invoke it). Each case
// constructs the type directly and checks both the message and the
// unwrapped cause, so a future edit that breaks the format string or drops
// the wrapped cause fails here.

func TestErrPlatformStoreBuild_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("boom")
	err := &ErrPlatformStoreBuild{Strategy: "tpm2", Err: cause}
	assert.Contains(t, err.Error(), "tpm2")
	assert.Contains(t, err.Error(), "boom")
	assert.Same(t, cause, err.Unwrap())
}

func TestErrPlatformStoreStrategyUnavailable_Error(t *testing.T) {
	err := &ErrPlatformStoreStrategyUnavailable{Strategy: "vault", Reason: "no credential service yet"}
	assert.Contains(t, err.Error(), "vault")
	assert.Contains(t, err.Error(), "no credential service yet")
}

func TestErrNoBootstrapSuite_ErrorAndUnwrap(t *testing.T) {
	noiseErr := errors.New("noise unavailable")
	p256Err := errors.New("p256 unavailable")
	err := &ErrNoBootstrapSuite{Noise: noiseErr, P256: p256Err}

	assert.Contains(t, err.Error(), "noise unavailable")
	assert.Contains(t, err.Error(), "p256 unavailable")

	unwrapped := err.Unwrap()
	assert.ElementsMatch(t, []error{noiseErr, p256Err}, unwrapped)
	assert.True(t, errors.Is(err, noiseErr))
	assert.True(t, errors.Is(err, p256Err))
}

func TestErrP256KeyLength_Error(t *testing.T) {
	err := &ErrP256KeyLength{Got: 60, Want: 64}
	assert.Contains(t, err.Error(), "60")
	assert.Contains(t, err.Error(), "64")
}

func TestErrFileWrite_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	err := &ErrFileWrite{Path: "/tmp/x", Err: cause}
	assert.Contains(t, err.Error(), "/tmp/x")
	assert.Contains(t, err.Error(), "disk full")
	assert.Same(t, cause, err.Unwrap())
}

func TestErrBarrierKeyLoad_Error(t *testing.T) {
	cause := errors.New("sealed")
	err := &ErrBarrierKeyLoad{Key: "noise-static-key", Err: cause}
	assert.Contains(t, err.Error(), "noise-static-key")
	assert.Contains(t, err.Error(), "sealed")
}

func TestErrBarrierKeySeal_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("barrier put failed")
	err := &ErrBarrierKeySeal{Key: "p256-static-key", Err: cause}
	assert.Contains(t, err.Error(), "p256-static-key")
	assert.Contains(t, err.Error(), "barrier put failed")
	assert.Same(t, cause, err.Unwrap())
}

func TestErrConfigSecretResolution_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("credential://missing not resolvable")
	err := &ErrConfigSecretResolution{Err: cause}
	assert.Contains(t, err.Error(), "credential://missing not resolvable")
	assert.Same(t, cause, err.Unwrap())
}

func TestErrFrostSecretBackendUnavailable_Error(t *testing.T) {
	err := &ErrFrostSecretBackendUnavailable{Backend: "software"}
	assert.Contains(t, err.Error(), "software")
}

func TestFirstBootError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("no leader")
	err := &FirstBootError{Op: "initialize", Cause: cause}
	assert.Contains(t, err.Error(), "initialize")
	assert.Contains(t, err.Error(), "no leader")
	assert.Same(t, cause, err.Unwrap())
}

func TestNodeSealError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("tpm not found")
	err := &NodeSealError{Reason: "no usable TPM", Err: cause}
	assert.Contains(t, err.Error(), "no usable TPM")
	assert.Same(t, cause, err.Unwrap())

	// Err is optional: a NodeSealError raised without an underlying cause
	// must still Unwrap cleanly to nil rather than panic.
	bare := &NodeSealError{Reason: "no usable TPM"}
	assert.Nil(t, bare.Unwrap())
}

func TestSealedWindowBindError_Error(t *testing.T) {
	err := &SealedWindowBindError{Host: "0.0.0.0"}
	assert.Contains(t, err.Error(), "0.0.0.0")

	// Empty Host reports the "<all interfaces>" placeholder rather than an
	// empty, unhelpful quoted string.
	wildcard := &SealedWindowBindError{}
	assert.Contains(t, wildcard.Error(), "<all interfaces>")
}

func TestClusterAdvertiseError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("registry unreachable")
	err := &ClusterAdvertiseError{Stage: "new node advertiser", Err: cause}
	assert.Contains(t, err.Error(), "new node advertiser")
	assert.Contains(t, err.Error(), "registry unreachable")
	assert.Same(t, cause, err.Unwrap())
}
