// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package server

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrBackendInit_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("connection refused")
	e := &ErrBackendInit{Backend: "tpm2", Err: inner}

	assert.Contains(t, e.Error(), "tpm2")
	assert.Contains(t, e.Error(), "connection refused")
	assert.ErrorIs(t, e, inner)
}

func TestErrStorageCreate_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("disk full")
	e := &ErrStorageCreate{Resource: "key storage", Err: inner}

	assert.Contains(t, e.Error(), "key storage")
	assert.Contains(t, e.Error(), "disk full")
	assert.ErrorIs(t, e, inner)
}

func TestErrBackendCreate_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("invalid config")
	e := &ErrBackendCreate{Backend: "pkcs11", Err: inner}

	assert.Contains(t, e.Error(), "pkcs11")
	assert.Contains(t, e.Error(), "invalid config")
	assert.ErrorIs(t, e, inner)
}

func TestErrConfigRequired_Error(t *testing.T) {
	e := &ErrConfigRequired{Field: "pin", Backend: "pkcs11", Hint: "set PKCS11_PIN"}
	msg := e.Error()
	assert.Contains(t, msg, "pin")
	assert.Contains(t, msg, "pkcs11")
	assert.Contains(t, msg, "set PKCS11_PIN")
}

func TestErrConfigRequired_ErrorNoHint(t *testing.T) {
	e := &ErrConfigRequired{Field: "path", Backend: "vault"}
	msg := e.Error()
	assert.Contains(t, msg, "path")
	assert.Contains(t, msg, "vault")
	assert.NotContains(t, msg, "(")
}

func TestErrKeystoreCreate_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("auth failed")
	e := &ErrKeystoreCreate{Backend: "gcpkms", Err: inner}

	assert.Contains(t, e.Error(), "gcpkms")
	assert.Contains(t, e.Error(), "auth failed")
	assert.ErrorIs(t, e, inner)
}

func TestErrServiceInit_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("bind failed")
	e := &ErrServiceInit{Service: "grpc", Err: inner}

	assert.Contains(t, e.Error(), "grpc")
	assert.Contains(t, e.Error(), "bind failed")

	unwrapped := e.Unwrap()
	require.Len(t, unwrapped, 1)
	assert.Equal(t, inner, unwrapped[0])
}

func TestErrServiceInit_ErrorAndUnwrapWithSentinel(t *testing.T) {
	inner := errors.New("port in use")
	sentinel := errors.New("server: bind error")
	e := &ErrServiceInit{Service: "rest", Err: inner, Sentinel: sentinel}

	assert.Contains(t, e.Error(), "rest")

	unwrapped := e.Unwrap()
	require.Len(t, unwrapped, 2)
	assert.Equal(t, sentinel, unwrapped[0])
	assert.Equal(t, inner, unwrapped[1])

	// errors.Is should match both.
	assert.True(t, errors.Is(e, sentinel))
	assert.True(t, errors.Is(e, inner))
}

func TestErrConfigReload_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("yaml parse error")
	e := &ErrConfigReload{Component: "tls", Err: inner}

	assert.Contains(t, e.Error(), "tls")
	assert.Contains(t, e.Error(), "yaml parse error")
	assert.ErrorIs(t, e, inner)
}

func TestErrUnknownBackendType_Error(t *testing.T) {
	e := &ErrUnknownBackendType{Type: "quantum-x"}
	assert.Contains(t, e.Error(), "quantum-x")
}

func TestErrUnknownPINStrategy_Error(t *testing.T) {
	e := &ErrUnknownPINStrategy{Strategy: "biometric"}
	assert.Contains(t, e.Error(), "biometric")
}

func TestErrBackendNotAvailable_Error(t *testing.T) {
	e := &ErrBackendNotAvailable{Backend: "tpm2", Purpose: "signing"}
	msg := e.Error()
	assert.Contains(t, msg, "tpm2")
	assert.Contains(t, msg, "signing")
}

func TestErrBackendNotAvailable_ErrorNoPurpose(t *testing.T) {
	e := &ErrBackendNotAvailable{Backend: "pkcs11"}
	msg := e.Error()
	assert.Contains(t, msg, "pkcs11")
	assert.NotContains(t, msg, "for")
}

func TestErrCAInit_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("key generation failed")
	e := &ErrCAInit{Operation: "initialize root CA", Err: inner}

	assert.Contains(t, e.Error(), "initialize root CA")
	assert.Contains(t, e.Error(), "key generation failed")
	assert.ErrorIs(t, e, inner)
}

func TestErrTLSCertOp_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("cert expired")
	e := &ErrTLSCertOp{Operation: "load TLS cert", Err: inner}

	assert.Contains(t, e.Error(), "load TLS cert")
	assert.Contains(t, e.Error(), "cert expired")

	unwrapped := e.Unwrap()
	require.Len(t, unwrapped, 1)
	assert.Equal(t, inner, unwrapped[0])
}

func TestErrTLSCertOp_ErrorAndUnwrapWithSentinel(t *testing.T) {
	inner := errors.New("key not found")
	sentinel := ErrCATLSCertFailed
	e := &ErrTLSCertOp{Operation: "issue cert", Err: inner, Sentinel: sentinel}

	unwrapped := e.Unwrap()
	require.Len(t, unwrapped, 2)
	assert.True(t, errors.Is(e, sentinel))
	assert.True(t, errors.Is(e, inner))
}

func TestErrCompositeMethodCreate_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("invalid key")
	e := &ErrCompositeMethodCreate{Method: "jwt", Err: inner}

	assert.Contains(t, e.Error(), "jwt")
	assert.Contains(t, e.Error(), "invalid key")
	assert.ErrorIs(t, e, inner)
}

func TestErrFileRead_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("permission denied")
	e := &ErrFileRead{Path: "/etc/secret.key", Err: inner}

	assert.Contains(t, e.Error(), "/etc/secret.key")
	assert.Contains(t, e.Error(), "permission denied")
	assert.ErrorIs(t, e, inner)
}

func TestErrCertParse_Error(t *testing.T) {
	e := &ErrCertParse{Path: "/certs/ca.pem"}
	assert.Contains(t, e.Error(), "/certs/ca.pem")
}

func TestErrCertParse_ErrorNoPath(t *testing.T) {
	e := &ErrCertParse{}
	assert.Contains(t, e.Error(), "failed to parse CA certificate")
}

func TestErrNotCompiledIn_ErrorAndUnwrap(t *testing.T) {
	e := &ErrNotCompiledIn{Backend: "awskms", Tag: "awskms"}

	msg := e.Error()
	assert.Contains(t, msg, "awskms")
	assert.Contains(t, msg, "-tags awskms")
	assert.ErrorIs(t, e, ErrBackendNotCompiled)
}

func TestErrCABundleGet_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("timeout")
	e := &ErrCABundleGet{Operation: "CA bundle", Err: inner}

	assert.Contains(t, e.Error(), "CA bundle")
	assert.Contains(t, e.Error(), "timeout")
	assert.ErrorIs(t, e, inner)
}

func TestErrUnsupportedStorageBackend_Error(t *testing.T) {
	e := &ErrUnsupportedStorageBackend{Backend: "redis"}
	assert.Contains(t, e.Error(), "redis")
}
