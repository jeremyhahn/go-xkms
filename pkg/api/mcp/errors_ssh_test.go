// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"errors"
	"testing"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

func TestMapSSHError_Nil(t *testing.T) {
	if mapSSHError(nil) != nil {
		t.Error("mapSSHError(nil) must be nil")
	}
}

func TestMapSSHError_AlreadyClassifiedPassesThrough(t *testing.T) {
	original := &KeyOpError{Code: ErrCodeForbidden, Err: errors.New("boom")}
	got := mapSSHError(original)
	var keyErr *KeyOpError
	if !errors.As(got, &keyErr) {
		t.Fatalf("expected *KeyOpError, got %T", got)
	}
	if keyErr.Code != ErrCodeForbidden {
		t.Errorf("Code = %d, want unchanged ErrCodeForbidden", keyErr.Code)
	}
}

func TestMapSSHError_NotConfiguredIsServiceUnavailable(t *testing.T) {
	got := mapSSHError(ErrSSHNotConfigured)
	var keyErr *KeyOpError
	if !errors.As(got, &keyErr) {
		t.Fatalf("expected *KeyOpError, got %T", got)
	}
	if keyErr.Code != ErrCodeServiceUnavailable {
		t.Errorf("Code = %d, want ErrCodeServiceUnavailable", keyErr.Code)
	}
}

// mapAndCheckCode is the shared assertion for the classification tables
// below: mapSSHError(err) must produce a *KeyOpError carrying wantCode, with
// the original error preserved as .Err (and so .Error() unchanged) so the
// message a caller sees never depends on which code classified it.
func mapAndCheckCode(t *testing.T, err error, wantCode int) {
	t.Helper()
	got := mapSSHError(err)
	var keyErr *KeyOpError
	if !errors.As(got, &keyErr) {
		t.Fatalf("expected *KeyOpError, got %T", got)
	}
	if keyErr.Code != wantCode {
		t.Errorf("Code = %d, want %d", keyErr.Code, wantCode)
	}
	if keyErr.Error() != err.Error() {
		t.Errorf("Error() = %q, want %q (message must survive unchanged)", keyErr.Error(), err.Error())
	}
}

// TestMapSSHError_NotFoundClassification proves a missing resource, from
// any of the three SSH store packages plus this package's own
// verify-with-no-match result, reaches its own distinct code --
// sdkssh.JSONRPCCodeNotFound -- rather than collapsing into the generic
// invalid-params bucket every other xkms method family is stuck with.
func TestMapSSHError_NotFoundClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"handler-local not found", &SSHNotFoundError{Resource: "authorized_key"}},
		{"key not found", &pkgkeys.KeyNotFoundError{ID: "k1"}},
		{"known_hosts not found", &pkgknownhosts.NotFoundError{Host: "h"}},
		{"authorized not found", &pkgauthorized.NotFoundError{Name: "n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapAndCheckCode(t, tt.err, sdkssh.JSONRPCCodeNotFound)
		})
	}
}

// TestMapSSHError_DuplicateClassification proves a non-idempotent conflict
// reaches sdkssh.JSONRPCCodeDuplicate, distinct from both NotFound and
// Mismatch.
func TestMapSSHError_DuplicateClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"known_hosts duplicate", &pkgknownhosts.DuplicateError{Host: "h"}},
		{"authorized duplicate", &pkgauthorized.DuplicateError{Name: "n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapAndCheckCode(t, tt.err, sdkssh.JSONRPCCodeDuplicate)
		})
	}
}

// TestMapSSHError_MismatchClassification proves a host-key mismatch (a
// MITM indicator) reaches sdkssh.JSONRPCCodeMismatch, distinct from
// Duplicate even though both are "the store already has something here"
// conditions.
func TestMapSSHError_MismatchClassification(t *testing.T) {
	mapAndCheckCode(t, &pkgknownhosts.MismatchError{Host: "h", Expected: "a", Received: "b"}, sdkssh.JSONRPCCodeMismatch)
}

// TestMapSSHError_InvalidParamsClassification covers the validation-grade
// errors sdkssh's shared classify() buckets as "bad request": malformed or
// unsupported caller input, not a not-found/duplicate/mismatch condition.
func TestMapSSHError_InvalidParamsClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"invalid params", &SSHInvalidParamsError{Err: errors.New("bad json")}},
		{"keys nil input", &pkgkeys.NilInputError{Field: "f"}},
		{"keys unsupported algorithm", &pkgkeys.UnsupportedAlgorithmError{Algorithm: "rot13"}},
		{"keys invalid key size", &pkgkeys.InvalidKeySizeError{Algorithm: "rsa", Size: 1}},
		{"keys passphrase required", &pkgkeys.PassphraseRequiredError{}},
		{"keys PEM parse", &pkgkeys.PEMParseError{Err: errors.New("bad pem")}},
		{"known_hosts nil input", &pkgknownhosts.NilInputError{Field: "f"}},
		{"known_hosts invalid host", &pkgknownhosts.InvalidHostError{Value: "v", Reason: "r"}},
		{"known_hosts invalid fingerprint", &pkgknownhosts.InvalidFingerprintError{Value: "v", Reason: "r"}},
		{"sdkssh missing public key", &sdkssh.MissingPublicKeyError{Host: "h"}},
		{"sdkssh invalid public key", &sdkssh.InvalidPublicKeyError{Host: "h", Err: errors.New("bad")}},
		{"authorized nil input", &pkgauthorized.NilInputError{Field: "f"}},
		{"authorized invalid name", &pkgauthorized.InvalidNameError{Value: "v", Reason: "r"}},
		{"authorized malformed line", &pkgauthorized.MalformedLineError{Line: "l", Err: errors.New("bad")}},
		{"sdkssh invalid scope", &sdkssh.InvalidScopeError{Value: "v"}},
		{"sdkssh invalid algorithm", &sdkssh.InvalidAlgorithmError{Value: "v"}},
		{"sdkssh nil input", &sdkssh.NilInputError{Field: "f"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapAndCheckCode(t, tt.err, ErrCodeInvalidParams)
		})
	}
}

// TestMapSSHError_NotImplementedClassification proves a transport stub
// (e.g. Session.Dial over MCP) reaches ErrCodeMethodNotFound, matching
// mapKeyOpError's own xkms.ErrOperationNotSupported mapping.
func TestMapSSHError_NotImplementedClassification(t *testing.T) {
	mapAndCheckCode(t, &sdkssh.NotImplementedError{Transport: "mcp", Op: "console"}, ErrCodeMethodNotFound)
}

// TestMapSSHError_InternalErrorClassification covers genuine internal
// faults (storage/serialization failures, programming-error signals) and
// anything sdkssh's shared classify() table does not otherwise recognize.
func TestMapSSHError_InternalErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"keys material", &pkgkeys.KeyMaterialError{Op: "op", Err: errors.New("x")}},
		{"keys storage", &pkgkeys.StorageError{Op: "op", Err: errors.New("x")}},
		{"keys serialization", &pkgkeys.SerializationError{Op: "op", Err: errors.New("x")}},
		{"keys closed signer", &pkgkeys.ClosedSignerError{}},
		{"known_hosts storage", &pkgknownhosts.StorageError{Op: "op", Err: errors.New("x")}},
		{"known_hosts serialization", &pkgknownhosts.SerializationError{Op: "op", Err: errors.New("x")}},
		{"known_hosts no public key", &pkgknownhosts.NoPublicKeyError{Host: "h"}},
		{"known_hosts legacy pin", &pkgknownhosts.LegacyPinError{Host: "h"}},
		{"known_hosts rejected", &pkgknownhosts.RejectedError{Host: "h"}},
		{"known_hosts public key required", &pkgknownhosts.PublicKeyRequiredError{Host: "h"}},
		{"authorized storage", &pkgauthorized.StorageError{Op: "op", Err: errors.New("x")}},
		{"authorized serialization", &pkgauthorized.SerializationError{Op: "op", Err: errors.New("x")}},
		{"authorized unsupported version", &pkgauthorized.UnsupportedVersionError{Found: 9, Supported: 2}},
		{"unclassified", errors.New("something unexpected")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapAndCheckCode(t, tt.err, ErrCodeInternalError)
		})
	}
}
