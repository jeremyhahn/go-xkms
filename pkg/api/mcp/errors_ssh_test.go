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

func TestMapSSHError_InvalidParamsClassification(t *testing.T) {
	// The not-found/duplicate/mismatch trio and every validation error share
	// ErrCodeInvalidParams (see mapSSHError's doc comment for why they
	// cannot be told apart by code alone).
	tests := []struct {
		name string
		err  error
	}{
		{"invalid params", &SSHInvalidParamsError{Err: errors.New("bad json")}},
		{"handler-local not found", &SSHNotFoundError{Resource: "authorized_key"}},
		{"key not found", &pkgkeys.KeyNotFoundError{ID: "k1"}},
		{"known_hosts not found", &pkgknownhosts.NotFoundError{Host: "h"}},
		{"authorized not found", &pkgauthorized.NotFoundError{Name: "n"}},
		{"known_hosts duplicate", &pkgknownhosts.DuplicateError{Host: "h"}},
		{"authorized duplicate", &pkgauthorized.DuplicateError{Name: "n"}},
		{"known_hosts mismatch", &pkgknownhosts.MismatchError{Host: "h", Expected: "a", Received: "b"}},
		{"keys nil input", &pkgkeys.NilInputError{Field: "f"}},
		{"keys unsupported algorithm", &pkgkeys.UnsupportedAlgorithmError{Algorithm: "rot13"}},
		{"keys invalid key size", &pkgkeys.InvalidKeySizeError{Algorithm: "rsa", Size: 1}},
		{"keys passphrase required", &pkgkeys.PassphraseRequiredError{}},
		{"keys PEM parse", &pkgkeys.PEMParseError{Err: errors.New("bad pem")}},
		{"known_hosts nil input", &pkgknownhosts.NilInputError{Field: "f"}},
		{"known_hosts no public key", &pkgknownhosts.NoPublicKeyError{Host: "h"}},
		{"known_hosts legacy pin", &pkgknownhosts.LegacyPinError{Host: "h"}},
		{"known_hosts rejected", &pkgknownhosts.RejectedError{Host: "h"}},
		{"known_hosts invalid host", &pkgknownhosts.InvalidHostError{Value: "v", Reason: "r"}},
		{"known_hosts public key required", &pkgknownhosts.PublicKeyRequiredError{Host: "h"}},
		{"known_hosts invalid fingerprint", &pkgknownhosts.InvalidFingerprintError{Value: "v", Reason: "r"}},
		{"authorized nil input", &pkgauthorized.NilInputError{Field: "f"}},
		{"authorized malformed line", &pkgauthorized.MalformedLineError{Line: "l", Err: errors.New("bad")}},
		{"authorized invalid name", &pkgauthorized.InvalidNameError{Value: "v", Reason: "r"}},
		{"authorized unsupported version", &pkgauthorized.UnsupportedVersionError{Found: 9, Supported: 2}},
		{"sdkssh nil input", &sdkssh.NilInputError{Field: "f"}},
		{"sdkssh invalid scope", &sdkssh.InvalidScopeError{Value: "v"}},
		{"sdkssh invalid algorithm", &sdkssh.InvalidAlgorithmError{Value: "v"}},
		{"sdkssh missing public key", &sdkssh.MissingPublicKeyError{Host: "h"}},
		{"sdkssh invalid public key", &sdkssh.InvalidPublicKeyError{Host: "h", Err: errors.New("bad")}},
		{"sdkssh backend unavailable", &sdkssh.BackendUnavailableError{Backend: "tpm2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSSHError(tt.err)
			var keyErr *KeyOpError
			if !errors.As(got, &keyErr) {
				t.Fatalf("expected *KeyOpError, got %T", got)
			}
			if keyErr.Code != ErrCodeInvalidParams {
				t.Errorf("Code = %d, want ErrCodeInvalidParams", keyErr.Code)
			}
			// The message must survive verbatim: the distinction lost at the
			// code level is exactly what the message still carries.
			if keyErr.Error() != tt.err.Error() {
				t.Errorf("Error() = %q, want %q (message must survive unchanged)", keyErr.Error(), tt.err.Error())
			}
		})
	}
}

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
		{"authorized storage", &pkgauthorized.StorageError{Op: "op", Err: errors.New("x")}},
		{"authorized serialization", &pkgauthorized.SerializationError{Op: "op", Err: errors.New("x")}},
		{"not implemented", &sdkssh.NotImplementedError{Transport: "mcp", Op: "console"}},
		{"unclassified", errors.New("something unexpected")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSSHError(tt.err)
			var keyErr *KeyOpError
			if !errors.As(got, &keyErr) {
				t.Fatalf("expected *KeyOpError, got %T", got)
			}
			if keyErr.Code != ErrCodeInternalError {
				t.Errorf("Code = %d, want ErrCodeInternalError", keyErr.Code)
			}
		})
	}
}
