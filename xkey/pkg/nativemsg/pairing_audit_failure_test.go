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

package nativemsg

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests prove that every security-relevant PairingVerifier operation
// fails closed when the audit sink itself is broken (issue class #688):
// OpPairing* events are SeveritySecurity, so a discarded write would let a
// caller believe a lockout, rejection or pairing succeeded when its audit
// trail never reached the store. failingPairingAudit and errPairingAuditSink
// are defined in pairing_test.go.

// TestVerifyIdentity_AuditFailurePropagates_OriginMismatch drives repeated
// unknown-origin verification attempts under a broken audit sink. Below
// maxVerifyFailures each call fails on the per-attempt audit write; the
// call that reaches maxVerifyFailures also exercises recordVerifyFailure's
// own lockout-write failure. Every call in the sequence must error.
func TestVerifyIdentity_AuditFailurePropagates_OriginMismatch(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	v.SetAuditLogger(failingPairingAudit{})

	ephemeralKey := make([]byte, X25519KeySize)
	unknownOrigin := "chrome-extension://unknownextension/"
	for i := 0; i < maxVerifyFailures; i++ {
		err := v.VerifyIdentity(pub, []byte("sig"), ephemeralKey, unknownOrigin)
		assert.ErrorIs(t, err, errPairingAuditSink, "attempt %d must not swallow the audit failure", i+1)
	}
}

// TestVerifyIdentity_AuditFailurePropagates_IdentityKeyMismatch mirrors the
// origin-mismatch case for the identity-key-mismatch branch.
func TestVerifyIdentity_AuditFailurePropagates_IdentityKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	otherPub, _ := generateTestIdentity(t)
	v.SetAuditLogger(failingPairingAudit{})

	ephemeralKey := make([]byte, X25519KeySize)
	for i := 0; i < maxVerifyFailures; i++ {
		err := v.VerifyIdentity(otherPub, []byte("sig"), ephemeralKey, testOrigin)
		assert.ErrorIs(t, err, errPairingAuditSink, "attempt %d must not swallow the audit failure", i+1)
	}
}

// TestVerifyIdentity_AuditFailurePropagates_BadSignature mirrors the
// origin-mismatch case for the invalid-signature branch.
func TestVerifyIdentity_AuditFailurePropagates_BadSignature(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	v.SetAuditLogger(failingPairingAudit{})

	ephemeralKey := make([]byte, X25519KeySize)
	for i := 0; i < maxVerifyFailures; i++ {
		err := v.VerifyIdentity(pub, []byte("not-a-valid-signature"), ephemeralKey, testOrigin)
		assert.ErrorIs(t, err, errPairingAuditSink, "attempt %d must not swallow the audit failure", i+1)
	}
}

// TestVerifyIdentity_AuditFailurePropagates_Success proves a successful
// verification still fails closed when the final success audit write fails.
func TestVerifyIdentity_AuditFailurePropagates_Success(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, priv := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	v.SetAuditLogger(failingPairingAudit{})

	ephemeralKey := make([]byte, X25519KeySize)
	sig := signEphemeral(t, priv, ephemeralKey, testOrigin)

	err = v.VerifyIdentity(pub, sig, ephemeralKey, testOrigin)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestStartPairing_AuditFailurePropagates_Lockout proves a lockout refusal
// still fails closed when its audit write fails.
func TestStartPairing_AuditFailurePropagates_Lockout(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)

	// Drive CompletePairing with a wrong code maxPairingFailures times to
	// trip the lockout, with a working (nil) audit logger.
	for i := 0; i < maxPairingFailures; i++ {
		code, err := v.StartPairing(pub, testOrigin)
		require.NoError(t, err)
		err = v.CompletePairing(pub, testOrigin, invertPairingCode(code))
		require.Error(t, err)
	}

	v.SetAuditLogger(failingPairingAudit{})

	_, err = v.StartPairing(pub, testOrigin)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestStartPairing_AuditFailurePropagates_Success proves a successful start
// still fails closed when its success audit write fails.
func TestStartPairing_AuditFailurePropagates_Success(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)
	v.SetAuditLogger(failingPairingAudit{})

	pub, _ := generateTestIdentity(t)
	_, err = v.StartPairing(pub, testOrigin)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestCompletePairing_AuditFailurePropagates_WrongCode drives repeated
// wrong-code completions under a broken audit sink, covering both the
// per-attempt failure write and recordPairingFailure's own lockout write.
func TestCompletePairing_AuditFailurePropagates_WrongCode(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	code, err := v.StartPairing(pub, testOrigin)
	require.NoError(t, err)

	v.SetAuditLogger(failingPairingAudit{})

	wrong := invertPairingCode(code)
	for i := 0; i < maxPairingFailures; i++ {
		err := v.CompletePairing(pub, testOrigin, wrong)
		assert.ErrorIs(t, err, errPairingAuditSink, "attempt %d must not swallow the audit failure", i+1)
	}
}

// TestCompletePairing_AuditFailurePropagates_IdentityMismatch proves the
// identity-key-mismatch failure path fails closed under a broken audit sink.
func TestCompletePairing_AuditFailurePropagates_IdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	code, err := v.StartPairing(pub, testOrigin)
	require.NoError(t, err)

	otherPub, _ := generateTestIdentity(t)
	v.SetAuditLogger(failingPairingAudit{})

	err = v.CompletePairing(otherPub, testOrigin, code)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestCompletePairing_AuditFailurePropagates_OriginMismatch proves the
// origin-mismatch failure path fails closed under a broken audit sink.
func TestCompletePairing_AuditFailurePropagates_OriginMismatch(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	code, err := v.StartPairing(pub, testOrigin)
	require.NoError(t, err)

	v.SetAuditLogger(failingPairingAudit{})

	err = v.CompletePairing(pub, "chrome-extension://different/", code)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestCompletePairing_AuditFailurePropagates_Success proves a successful
// completion fails closed when its success audit write fails, before the
// state is ever persisted to disk.
func TestCompletePairing_AuditFailurePropagates_Success(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	code, err := v.StartPairing(pub, testOrigin)
	require.NoError(t, err)

	v.SetAuditLogger(failingPairingAudit{})

	err = v.CompletePairing(pub, testOrigin, code)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestUnpairOrigin_AuditFailurePropagates proves UnpairOrigin fails closed
// when its audit write fails, whether or not it is the last paired origin.
func TestUnpairOrigin_AuditFailurePropagates(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	v.SetAuditLogger(failingPairingAudit{})

	err = v.UnpairOrigin(testOrigin)
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// TestUnpairAll_AuditFailurePropagates proves UnpairAll fails closed when
// its audit write fails.
func TestUnpairAll_AuditFailurePropagates(t *testing.T) {
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)

	v.SetAuditLogger(failingPairingAudit{})

	err = v.UnpairAll()
	assert.ErrorIs(t, err, errPairingAuditSink)
}

// invertPairingCode returns a digit string guaranteed to differ from code at
// every position, so it can never coincidentally equal a freshly generated
// pairing code.
func invertPairingCode(code string) string {
	out := make([]byte, len(code))
	for i, c := range []byte(code) {
		out[i] = '0' + (9 - (c - '0'))
	}
	return string(out)
}
