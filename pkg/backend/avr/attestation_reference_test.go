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

package avr

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vecApplicationEvidenceHex is the application evidence (273) the frozen
// alias certificate vector carries: sha-256 of "abc".
const vecApplicationEvidenceHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func checkVectorAgainst(t *testing.T, ref []byte) (*Attestation, error) {
	t.Helper()
	der, err := hex.DecodeString(vecAliasCertHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(vecAliasCertNonceHex)
	require.NoError(t, err)
	b := &Backend{
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		applicationReference: ref,
	}
	return b.checkAliasCertificate(der, nonce)
}

func TestCheckAliasCertificateAcceptsTheRegisteredApplicationReference(t *testing.T) {
	ref, err := hex.DecodeString(vecApplicationEvidenceHex)
	require.NoError(t, err)

	att, err := checkVectorAgainst(t, ref)

	require.NoError(t, err)
	der, err := hex.DecodeString(vecAliasCertHex)
	require.NoError(t, err)
	assert.Equal(t, der, att.Certificate.Raw)
}

func TestCheckAliasCertificateRefusesADifferentApplication(t *testing.T) {
	ref, err := hex.DecodeString(vecApplicationEvidenceHex)
	require.NoError(t, err)
	ref[len(ref)-1] ^= 0x01

	att, err := checkVectorAgainst(t, ref)

	assert.ErrorIs(t, err, dice.ErrApplicationEvidenceMismatch)
	assert.Nil(t, att)
}

func TestCheckAliasCertificateWithoutAReferenceSkipsTheMatch(t *testing.T) {
	att, err := checkVectorAgainst(t, nil)

	require.NoError(t, err)
	assert.NotNil(t, att.Certificate)
}

func TestNewBackendRefusesAMalformedApplicationReference(t *testing.T) {
	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{ApplicationReference: make([]byte, 31)}

	_, err := NewBackend(context.Background(), cfg, newTestDevice(secureElementLink()))

	require.ErrorIs(t, err, dice.ErrInvalidApplicationReference)
	assert.Contains(t, err.Error(), "got 31")
}

// An explicitly empty reference is not "no reference": it names no
// application, so it is refused like any other wrong length rather than
// silently leaving the application unchecked.
func TestNewBackendRefusesAnEmptyApplicationReference(t *testing.T) {
	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{ApplicationReference: []byte{}}

	_, err := NewBackend(context.Background(), cfg, newTestDevice(secureElementLink()))

	require.ErrorIs(t, err, dice.ErrInvalidApplicationReference)
	assert.Contains(t, err.Error(), "got 0")
}

func TestNewBackendAcceptsAnApplicationReferenceWithoutATrustStore(t *testing.T) {
	cfg := testConfig()
	cfg.Attestation = &AttestationConfig{ApplicationReference: make([]byte, 32)}

	b, err := NewBackend(context.Background(), cfg, newTestDevice(secureElementLink()))

	require.NoError(t, err)
	assert.Len(t, b.applicationReference, 32)
}
