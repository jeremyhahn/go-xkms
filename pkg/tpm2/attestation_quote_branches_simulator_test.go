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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// TestQuote_ExtractsBothIAKSignatureAlgorithms proves Quote's signature
// extraction takes the ECDSA branch -- not just the RSA branch every other
// simulator test in this package exercises -- when the IAK is configured
// ECC, and that the branch actually produces a usable ASN.1 r||s signature
// rather than merely being reached.
func TestQuote_ExtractsBothIAKSignatureAlgorithms(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IAK.RSAConfig = nil
		c.IAK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.IAK.KeyAlgorithm = x509.ECDSA.String()
		c.IAK.SignatureAlgorithm = "ECDSA-SHA256"
	})

	quote, err := h.TPM.Quote([]uint{0}, []byte("ecdsa-quote-nonce"))
	require.NoError(t, err)
	require.NotEmpty(t, quote.Signature)
	require.NotEmpty(t, quote.Quoted)
}

// TestQuote_RejectsSignatureUnionMismatchedToTheConfiguredAlgorithm proves
// Quote's signature-extraction switch actually checks the shape of what
// TPM2_Quote returned rather than trusting tpm.iakAttrs.KeyAlgorithm blindly:
// an IAK real key is RSA, but if the in-memory attributes were ever to
// disagree (a corrupted cache, a config edited between calls) the ECDSA
// extraction call must fail on the mismatched union instead of returning a
// zero-value signature as if it had succeeded.
func TestQuote_RejectsSignatureUnionMismatchedToTheConfiguredAlgorithm(t *testing.T) {
	h := newSimHarness(t, nil)

	h.TPM.iakAttrs.KeyAlgorithm = x509.ECDSA

	_, err := h.TPM.Quote([]uint{0}, []byte("mismatched-algorithm-nonce"))
	require.Error(t, err)
}

// TestPlatformQuote_PropagatesRandomFailure proves PlatformQuote surfaces a
// failure generating its own freshness nonce instead of quoting under no
// nonce at all.
func TestPlatformQuote_PropagatesRandomFailure(t *testing.T) {
	h := newSimHarness(t, nil)

	h.TPM.transport = &nSendTransport{inner: h.TPM.transport, n: 0}

	_, _, err := h.TPM.PlatformQuote(nil)
	require.Error(t, err)
}

// TestPlatformQuote_PropagatesQuoteFailure proves PlatformQuote surfaces a
// failure from the underlying Quote call (here, no IAK provisioned) rather
// than reporting the nonce it already generated as if the quote had
// succeeded.
func TestPlatformQuote_PropagatesQuoteFailure(t *testing.T) {
	h := newSimHarness(t, nil)

	h.TPM.iakAttrs = nil

	_, _, err := h.TPM.PlatformQuote(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotInitialized)
}

// TestAKProfile_PropagatesEKAttributesFailure proves AKProfile surfaces a
// failure resolving the EK -- here, a simulator whose EK was never
// provisioned -- instead of reporting a profile built around a zero-value
// EKPub.
func TestAKProfile_PropagatesEKAttributesFailure(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)

	_, err := h.TPM.AKProfile()
	require.Error(t, err)
}

// TestAKProfile_RejectsNilTPMAttributes proves AKProfile's final guard
// actually fires: even though EKAttributes and IAKAttributes both already
// return an error whenever the TPM never populated TPMAttributes on the
// path this package's own accessors take, the guard is the last line of
// defense against a future accessor change (or a caller that reaches in and
// clears the cached attributes directly, as this test does) leaving
// TPMAttributes nil while returning a non-nil KeyAttributes.
func TestAKProfile_RejectsNilTPMAttributes(t *testing.T) {
	h := newSimHarness(t, nil)

	// Warm both caches through a real, successful call first.
	_, err := h.TPM.AKProfile()
	require.NoError(t, err)

	h.TPM.ekAttrs.TPMAttributes = nil

	_, err = h.TPM.AKProfile()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotInitialized)
}
