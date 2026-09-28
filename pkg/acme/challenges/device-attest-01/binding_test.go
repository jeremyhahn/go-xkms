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

package deviceattest01

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveAttestation stands up the endpoint a device answers on and returns the
// host and port to verify against, so these tests drive the same path a server
// does rather than the evidence verifier alone.
func serveAttestation(t *testing.T, object *AttestationObject) (string, string) {
	t.Helper()

	encoded, err := cbor.Marshal(object)
	require.NoError(t, err)
	payload, err := json.Marshal(AttestationRequest{AttStmt: encoded})
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)
	return host, port
}

// csrFor builds a certificate request for a key, which is what a client sends
// at finalization.
func csrFor(t *testing.T, key *ecdsa.PrivateKey) *x509.CertificateRequest {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "avr-device-0001"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// TestVerifyDoesNotAuthorizeDICEOnTheNonceAlone is the hole this file closes.
//
// The device answered the challenge correctly: the nonce in its alias
// certificate is SHA-256 of this exact key authorization. What the challenge
// does NOT establish is which key the certificate about to be issued is for,
// because the CSR arrives one request later. A verifier that reported success
// here would have authorized issuance against a key nobody compared with the
// device's -- and attestation chains are public, so anyone who has seen one
// genuine device's answer could replay it beside a software key.
func TestVerifyDoesNotAuthorizeDICEOnTheNonceAlone(t *testing.T) {
	host, port := serveAttestation(t, diceAttestationObject(t, DICENonce(diceKeyAuth)))

	err := Verify(net.DefaultResolver, &mockCA{}, host, port, "token", diceKeyAuth)
	require.Error(t, err, "a dice challenge authorized issuance with no csr in sight")
	assert.ErrorIs(t, err, ErrKeyBindingRequired)
}

// TestBindCSRKeyRefusesACSRForAnUnrelatedKey is the binding itself, on the
// path an order takes: verify the device's evidence, then meet the CSR.
func TestBindCSRKeyRefusesACSRForAnUnrelatedKey(t *testing.T) {
	leafDER, aliasKey := newDICEAlias(t, DICENonce(diceKeyAuth))
	object := &AttestationObject{
		Format:       string(FormatDICE),
		AttStatement: AttestationStatement{X5c: []interface{}{leafDER}},
	}
	host, port := serveAttestation(t, object)

	verified, err := VerifyAttestation(net.DefaultResolver, &mockCA{}, host, port, "token", diceKeyAuth)
	require.NoError(t, err)
	require.NotNil(t, verified)
	assert.Equal(t, FormatDICE, verified.Format)
	require.NotNil(t, verified.Leaf, "the verified alias certificate did not survive to finalization")

	// A key generated in software, presented beside the device's genuine
	// evidence. This is the certificate an attacker wants and must not get.
	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	err = verified.BindCSRKey(csrFor(t, software))
	require.Error(t, err, "a software key was certified against a device's attestation")
	assert.ErrorIs(t, err, attestation.ErrKeyNotBound)

	// The device's own key, which is the only one this evidence covers.
	require.NoError(t, verified.BindCSRKey(csrFor(t, aliasKey)))
}

// TestBindCSRKeyRefusesWhatItCannotCheck covers every way the gate can fail to
// run. None of them may read as the gate passing.
func TestBindCSRKeyRefusesWhatItCannotCheck(t *testing.T) {
	leafDER, aliasKey := newDICEAlias(t, DICENonce(diceKeyAuth))
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	verified := &VerifiedAttestation{
		Format:           FormatDICE,
		KeyAuthorization: diceKeyAuth,
		Leaf:             leaf,
	}

	t.Run("no verified attestation", func(t *testing.T) {
		var missing *VerifiedAttestation
		assert.ErrorIs(t, missing.BindCSRKey(csrFor(t, aliasKey)), ErrNoVerifiedAttestation)
	})

	t.Run("no certificate request", func(t *testing.T) {
		assert.ErrorIs(t, verified.BindCSRKey(nil), ErrKeyBindingUnavailable)
	})

	t.Run("a format with no csr binding", func(t *testing.T) {
		unknown := &VerifiedAttestation{Format: AttestationFormat("apple"), KeyAuthorization: diceKeyAuth, Leaf: leaf}
		assert.ErrorIs(t, unknown.BindCSRKey(csrFor(t, aliasKey)), ErrKeyBindingUnavailable)
	})

	t.Run("no verified leaf", func(t *testing.T) {
		leafless := &VerifiedAttestation{Format: FormatDICE, KeyAuthorization: diceKeyAuth}
		assert.ErrorIs(t, leafless.BindCSRKey(csrFor(t, aliasKey)), ErrKeyBindingUnavailable)
	})

	t.Run("a certificate request whose signature does not verify", func(t *testing.T) {
		// A CSR is self-signed by the key it names. Without that proof the
		// requester has not shown it holds the private half, so binding it to
		// attested hardware would certify a key nobody controls.
		csr := csrFor(t, aliasKey)
		csr.Signature[len(csr.Signature)-1] ^= 0xFF

		err := verified.BindCSRKey(csr)
		require.Error(t, err)
		assert.ErrorIs(t, err, attestation.ErrKeyNotBound)
	})

	t.Run("evidence that answered another challenge", func(t *testing.T) {
		// Freshness is re-checked at the gate rather than assumed from the
		// challenge, so a record carried forward against the wrong key
		// authorization is refused even though the SPKI matches.
		stale := &VerifiedAttestation{
			Format:           FormatDICE,
			KeyAuthorization: "another.keyauthorization",
			Leaf:             leaf,
		}
		err := stale.BindCSRKey(csrFor(t, aliasKey))
		require.Error(t, err)
		assert.ErrorIs(t, err, attestation.ErrStaleEvidence)
	})
}

// TestBindCSRKeySurvivesStorage is the record doing the job it exists for.
//
// The challenge and the finalize are two requests, so a server that is not a
// single process writes the record down in between. Only the bytes survive
// that trip: a parsed certificate does not, and a re-encoded one is a different
// document whose signature is over something else. The binding must hold on the
// far side of it, and must still refuse a software key there.
func TestBindCSRKeySurvivesStorage(t *testing.T) {
	leafDER, aliasKey := newDICEAlias(t, DICENonce(diceKeyAuth))
	object := &AttestationObject{
		Format:       string(FormatDICE),
		AttStatement: AttestationStatement{X5c: []interface{}{leafDER}},
	}
	host, port := serveAttestation(t, object)

	verified, err := VerifyAttestation(net.DefaultResolver, &mockCA{}, host, port, "token", diceKeyAuth)
	require.NoError(t, err)
	require.Equal(t, leafDER, verified.LeafDER, "the device's own bytes are what get written down")

	// What a store hands back: the fields that serialise, and no parsed
	// certificate.
	restored := &VerifiedAttestation{
		Format:           verified.Format,
		KeyAuthorization: verified.KeyAuthorization,
		LeafDER:          verified.LeafDER,
	}

	require.NoError(t, restored.BindCSRKey(csrFor(t, aliasKey)))

	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.ErrorIs(t, restored.BindCSRKey(csrFor(t, software)), attestation.ErrKeyNotBound)

	// Bytes that are not a certificate are a record that cannot be bound,
	// which must never read as a record that was.
	broken := &VerifiedAttestation{
		Format:           FormatDICE,
		KeyAuthorization: diceKeyAuth,
		LeafDER:          []byte{0x30, 0x00},
	}
	assert.ErrorIs(t, broken.BindCSRKey(csrFor(t, aliasKey)), ErrKeyBindingUnavailable)
}
