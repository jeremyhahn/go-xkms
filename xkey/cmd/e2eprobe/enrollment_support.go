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

package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"os"
	"strings"

	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	flynnNoise "github.com/flynn/noise"
	pairing "github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"math/big"
	"strconv"
	"time"

	android "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
)

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// bytesEqual compares in constant time.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// parseChallenge reads the attestation challenge out of the leaf.
func parseChallenge(leaf *x509.Certificate) ([]byte, error) {
	desc, err := android.ParseKeyAttestation(leaf)
	if err != nil {
		return nil, err
	}
	return desc.AttestationChallenge, nil
}

// csrBindsToLeaf confirms the CSR asks for the key the attestation covers.
func csrBindsToLeaf(csrDER []byte, leaf *x509.Certificate) error {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(
		csr.RawSubjectPublicKeyInfo,
		leaf.RawSubjectPublicKeyInfo,
	) != 1 {
		return &MessageError{Msg: "the CSR key is not the attested key"}
	}
	return nil
}

// issueProbeCredential signs the phone's CSR with a throwaway CA.
//
// The probe is testing the exchange, not the CA: what matters is that the
// phone accepts a certificate genuinely made for its own key, and would refuse
// one that was not. A real enrolment routes this through `xkey device
// enroll-phone`, which applies EnrollmentPolicy first.
func issueProbeCredential(csrDER []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2eprobe throwaway CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, leafTemplate, caCert, csr.PublicKey, caKey)
}

// probeStaticKey loads the probe's Noise static key.
//
// XKEY_PROBE_STATIC_KEY supplies a fixed base64 private key so the phone can be
// told about this peer in advance; without it a fresh key is generated and the
// phone will ask a human to approve the pairing.
func probeStaticKey() (*flynnNoise.DHKey, error) {
	encoded := strings.TrimSpace(os.Getenv("XKEY_PROBE_STATIC_KEY"))
	if encoded == "" {
		return pairing.GenerateStaticKey()
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return pairing.LoadStaticKey(raw)
}
