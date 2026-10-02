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

package trustedca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestEnroll01ProductionCAIsReachable pins the capability assertion that gates
// enroll-01 to the CA that production actually deploys.
//
// ACMEAttestationVerifiers reaches the CA through a runtime type assertion, so
// a CA that does not satisfy ACMEEnroll01TCGCSRVerifier does not fail to
// compile -- it returns ErrACMEEnrollCAUnsupported and the challenge is
// refused. That shipped: the interface declared sigAlg as interface{} while
// *ca.CA declares x509.SignatureAlgorithm, Go requires an exact method
// signature match, so the assertion failed on every deployment and TPM IDevID
// enrollment could not succeed. Only the enroll-01 package's own mock
// satisfied the interface, which is why its tests passed.
//
// This asserts the production type, not a mock, because a mock is what hid the
// bug.
func TestEnroll01ProductionCAIsReachable(t *testing.T) {
	var ca ACMECertificateAuthority = (*pkgca.CA)(nil)

	if _, ok := ca.(ACMEEnroll01TCGCSRVerifier); !ok {
		t.Fatal("*ca.CA does not satisfy ACMEEnroll01TCGCSRVerifier: " +
			"ACMEAttestationVerifiers will return ErrACMEEnrollCAUnsupported " +
			"for every enroll-01 challenge and TPM IDevID enrollment cannot succeed")
	}
}

// nonTCGCA is an ACMECertificateAuthority that deliberately does NOT implement
// the TCG-CSR-IDEVID surface, so the capability check must reject it.
type nonTCGCA struct{ ACMECertificateAuthority }

// TestACMEAttestationVerifiersCapabilityCheck drives the verifier closure the
// ACME server installs and pins both directions of its capability check.
//
// The negative direction proves the check is live: a CA lacking the surface is
// refused with ErrACMEEnrollCAUnsupported. The positive direction proves the
// production CA clears it -- the closure gets past the assertion and into
// enroll01.Verify, whose own failure (no TPM-backed client answers here) is a
// different error. Distinguishing those two failures is the whole point: the
// shipped bug made every enroll-01 challenge take the negative path.
//
// No I/O: the assertion runs before enroll01.Verify is reached, and a
// challenge client whose resolver answers nothing keeps the positive case
// off the network.
func TestACMEAttestationVerifiersCapabilityCheck(t *testing.T) {
	client := NewACMEChallengeClient(ACMEChallengeClientConfig{Resolver: offlineResolver(t)})
	verifiers := ACMEAttestationVerifiers(client, true, false)

	verify, ok := verifiers[ACMEChallengeTypeEnroll01]
	if !ok {
		t.Fatal("enroll-01 verifier not registered when enroll is enabled")
	}

	t.Run("CA without the TCG surface is refused", func(t *testing.T) {
		err := verify(offlineResolver(t), nonTCGCA{}, "device.example.com", "8443", "token", "expected")
		if !errors.Is(err, ErrACMEEnrollCAUnsupported) {
			t.Fatalf("capability check is not enforced: got %v, want ErrACMEEnrollCAUnsupported", err)
		}
	})

	t.Run("production CA clears the check", func(t *testing.T) {
		err := verify(offlineResolver(t), (*pkgca.CA)(nil), "device.example.com", "8443", "token", "expected")
		if errors.Is(err, ErrACMEEnrollCAUnsupported) {
			t.Fatal("enroll-01 refused the production CA as unsupported; " +
				"the capability assertion is failing and TPM IDevID enrollment cannot succeed")
		}
	})
}

// offlineResolver returns a resolver whose dial always fails, so a test that
// gets past the capability check cannot reach the network.
func offlineResolver(t *testing.T) *net.Resolver {
	t.Helper()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errOfflineResolver
		},
	}
}

var errOfflineResolver = errors.New("acme test: resolver is offline by design")

// TestACMEDeviceIdentityFromCertificate_DICEAndRefusal exercises the SDK
// alias of the identity rule: a DICE leaf's Ueid is the identity, a leaf with
// none is ACMEErrDeviceIdentityUnavailable.
func TestACMEDeviceIdentityFromCertificate_DICEAndRefusal(t *testing.T) {
	ueid, err := dice.CreateUeidExtension([]byte{0xCA, 0xFE})
	if err != nil {
		t.Fatal(err)
	}
	leaf := selfSignedLeaf(t, ueid)
	got, err := ACMEDeviceIdentityFromCertificate(ACMEDeviceAttestFormatDICE, leaf)
	if err != nil || got != "cafe" {
		t.Fatalf("got (%q, %v), want (\"cafe\", nil)", got, err)
	}

	_, err = ACMEDeviceIdentityFromCertificate(ACMEDeviceAttestFormatDICE, selfSignedLeaf(t))
	if !errors.Is(err, ACMEErrDeviceIdentityUnavailable) {
		t.Fatalf("got %v, want ACMEErrDeviceIdentityUnavailable", err)
	}
}

func selfSignedLeaf(t *testing.T, extensions ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "leaf"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
