// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xkms

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
)

// EKCertificatePermanentIdentifier is the hex SHA-256 of the certificate's DER,
// the identifier the enroll-01 activation record names a TPM by; the SDK
// re-export must be the pkg/ca function, and refuse what it refuses.
func TestEKCertificatePermanentIdentifier(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("a certificate's DER")}
	want := sha256.Sum256(cert.Raw)

	got, err := EKCertificatePermanentIdentifier(cert)
	if err != nil {
		t.Fatalf("EKCertificatePermanentIdentifier: %v", err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("identifier = %q, want %q", got, hex.EncodeToString(want[:]))
	}

	if _, err := EKCertificatePermanentIdentifier(nil); !errors.Is(err, ErrCATCGMissingEKCert) {
		t.Errorf("nil certificate: error = %v, want ErrCATCGMissingEKCert", err)
	}
}

// SignOptions.OtherNames is how an issuer asserts an identity it verified (an
// attested device's permanentIdentifier) in a certificate; it is reachable
// through the SDK's alias of the sign options.
var _ []OtherName = TrustedCASignOptions{}.OtherNames
