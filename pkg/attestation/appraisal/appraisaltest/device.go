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

package appraisaltest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
)

// AndroidKeyAttestation returns the DER chain (leaf first, root last) of an
// Android key attestation under root: a TEE-backed key generated in secure
// hardware for signing, whose boot claim is rot. A nil rot omits the claim.
func AndroidKeyAttestation(root *Authority, rot *android.RootOfTrust) ([][]byte, error) {
	return AndroidKeyAttestationFor(root, rot, FixtureApplication())
}

// FixtureApplicationPackage is the package FixtureApplication names.
const FixtureApplicationPackage = "com.example.appraisal"

// FixtureApplicationDigest is the hex SHA-256 signing-certificate digest
// FixtureApplication carries.
const FixtureApplicationDigest = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0"

// FixtureApplication is the attested application AndroidKeyAttestation's
// chains name: FixtureApplicationPackage signed with FixtureApplicationDigest.
func FixtureApplication() *android.AttestationApplicationID {
	digest, _ := hex.DecodeString(FixtureApplicationDigest)
	return &android.AttestationApplicationID{
		Packages:         []android.AttestationPackageInfo{{Name: FixtureApplicationPackage, Version: 1}},
		SignatureDigests: [][]byte{digest},
	}
}

// AndroidKeyAttestationFor is AndroidKeyAttestation naming appID as the
// attested application; a nil appID omits the application identity.
func AndroidKeyAttestationFor(root *Authority, rot *android.RootOfTrust, appID *android.AttestationApplicationID) ([][]byte, error) {
	ext, err := android.BuildAttestationExtensionWithOptions(4, android.SecurityLevelTrustedEnvironment,
		4, android.SecurityLevelTrustedEnvironment, []byte("appraisal-challenge"), nil,
		&android.AttestationExtensionOptions{
			RootOfTrust:   rot,
			Origin:        android.OriginGenerated,
			HasOrigin:     true,
			Purpose:       []int{android.PurposeSign},
			ApplicationID: appID,
		})
	if err != nil {
		return nil, &FixtureError{Step: "android attestation extension", Cause: err}
	}
	// local-keygen-ok: stands in for a key a handset's KeyMint generated; the Verifier only verifies its attestation.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &FixtureError{Step: "generate android key", Cause: err}
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(serial.Add(1)),
		Subject:         pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: android.AndroidKeyAttestationOID, Value: ext}},
	}
	leaf, err := createCertificate(tmpl, root.Certificate, &key.PublicKey, root.Key)
	if err != nil {
		return nil, err
	}
	return [][]byte{leaf.Raw, root.Certificate.Raw}, nil
}

// LockedVerifiedBoot is the boot claim of a handset with a locked bootloader
// running a verified boot chain.
func LockedVerifiedBoot() *android.RootOfTrust {
	return &android.RootOfTrust{
		VerifiedBootKey:   make([]byte, 32),
		DeviceLocked:      true,
		VerifiedBootState: android.VerifiedBootVerified,
		VerifiedBootHash:  make([]byte, 32),
	}
}

// EKCertificate issues a TPM endorsement key certificate under ca and
// returns its DER. withEKU controls whether it carries the
// tcg-kp-EKCertificate extended key usage a Verifier requires.
func EKCertificate(ca *Authority, withEKU bool) ([]byte, error) {
	// local-keygen-ok: stands in for a TPM-resident endorsement key, which no keystore of this stack holds.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &FixtureError{Step: "generate EK", Cause: err}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: "endorsement key " + strconv.FormatInt(serial.Load(), 10)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	if withEKU {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{evidence.OIDTCGKpEKCertificate}
	}
	cert, err := createCertificate(tmpl, ca.Certificate, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	return cert.Raw, nil
}
