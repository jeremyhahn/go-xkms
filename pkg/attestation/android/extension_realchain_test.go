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

package android

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// loadRealChain reads the captured emulator attestation chain, leaf first.
func loadRealChain(t *testing.T) []*x509.Certificate {
	t.Helper()

	f, err := os.Open("testdata/android_emulator_chain.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	var chain []*x509.Certificate
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		der, decErr := base64.StdEncoding.DecodeString(line)
		if decErr != nil {
			t.Fatalf("decode fixture line: %v", decErr)
		}
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			t.Fatalf("parse fixture certificate: %v", parseErr)
		}
		chain = append(chain, cert)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("fixture contained no certificates")
	}
	return chain
}

// realChainVerificationTime sits inside the captured chain's validity window
// (2026-08-05 00:55 UTC to 2026-08-21 00:43 UTC). Google's test attestation CA
// mints short-lived intermediates, so the window closes about sixteen days
// after any capture; re-capturing the fixture would only reset the countdown.
var realChainVerificationTime = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

// TestVerifyKeyAttestation_HonoursTheVerificationTime covers both directions of
// VerifyOptions.CurrentTime.
//
// The pinned direction uses the captured chain, because only real evidence can
// show the option working on a window somebody else chose. The default
// direction uses a certificate minted here with a window that has already
// closed relative to whatever time.Now() returns -- not the captured chain,
// whose expiry is a fixed date the host clock would have to be past. Assuming
// something about the calendar is the defect this change removes, and it is no
// better inverted.
func TestVerifyKeyAttestation_HonoursTheVerificationTime(t *testing.T) {
	t.Run("verifies the captured chain at a pinned time inside its window", func(t *testing.T) {
		chain := loadRealChain(t)
		roots := x509.NewCertPool()
		roots.AddCert(chain[len(chain)-1])

		_, err := VerifyKeyAttestation(chain, &VerifyOptions{
			TrustedRoots:     roots,
			MinSecurityLevel: SecurityLevelSoftware,
			CurrentTime:      realChainVerificationTime,
		})
		if err != nil {
			t.Fatalf("verify at %s: %v", realChainVerificationTime, err)
		}
	})

	// Valid from two days ago until one day ago: expired now, and expired on
	// any clock this ever runs on.
	expired := makeExpiredAttestationCert(t,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	expiredRoots := x509.NewCertPool()
	expiredRoots.AddCert(expired)

	t.Run("refuses expired evidence when the time is unset", func(t *testing.T) {
		_, err := VerifyKeyAttestation([]*x509.Certificate{expired}, &VerifyOptions{
			TrustedRoots:     expiredRoots,
			MinSecurityLevel: SecurityLevelSoftware,
		})
		if err == nil {
			t.Fatal("an unset CurrentTime must verify against now, and this certificate has expired")
		}
		if !errors.Is(err, ErrChainVerificationFailed) {
			t.Fatalf("error = %v, want ErrChainVerificationFailed", err)
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("error = %v, want it to name the expiry", err)
		}
	})

	t.Run("accepts the same evidence at a time inside its window", func(t *testing.T) {
		_, err := VerifyKeyAttestation([]*x509.Certificate{expired}, &VerifyOptions{
			TrustedRoots:     expiredRoots,
			MinSecurityLevel: SecurityLevelSoftware,
			CurrentTime:      time.Now().Add(-36 * time.Hour),
		})
		if err != nil {
			t.Fatalf("verify inside the window: %v", err)
		}
	})
}

// makeExpiredAttestationCert mints a self-signed certificate carrying a minimal
// attestation extension, valid only between notBefore and notAfter. It is both
// leaf and trust anchor, so a single-certificate chain exercises the temporal
// check without anything else standing in the way.
func makeExpiredAttestationCert(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ext, err := BuildMinimalAttestationExtension(
		3, SecurityLevelSoftware, 4, SecurityLevelSoftware, []byte("expiry-fixture"), nil)
	if err != nil {
		t.Fatalf("build attestation extension: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "Expired Attestation"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{{
			Id:    AndroidKeyAttestationOID,
			Value: ext,
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestParseKeyAttestation_RealEmulatorChain parses an attestation produced by a
// real device rather than one assembled by these tests.
//
// This is the only fixture that can tell a correct parser from a lenient one.
// The hand-built ones encode RootOfTrust under context tag 0 while every real
// device uses 704, so a parser that matched any context-specific SEQUENCE it
// could decode passed them and would also have accepted a neighbouring entry as
// a boot state that was never attested.
func TestParseKeyAttestation_RealEmulatorChain(t *testing.T) {
	chain := loadRealChain(t)

	desc, err := ParseKeyAttestation(chain[0])
	if err != nil {
		t.Fatalf("parse real attestation: %v", err)
	}

	if got := string(desc.AttestationChallenge); got != "xkey-fixture-challenge" {
		t.Errorf("challenge = %q, want %q", got, "xkey-fixture-challenge")
	}

	// An emulator has no TEE keymaster, so everything lands in softwareEnforced
	// and the security level is software. A parser that only ever looked at
	// teeEnforced would silently find nothing here.
	if desc.AttestationSecurityLevel != SecurityLevelSoftware {
		t.Errorf("security level = %v, want software", desc.AttestationSecurityLevel)
	}

	rot := desc.SoftwareEnforced.RootOfTrust
	if rot == nil {
		t.Fatal("RootOfTrust absent; tag 704 was not found in softwareEnforced")
	}
	if rot.DeviceLocked {
		t.Error("an emulator must report an unlocked bootloader")
	}
	if rot.VerifiedBootState != VerifiedBootUnverified {
		t.Errorf("verified boot state = %v, want unverified", rot.VerifiedBootState)
	}
}

// TestParseKeyAttestation_RealChainOriginAndPurpose is genuine ASN.1 this
// suite did not build, so it is the one fixture that can catch findOrigin and
// findPurpose reading the wrong tag rather than merely one this test chose to
// encode correctly (go-xkms#132).
//
// An emulator has no TEE keymaster, so the key was generated and authorized
// for SIGN in *software*, not in secure hardware -- and the parser must
// report exactly that distinction: a real claim under softwareEnforced, and
// no claim at all under teeEnforced.
func TestParseKeyAttestation_RealChainOriginAndPurpose(t *testing.T) {
	chain := loadRealChain(t)

	desc, err := ParseKeyAttestation(chain[0])
	if err != nil {
		t.Fatalf("parse real attestation: %v", err)
	}

	if desc.SoftwareEnforced.Origin != OriginGenerated {
		t.Errorf("softwareEnforced origin = %d, want OriginGenerated (%d)",
			desc.SoftwareEnforced.Origin, OriginGenerated)
	}
	if len(desc.SoftwareEnforced.Purpose) != 1 || desc.SoftwareEnforced.Purpose[0] != PurposeSign {
		t.Errorf("softwareEnforced purpose = %v, want [PurposeSign]", desc.SoftwareEnforced.Purpose)
	}

	// The claim this fixture's key actually makes lives in softwareEnforced,
	// which go-xkms#132's check must never accept as a substitute for a
	// TEE-enforced one. teeEnforced must show NO claim -- OriginUnknown, not
	// OriginGenerated by coincidence of the zero value -- because this
	// emulator has no secure hardware to make one.
	if desc.TeeEnforced.Origin != OriginUnknown {
		t.Errorf("teeEnforced origin = %d, want OriginUnknown (%d): an emulator's TEE makes no claim",
			desc.TeeEnforced.Origin, OriginUnknown)
	}
	if len(desc.TeeEnforced.Purpose) != 0 {
		t.Errorf("teeEnforced purpose = %v, want none", desc.TeeEnforced.Purpose)
	}
}

// TestParseKeyAttestation_RealChainCarriesApplicationIdentity proves the field
// the enterprise CA's allow-list is built on actually decodes.
//
// attestationApplicationId is what distinguishes "an Android device" from "this
// application on an Android device". The application cannot set it -- the
// Keystore daemon does -- so a repackaged build signed with another key carries
// a different digest and cannot pass as the real one.
func TestParseKeyAttestation_RealChainCarriesApplicationIdentity(t *testing.T) {
	chain := loadRealChain(t)

	desc, err := ParseKeyAttestation(chain[0])
	if err != nil {
		t.Fatalf("parse real attestation: %v", err)
	}

	appID := desc.SoftwareEnforced.AttestationApplicationID
	if appID == nil {
		t.Fatal("AttestationApplicationID absent; tag 709 was not decoded")
	}

	if len(appID.Packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(appID.Packages))
	}
	if got := appID.Packages[0].Name; got != "com.automatethethings.xkey.debug" {
		t.Errorf("package = %q, want com.automatethethings.xkey.debug", got)
	}

	if len(appID.SignatureDigests) != 1 {
		t.Fatalf("signature digests = %d, want 1", len(appID.SignatureDigests))
	}
	digest := hex.EncodeToString(appID.SignatureDigests[0])
	const wantDigest = "471812d11ee2279da7a6957997c7b66a2d1fd8ccbba106f5fbf9c4c024a30aba"
	if digest != wantDigest {
		t.Errorf("signing digest = %s, want %s", digest, wantDigest)
	}
	if len(appID.SignatureDigests[0]) != 32 {
		t.Errorf("digest length = %d, want 32 (SHA-256)", len(appID.SignatureDigests[0]))
	}
}

// TestFindRootOfTrust_IgnoresAForeignTagThatHappensToDecode is the regression
// guard for the leniency the real chain exposed.
//
// Several AuthorizationList entries are context-specific SEQUENCEs, and
// rootOfTrustASN1 is structurally unremarkable -- an OCTET STRING, a BOOLEAN,
// an ENUMERATED, an OCTET STRING. Accepting the first element that decoded
// meant an unrelated entry could be reported as an attested boot state, which
// is worse than reporting none: a caller checking DeviceLocked would be
// reading a field the TEE never asserted.
func TestFindRootOfTrust_IgnoresAForeignTagThatHappensToDecode(t *testing.T) {
	wellFormed := rootOfTrustASN1{
		VerifiedBootKey:   make([]byte, 32),
		DeviceLocked:      true,
		VerifiedBootState: 0,
		VerifiedBootHash:  make([]byte, 32),
	}
	body, err := asn1.Marshal(wellFormed)
	if err != nil {
		t.Fatalf("marshal RootOfTrust body: %v", err)
	}

	// Tag 706 is osPatchLevel, not rootOfTrust. The bytes below would parse
	// happily as a RootOfTrust, which is exactly the trap.
	imposter, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        706,
		IsCompound: true,
		Bytes:      body,
	})
	if err != nil {
		t.Fatalf("marshal imposter: %v", err)
	}

	outer, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      imposter,
	})
	if err != nil {
		t.Fatalf("marshal outer SEQUENCE: %v", err)
	}

	if got := findRootOfTrust(outer); got != nil {
		t.Errorf("tag 706 was accepted as a RootOfTrust reporting DeviceLocked=%v; "+
			"only tag 704 may be", got.DeviceLocked)
	}
}
