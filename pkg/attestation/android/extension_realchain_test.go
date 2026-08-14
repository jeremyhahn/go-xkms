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
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
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
