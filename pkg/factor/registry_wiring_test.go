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

package factor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/factor/mtls"
	"github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	"github.com/jeremyhahn/go-xkms/pkg/factor/pkcs11"
)

// pkixPublicKeyDER returns a fresh P-256 public key in PKIX DER form, the
// enrollment input the PKCS#11 factor expects.
func pkixPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// enrollmentShell returns the smallest enrollment every factor's Challenge
// accepts: no ttl override, and a self-signed certificate as the public key,
// which the mtls factor parses to put the enrolled key in the challenge.
func enrollmentShell(t *testing.T) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "user-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return &qrdbsdk.AuthFactorEnrollment{
		EnrollmentID: "enr-1",
		PublicKey:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Metadata:     map[string]string{},
	}
}

// TestNewDefaultRegistry_ConfigReachesTheFactorInstances is the behavioral
// counterpart to the existing name-based checks. It proves each Config field
// is threaded into the factor it belongs to by observing the resulting
// enrollment and challenge, so a regression that dropped a field — or wired
// PKCS11Mechanism into the wrong constructor — fails here instead of shipping
// factors that silently ignore operator configuration.
func TestNewDefaultRegistry_ConfigReachesTheFactorInstances(t *testing.T) {
	const (
		// wantMechanism must stay in the ECDSA family: pkixPublicKeyDER below
		// enrolls a P-256 key, and the factor now refuses an enrollment whose
		// mechanism names a different key algorithm (#1289). It only needs to
		// differ from the factor's own default (CKM_ECDSA_SHA256) to prove
		// this value, and not the default, reached the enrollment.
		wantMechanism = "CKM_ECDSA_SHA384"
		wantRPID      = "ca.example.com"
		wantTTL       = 120
	)
	ctx := context.Background()

	registry, err := NewDefaultRegistry(Config{
		PKCS11Mechanism:     wantMechanism,
		FIDO2RPID:           wantRPID,
		ChallengeTTLSeconds: wantTTL,
	})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}

	t.Run("pkcs11 mechanism and ttl", func(t *testing.T) {
		plugin, err := registry.Lookup(pkcs11.FactorName)
		if err != nil {
			t.Fatalf("Lookup(pkcs11): %v", err)
		}
		enrollment, err := plugin.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
			UserID:       "user-1",
			MethodParams: map[string]any{"public_key_der": pkixPublicKeyDER(t)},
		})
		if err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		if got := enrollment.Metadata["mechanism"]; got != wantMechanism {
			t.Errorf("mechanism = %q, want %q (Config.PKCS11Mechanism was not applied)", got, wantMechanism)
		}
		if got := enrollment.Metadata["ttl"]; got != "120" {
			t.Errorf("ttl = %q, want 120 (Config.ChallengeTTLSeconds was not applied)", got)
		}

		challenge, err := plugin.Challenge(ctx, enrollment)
		if err != nil {
			t.Fatalf("Challenge: %v", err)
		}
		assertTTLNear(t, challenge, wantTTL)
	})

	t.Run("fido2 relying party id", func(t *testing.T) {
		plugin, err := registry.Lookup(fido2.FactorName)
		if err != nil {
			t.Fatalf("Lookup(fido2): %v", err)
		}
		// The RP id is recorded on the enrollment; a wrong value makes every
		// browser assertion fail origin validation.
		enrollment, err := plugin.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
			UserID: "user-1",
			MethodParams: map[string]any{
				"cose_public_key": es256COSEKey(t),
				"credential_id":   "Y3JlZC1pZA",
			},
		})
		if err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		if got := enrollment.Metadata["rp_id"]; got != wantRPID {
			t.Errorf("rp_id = %q, want %q (Config.FIDO2RPID was not applied)", got, wantRPID)
		}
		if got := enrollment.Metadata["ttl"]; got != "120" {
			t.Errorf("ttl = %q, want 120", got)
		}
	})

	t.Run("mtls and piv inherit the challenge ttl", func(t *testing.T) {
		for _, name := range []string{mtls.FactorName, piv.FactorName} {
			plugin, err := registry.Lookup(name)
			if err != nil {
				t.Fatalf("Lookup(%s): %v", name, err)
			}
			// Challenge only needs an enrollment shell; the ttl comes from the
			// factor config when the enrollment carries no override.
			shell := enrollmentShell(t)
			shell.FactorName = name
			challenge, err := plugin.Challenge(ctx, shell)
			if err != nil {
				t.Fatalf("%s Challenge: %v", name, err)
			}
			assertTTLNear(t, challenge, wantTTL)
		}
	})
}

// TestNewDefaultRegistry_ZeroConfigUsesFactorDefaults proves the zero Config
// is genuinely usable — the documented contract — rather than producing
// factors with a zero TTL, which would make every challenge expire instantly.
func TestNewDefaultRegistry_ZeroConfigUsesFactorDefaults(t *testing.T) {
	ctx := context.Background()
	registry, err := NewDefaultRegistry(Config{})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}

	for _, name := range []string{piv.FactorName, pkcs11.FactorName, mtls.FactorName} {
		plugin, err := registry.Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%s): %v", name, err)
		}
		challenge, err := plugin.Challenge(ctx, enrollmentShell(t))
		if err != nil {
			t.Fatalf("%s Challenge: %v", name, err)
		}
		if ttl := time.Until(challenge.ExpiresAt); ttl <= 0 {
			t.Errorf("%s: zero Config produced an already-expired challenge (ttl %v)", name, ttl)
		}
		if len(challenge.Nonce) == 0 {
			t.Errorf("%s: challenge has an empty nonce", name)
		}
	}
}

// TestDefaultFactors_ProducesIndependentInstances guards against a shared
// package-level factor being handed out: two calls must yield distinct
// instances so per-tenant configurations cannot bleed into each other.
func TestDefaultFactors_ProducesIndependentInstances(t *testing.T) {
	a := DefaultFactors(Config{ChallengeTTLSeconds: 60})
	b := DefaultFactors(Config{ChallengeTTLSeconds: 600})
	if len(a) != len(b) {
		t.Fatalf("DefaultFactors returned %d and %d factors", len(a), len(b))
	}
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("DefaultFactors[%d] (%s) returned the same instance for two different configs", i, a[i].Name())
		}
	}

	ctx := context.Background()
	shell := enrollmentShell(t)
	shortC, err := a[3].Challenge(ctx, shell)
	if err != nil {
		t.Fatalf("Challenge (short ttl): %v", err)
	}
	longC, err := b[3].Challenge(ctx, shell)
	if err != nil {
		t.Fatalf("Challenge (long ttl): %v", err)
	}
	if !longC.ExpiresAt.After(shortC.ExpiresAt) {
		t.Errorf("the 600s factor expires at %v, not after the 60s factor at %v — the configs were shared",
			longC.ExpiresAt, shortC.ExpiresAt)
	}
}

// TestNewDefaultRegistry_NamesAreUnique documents why NewDefaultRegistry's
// error branch is unreachable through the public API: registration fails only
// on a duplicate name, and the canonical set has four distinct ones. If a new
// factor is ever added with a colliding name this test catches it before the
// silently-dropped registration reaches production.
func TestNewDefaultRegistry_NamesAreUnique(t *testing.T) {
	seen := map[string]int{}
	for i, f := range DefaultFactors(Config{}) {
		name := f.Name()
		if name == "" {
			t.Fatalf("DefaultFactors[%d] has an empty name", i)
		}
		if prev, dup := seen[name]; dup {
			t.Fatalf("DefaultFactors[%d] and [%d] both use the name %q; registration would fail", prev, i, name)
		}
		seen[name] = i
	}
}

// assertTTLNear checks a challenge expires roughly wantSeconds from now,
// allowing a few seconds of slack for test scheduling.
func assertTTLNear(t *testing.T, challenge *qrdbsdk.AuthFactorChallenge, wantSeconds int) {
	t.Helper()
	ttl := time.Until(challenge.ExpiresAt)
	want := time.Duration(wantSeconds) * time.Second
	if ttl > want+5*time.Second || ttl < want-5*time.Second {
		t.Errorf("challenge ttl = %v, want approximately %v", ttl, want)
	}
}

// es256COSEKey builds an ES256 COSE_Key for a fresh P-256 credential, the
// enrollment input the FIDO2 factor validates before recording it.
func es256COSEKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	point := ecdhPub.Bytes()
	key := map[int]interface{}{
		1:  2,
		3:  int(webauthncose.AlgES256),
		-1: 1,
		-2: point[1:33],
		-3: point[33:65],
	}
	encoded, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	return encoded
}
