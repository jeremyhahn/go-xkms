// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package backend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errBackendDown is the sentinel a failing resolver/provider surfaces so the
// tests can prove the provider preserves the underlying cause through its
// typed error wrappers (callers use errors.Is to distinguish a transient
// backend outage from a permanent misconfiguration).
var errBackendDown = errors.New("backend is down")

// recordingProvider wraps a real types.KeyProvider, recording the attributes
// the Provider builds and optionally forcing failures on individual methods.
// It embeds the interface so it stays source-compatible if KeyProvider grows.
type recordingProvider struct {
	types.KeyProvider

	backendType types.BackendType

	generated []*types.KeyAttributes
	signed    []*types.KeyAttributes
	deleted   []*types.KeyAttributes

	failGenerate error
	failSigner   error
	failDelete   error
}

func (r *recordingProvider) Type() types.BackendType {
	if r.backendType != "" {
		return r.backendType
	}
	return r.KeyProvider.Type()
}

func (r *recordingProvider) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.generated = append(r.generated, attrs)
	if r.failGenerate != nil {
		return nil, r.failGenerate
	}
	return r.KeyProvider.GenerateKey(ctx, attrs)
}

func (r *recordingProvider) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	r.signed = append(r.signed, attrs)
	if r.failSigner != nil {
		return nil, r.failSigner
	}
	return r.KeyProvider.Signer(ctx, attrs)
}

func (r *recordingProvider) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	r.deleted = append(r.deleted, attrs)
	if r.failDelete != nil {
		return r.failDelete
	}
	return r.KeyProvider.DeleteKey(ctx, attrs)
}

// newRecordingResolver returns a Provider whose single backend is a recording
// wrapper around the in-memory software backend, plus the recorder itself.
func newRecordingResolver(t *testing.T, rec *recordingProvider) *Provider {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	rec.KeyProvider = kp
	p, err := New(ResolverFunc(func(context.Context, string) (types.KeyProvider, error) {
		return rec, nil
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// TestProvider_ECDSASignaturesAreASN1DER pins the crypto.Signer contract for
// every ECDSA curve the package advertises: Sign must return an ASN.1 DER
// SEQUENCE{r,s}, never a raw IEEE-P1363 r||s concatenation.
//
// This is a regression guard for the class of bug previously found in the
// Azure Key Vault backend, where the cloud KMS returned P1363 and the raw
// bytes were handed back unconverted. x/crypto/ssh's ssh.NewSignerFromSigner
// unconditionally reinterprets the Sign output as DER when building the SSH
// wire signature, so a P1363 regression yields a silently unverifiable SSH
// signature rather than an error at signing time.
func TestProvider_ECDSASignaturesAreASN1DER(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		algo    keys.Algorithm
		curve   elliptic.Curve
		newHash func() hash.Hash
		hashID  crypto.Hash
	}{
		{keys.AlgorithmECDSAP256, elliptic.P256(), sha256.New, crypto.SHA256},
		{keys.AlgorithmECDSAP384, elliptic.P384(), sha512.New384, crypto.SHA384},
		{keys.AlgorithmECDSAP521, elliptic.P521(), sha512.New, crypto.SHA512},
	}

	for _, tc := range cases {
		t.Run(tc.algo.String(), func(t *testing.T) {
			signer, err := p.GenerateKey(ctx, "software", "ssh-user-der-"+tc.algo.String(), tc.algo, 0)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			pub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", signer.Public())
			}
			if pub.Curve != tc.curve {
				t.Fatalf("expected curve %s, got %s", tc.curve.Params().Name, pub.Curve.Params().Name)
			}

			h := tc.newHash()
			h.Write([]byte("der contract"))
			digest := h.Sum(nil)

			sig, err := signer.Sign(rand.Reader, digest, tc.hashID)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// A raw P1363 signature is exactly 2*byteLen(curve); DER is a
			// SEQUENCE and starts with 0x30. Both checks fail loudly on a
			// P1363 regression.
			byteLen := (tc.curve.Params().BitSize + 7) / 8
			if len(sig) == 2*byteLen {
				t.Fatalf("signature length %d equals raw IEEE-P1363 size for %s; expected ASN.1 DER", len(sig), tc.curve.Params().Name)
			}
			if sig[0] != 0x30 {
				t.Fatalf("signature does not begin with an ASN.1 SEQUENCE tag (0x30); got 0x%02x", sig[0])
			}

			var parsed struct{ R, S *big.Int }
			if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
				t.Fatalf("signature is not a valid ASN.1 ECDSA signature: %v", err)
			}
			if !ecdsa.Verify(pub, digest, parsed.R, parsed.S) {
				t.Fatal("ecdsa.Verify rejected the parsed (r,s) — signature encoding or key mismatch")
			}
			if !ecdsa.VerifyASN1(pub, digest, sig) {
				t.Fatal("ecdsa.VerifyASN1 rejected the DER signature")
			}
		})
	}
}

// TestProvider_SSHSignVerifyAllAlgorithms drives every advertised algorithm
// through the full SSH wire path — generate on the backend, marshal the
// public key, sign via x/crypto/ssh, verify — and then proves the signature
// is bound to the payload by flipping one byte of the message and one byte of
// the signature blob. Without the tamper checks a broken Verify that always
// returned nil would pass.
func TestProvider_SSHSignVerifyAllAlgorithms(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		algo      keys.Algorithm
		wantWire  string
		wantSigFm string
	}{
		{keys.AlgorithmEd25519, ssh.KeyAlgoED25519, ssh.KeyAlgoED25519},
		{keys.AlgorithmECDSAP256, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA256},
		{keys.AlgorithmECDSAP384, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA384},
		{keys.AlgorithmECDSAP521, ssh.KeyAlgoECDSA521, ssh.KeyAlgoECDSA521},
		{keys.AlgorithmRSA, ssh.KeyAlgoRSA, ssh.KeyAlgoRSA},
	}

	for _, tc := range cases {
		t.Run(tc.algo.String(), func(t *testing.T) {
			keyID := "ssh-user-wire-" + tc.algo.String()
			signer, err := p.GenerateKey(ctx, "software", keyID, tc.algo, 2048)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sshPub, err := ssh.NewPublicKey(signer.Public())
			if err != nil {
				t.Fatalf("ssh.NewPublicKey: %v", err)
			}
			if sshPub.Type() != tc.wantWire {
				t.Fatalf("public key wire type = %q, want %q", sshPub.Type(), tc.wantWire)
			}

			// Round-trip the public key through the authorized_keys encoding
			// so an encoding regression in the generated key is caught.
			reparsed, _, _, _, err := ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(sshPub))
			if err != nil {
				t.Fatalf("ParseAuthorizedKey(MarshalAuthorizedKey(pub)): %v", err)
			}
			if reparsed.Type() != sshPub.Type() {
				t.Fatalf("reparsed key type %q != %q", reparsed.Type(), sshPub.Type())
			}

			sshSigner, err := ssh.NewSignerFromSigner(signer)
			if err != nil {
				t.Fatalf("ssh.NewSignerFromSigner: %v", err)
			}
			msg := []byte("ssh session identifier payload")
			sig, err := sshSigner.Sign(rand.Reader, msg)
			if err != nil {
				// "ssh-rsa" is RFC 4253's original RSA signature format,
				// which signs with SHA-1; x/crypto/ssh's default Sign (as
				// opposed to SignWithAlgorithm requesting rsa-sha2-256/512)
				// refuses it outright under GODEBUG=fips140=only with its
				// own typed error, not a panic.
				if tc.algo == keys.AlgorithmRSA && fips140.Enforced() {
					return
				}
				t.Fatalf("Sign: %v", err)
			}
			if sig.Format != tc.wantSigFm {
				t.Fatalf("signature format = %q, want %q", sig.Format, tc.wantSigFm)
			}
			if err := reparsed.Verify(msg, sig); err != nil {
				t.Fatalf("Verify with reparsed public key: %v", err)
			}

			// Tampered payload must not verify.
			tampered := append([]byte(nil), msg...)
			tampered[0] ^= 0xFF
			if err := reparsed.Verify(tampered, sig); err == nil {
				t.Fatal("Verify accepted a tampered payload")
			}

			// Tampered signature blob must not verify.
			badSig := &ssh.Signature{Format: sig.Format, Blob: append([]byte(nil), sig.Blob...)}
			badSig.Blob[len(badSig.Blob)-1] ^= 0xFF
			if err := reparsed.Verify(msg, badSig); err == nil {
				t.Fatal("Verify accepted a tampered signature blob")
			}
		})
	}
}

// TestProvider_CrossKeyVerificationFails proves each generated key is
// independent: a signature made by one key must not verify under another
// key of the same algorithm. A backend that silently reused a single key for
// every CN (a real hazard when the CN is not threaded into the attributes)
// would pass a naive round-trip test but fail here.
func TestProvider_CrossKeyVerificationFails(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, algo := range []keys.Algorithm{keys.AlgorithmEd25519, keys.AlgorithmECDSAP256} {
		t.Run(algo.String(), func(t *testing.T) {
			a, err := p.GenerateKey(ctx, "software", "ssh-user-xkey-a-"+algo.String(), algo, 0)
			if err != nil {
				t.Fatalf("GenerateKey a: %v", err)
			}
			b, err := p.GenerateKey(ctx, "software", "ssh-user-xkey-b-"+algo.String(), algo, 0)
			if err != nil {
				t.Fatalf("GenerateKey b: %v", err)
			}

			pubA, err := ssh.NewPublicKey(a.Public())
			if err != nil {
				t.Fatalf("NewPublicKey a: %v", err)
			}
			pubB, err := ssh.NewPublicKey(b.Public())
			if err != nil {
				t.Fatalf("NewPublicKey b: %v", err)
			}
			if string(pubA.Marshal()) == string(pubB.Marshal()) {
				t.Fatal("two distinct key IDs produced identical public keys")
			}

			signerB, err := ssh.NewSignerFromSigner(b)
			if err != nil {
				t.Fatalf("NewSignerFromSigner b: %v", err)
			}
			msg := []byte("cross-key check")
			sig, err := signerB.Sign(rand.Reader, msg)
			if err != nil {
				t.Fatalf("Sign b: %v", err)
			}
			if err := pubA.Verify(msg, sig); err == nil {
				t.Fatal("key A verified a signature made by key B")
			}
			if err := pubB.Verify(msg, sig); err != nil {
				t.Fatalf("key B failed to verify its own signature: %v", err)
			}
		})
	}
}

// TestProvider_Ed25519PublicKeyShape asserts the Ed25519 path yields a real
// 32-byte ed25519.PublicKey rather than an interface holding another type —
// the SSH agent and authorized_keys writers both depend on this.
func TestProvider_Ed25519PublicKeyShape(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	signer, err := p.GenerateKey(ctx, "software", "ssh-user-ed-shape", keys.AlgorithmEd25519, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", signer.Public())
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("ed25519 public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Ed25519 signs the message directly (crypto.Hash(0)).
	msg := []byte("ed25519 direct sign")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519.Verify rejected the backend signature")
	}
	msg[0] ^= 0xFF
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519.Verify accepted a tampered message")
	}
}

// TestProvider_RSABitsHonoredAndDefaulted proves the rsaBits argument reaches
// the backend and that a zero value defaults to RSA-4096 rather than to an
// unsafe small modulus (Go's rsa.GenerateKey has no default, so a regression
// here becomes a hard failure or a weak key).
func TestProvider_RSABitsHonoredAndDefaulted(t *testing.T) {
	ctx := context.Background()
	rec := &recordingProvider{}
	p := newRecordingResolver(t, rec)

	// Explicit 2048.
	signer, err := p.GenerateKey(ctx, "software", "ssh-user-rsa-2048", keys.AlgorithmRSA, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(2048): %v", err)
	}
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", signer.Public())
	}
	if got := pub.N.BitLen(); got != 2048 {
		t.Fatalf("explicit rsaBits=2048 produced a %d-bit modulus", got)
	}

	// Zero defaults to the package default.
	if len(rec.generated) == 0 {
		t.Fatal("recording provider saw no GenerateKey call")
	}
	attrs, err := buildAttrs("ssh-user-rsa-default", keys.AlgorithmRSA, 0, rec)
	if err != nil {
		t.Fatalf("buildAttrs: %v", err)
	}
	if attrs.RSAAttributes == nil {
		t.Fatal("RSAAttributes not populated for the RSA algorithm")
	}
	if attrs.RSAAttributes.KeySize != types.RSAKeySize4096 {
		t.Fatalf("rsaBits=0 defaulted to %d, want %d", attrs.RSAAttributes.KeySize, types.RSAKeySize4096)
	}
	if got := rec.generated[0].RSAAttributes.KeySize; got != 2048 {
		t.Fatalf("backend received KeySize %d for an explicit rsaBits=2048 request", got)
	}
}

// TestBuildAttrs_MapsAlgorithmsToKeyAttributes locks the SSH-algorithm →
// xkms-attribute translation. A regression that dropped the ECC curve or the
// RSA size would produce a key on the wrong curve/size — which fails only at
// the far end of an SSH handshake, not at generation.
func TestBuildAttrs_MapsAlgorithmsToKeyAttributes(t *testing.T) {
	rec := &recordingProvider{backendType: types.BackendTypeTPM2}
	newRecordingResolver(t, rec)

	cases := []struct {
		algo      keys.Algorithm
		wantKey   x509.PublicKeyAlgorithm
		wantCurve elliptic.Curve
	}{
		{keys.AlgorithmEd25519, x509.Ed25519, nil},
		{keys.AlgorithmRSA, x509.RSA, nil},
		{keys.AlgorithmECDSAP256, x509.ECDSA, elliptic.P256()},
		{keys.AlgorithmECDSAP384, x509.ECDSA, elliptic.P384()},
		{keys.AlgorithmECDSAP521, x509.ECDSA, elliptic.P521()},
	}

	for _, tc := range cases {
		t.Run(tc.algo.String(), func(t *testing.T) {
			attrs, err := buildAttrs("ssh-user-attrs", tc.algo, 0, rec)
			if err != nil {
				t.Fatalf("buildAttrs: %v", err)
			}
			if attrs.CN != "ssh-user-attrs" {
				t.Errorf("CN = %q, want the key ID", attrs.CN)
			}
			if attrs.KeyType != types.KeyTypeSigning {
				t.Errorf("KeyType = %v, want KeyTypeSigning", attrs.KeyType)
			}
			// The store type must come from the provider, not be hardcoded:
			// keys generated under the wrong store type land in the wrong
			// namespace and become unreachable at sign time.
			if attrs.StoreType != types.StoreTPM2 {
				t.Errorf("StoreType = %v, want StoreTPM2 (derived from the provider Type())", attrs.StoreType)
			}
			if attrs.KeyAlgorithm != tc.wantKey {
				t.Errorf("KeyAlgorithm = %v, want %v", attrs.KeyAlgorithm, tc.wantKey)
			}
			switch tc.wantCurve {
			case nil:
				if attrs.ECCAttributes != nil {
					t.Errorf("ECCAttributes set for a non-ECDSA algorithm: %+v", attrs.ECCAttributes)
				}
			default:
				if attrs.ECCAttributes == nil {
					t.Fatalf("ECCAttributes nil for %s", tc.algo)
				}
				if attrs.ECCAttributes.Curve != tc.wantCurve {
					t.Errorf("curve = %v, want %v", attrs.ECCAttributes.Curve, tc.wantCurve)
				}
			}
		})
	}
}

// TestBuildAttrs_UnsupportedAlgorithm covers the rejection path for every
// entry point, including the empty algorithm (an unset field in a decoded
// request body) which must not silently default to a key type.
func TestBuildAttrs_UnsupportedAlgorithm(t *testing.T) {
	ctx := context.Background()
	rec := &recordingProvider{}
	p := newRecordingResolver(t, rec)

	for _, algo := range []keys.Algorithm{"", "dsa", "ecdsa-p224", "ED25519"} {
		t.Run("algo="+string(algo), func(t *testing.T) {
			_, err := buildAttrs("k", algo, 0, rec)
			var unsupported *UnsupportedAlgorithmError
			if !errors.As(err, &unsupported) {
				t.Fatalf("buildAttrs(%q) error = %v, want *UnsupportedAlgorithmError", algo, err)
			}
			if unsupported.Algorithm != string(algo) {
				t.Errorf("UnsupportedAlgorithmError.Algorithm = %q, want %q", unsupported.Algorithm, algo)
			}
			if !strings.Contains(unsupported.Error(), string(algo)) && algo != "" {
				t.Errorf("error message %q does not name the offending algorithm", unsupported.Error())
			}

			// Every public entry point must reject it, and must not reach the
			// backend.
			before := len(rec.generated) + len(rec.signed) + len(rec.deleted)
			if _, err := p.GenerateKey(ctx, "software", "k", algo, 0); !errors.As(err, &unsupported) {
				t.Errorf("GenerateKey error = %v, want *UnsupportedAlgorithmError", err)
			}
			if _, err := p.Signer(ctx, "software", "k", algo); !errors.As(err, &unsupported) {
				t.Errorf("Signer error = %v, want *UnsupportedAlgorithmError", err)
			}
			if err := p.DeleteKey(ctx, "software", "k", algo); !errors.As(err, &unsupported) {
				t.Errorf("DeleteKey error = %v, want *UnsupportedAlgorithmError", err)
			}
			if after := len(rec.generated) + len(rec.signed) + len(rec.deleted); after != before {
				t.Errorf("an unsupported algorithm reached the backend (%d calls before, %d after)", before, after)
			}
		})
	}
}

// TestNew_NilResolver checks the constructor guard names the offending field
// so operators can act on the message.
func TestNew_NilResolver(t *testing.T) {
	p, err := New(nil)
	if p != nil {
		t.Fatalf("New(nil) returned a non-nil Provider: %+v", p)
	}
	var nilErr *NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("New(nil) error = %v, want *NilInputError", err)
	}
	if nilErr.Field != "resolver" {
		t.Errorf("NilInputError.Field = %q, want %q", nilErr.Field, "resolver")
	}
	if !strings.Contains(nilErr.Error(), "resolver") {
		t.Errorf("error message %q does not name the field", nilErr.Error())
	}
}

// TestProvider_NilKeyProviderIsBackendNotFound covers the resolver contract
// hole where a resolver returns (nil, nil) — e.g. a map lookup miss returned
// without an error. Every entry point must convert that into a typed
// BackendNotFoundError instead of panicking on a nil interface call.
func TestProvider_NilKeyProviderIsBackendNotFound(t *testing.T) {
	ctx := context.Background()
	p, err := New(ResolverFunc(func(context.Context, string) (types.KeyProvider, error) {
		return nil, nil
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertNotFound := func(t *testing.T, op string, err error) {
		t.Helper()
		var nf *BackendNotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("%s error = %v, want *BackendNotFoundError", op, err)
		}
		if nf.BackendID != "ghost" {
			t.Errorf("%s BackendNotFoundError.BackendID = %q, want %q", op, nf.BackendID, "ghost")
		}
		if !strings.Contains(nf.Error(), "ghost") {
			t.Errorf("%s error message %q does not name the backend", op, nf.Error())
		}
	}

	_, gerr := p.GenerateKey(ctx, "ghost", "k", keys.AlgorithmEd25519, 0)
	assertNotFound(t, "GenerateKey", gerr)

	_, serr := p.Signer(ctx, "ghost", "k", keys.AlgorithmEd25519)
	assertNotFound(t, "Signer", serr)

	assertNotFound(t, "DeleteKey", p.DeleteKey(ctx, "ghost", "k", keys.AlgorithmEd25519))
}

// TestProvider_ResolverErrorPropagatesUnwrapped proves a resolver failure is
// surfaced verbatim (errors.Is against the caller's own sentinel still works)
// rather than being flattened into an opaque string.
func TestProvider_ResolverErrorPropagatesUnwrapped(t *testing.T) {
	ctx := context.Background()
	p, err := New(ResolverFunc(func(context.Context, string) (types.KeyProvider, error) {
		return nil, errBackendDown
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := p.GenerateKey(ctx, "b", "k", keys.AlgorithmEd25519, 0); !errors.Is(err, errBackendDown) {
		t.Errorf("GenerateKey error = %v, want errors.Is(errBackendDown)", err)
	}
	if _, err := p.Signer(ctx, "b", "k", keys.AlgorithmEd25519); !errors.Is(err, errBackendDown) {
		t.Errorf("Signer error = %v, want errors.Is(errBackendDown)", err)
	}
	if err := p.DeleteKey(ctx, "b", "k", keys.AlgorithmEd25519); !errors.Is(err, errBackendDown) {
		t.Errorf("DeleteKey error = %v, want errors.Is(errBackendDown)", err)
	}
}

// TestProvider_BackendFailuresAreTypedAndUnwrappable covers the three wrapper
// error types. Each must carry the backend/key identity for diagnostics AND
// unwrap to the backend's own error so callers can branch on it.
func TestProvider_BackendFailuresAreTypedAndUnwrappable(t *testing.T) {
	ctx := context.Background()

	t.Run("generate", func(t *testing.T) {
		rec := &recordingProvider{failGenerate: errBackendDown}
		p := newRecordingResolver(t, rec)

		_, err := p.GenerateKey(ctx, "software", "ssh-user-gfail", keys.AlgorithmEd25519, 0)
		var gerr *GenerateError
		if !errors.As(err, &gerr) {
			t.Fatalf("error = %v, want *GenerateError", err)
		}
		if gerr.BackendID != "software" || gerr.KeyID != "ssh-user-gfail" {
			t.Errorf("GenerateError identity = (%q,%q), want (software, ssh-user-gfail)", gerr.BackendID, gerr.KeyID)
		}
		if !errors.Is(err, errBackendDown) {
			t.Error("GenerateError does not unwrap to the backend cause")
		}
		if !strings.Contains(gerr.Error(), "ssh-user-gfail") || !strings.Contains(gerr.Error(), "software") {
			t.Errorf("message %q omits the key or backend identity", gerr.Error())
		}
	})

	t.Run("signer-after-successful-generate", func(t *testing.T) {
		// A backend that generates but cannot produce a signer must surface a
		// SignerError, not a GenerateError — the distinction tells an operator
		// whether the key exists.
		rec := &recordingProvider{failSigner: errBackendDown}
		p := newRecordingResolver(t, rec)

		_, err := p.GenerateKey(ctx, "software", "ssh-user-sfail", keys.AlgorithmEd25519, 0)
		var serr *SignerError
		if !errors.As(err, &serr) {
			t.Fatalf("error = %v, want *SignerError", err)
		}
		var gerr *GenerateError
		if errors.As(err, &gerr) {
			t.Fatal("a signer failure was reported as a GenerateError")
		}
		if serr.KeyID != "ssh-user-sfail" {
			t.Errorf("SignerError.KeyID = %q", serr.KeyID)
		}
		if !errors.Is(err, errBackendDown) {
			t.Error("SignerError does not unwrap to the backend cause")
		}
		if !strings.Contains(serr.Error(), "ssh-user-sfail") || !strings.Contains(serr.Error(), "software") {
			t.Errorf("message %q omits the key or backend identity", serr.Error())
		}
		if len(rec.generated) != 1 {
			t.Errorf("expected the key to have been generated before the signer failure, got %d generate calls", len(rec.generated))
		}
	})

	t.Run("delete", func(t *testing.T) {
		rec := &recordingProvider{failDelete: errBackendDown}
		p := newRecordingResolver(t, rec)

		err := p.DeleteKey(ctx, "software", "ssh-user-dfail", keys.AlgorithmECDSAP256)
		var derr *DeleteError
		if !errors.As(err, &derr) {
			t.Fatalf("error = %v, want *DeleteError", err)
		}
		if derr.BackendID != "software" || derr.KeyID != "ssh-user-dfail" {
			t.Errorf("DeleteError identity = (%q,%q)", derr.BackendID, derr.KeyID)
		}
		if !errors.Is(err, errBackendDown) {
			t.Error("DeleteError does not unwrap to the backend cause")
		}
		if !strings.Contains(derr.Error(), "ssh-user-dfail") {
			t.Errorf("message %q omits the key identity", derr.Error())
		}
	})
}

// TestProvider_DeleteMissingKeyIsTyped covers the real-backend delete-miss
// path (as opposed to the injected failure above): deleting a key that was
// never generated must produce a DeleteError naming the key.
func TestProvider_DeleteMissingKeyIsTyped(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = p.DeleteKey(ctx, "software", "ssh-user-never-existed", keys.AlgorithmEd25519)
	var derr *DeleteError
	if !errors.As(err, &derr) {
		t.Fatalf("DeleteKey on a missing key returned %v, want *DeleteError", err)
	}
	if derr.Unwrap() == nil {
		t.Error("DeleteError.Unwrap() is nil; the backend cause was dropped")
	}
}

// TestProvider_SignerResolvesSameKeyAcrossCalls proves Signer reconstructs the
// attributes well enough to find the previously generated key: the public key
// from a fresh Signer must be byte-identical to the one from GenerateKey. A
// regression in the attribute reconstruction (wrong curve, wrong store type)
// would either error or, worse, silently resolve a different key.
func TestProvider_SignerResolvesSameKeyAcrossCalls(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, algo := range []keys.Algorithm{keys.AlgorithmEd25519, keys.AlgorithmECDSAP384, keys.AlgorithmECDSAP521} {
		t.Run(algo.String(), func(t *testing.T) {
			keyID := "ssh-user-stable-" + algo.String()
			gen, err := p.GenerateKey(ctx, "software", keyID, algo, 0)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			resolved, err := p.Signer(ctx, "software", keyID, algo)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			genPub, err := ssh.NewPublicKey(gen.Public())
			if err != nil {
				t.Fatalf("NewPublicKey(gen): %v", err)
			}
			resPub, err := ssh.NewPublicKey(resolved.Public())
			if err != nil {
				t.Fatalf("NewPublicKey(resolved): %v", err)
			}
			if string(genPub.Marshal()) != string(resPub.Marshal()) {
				t.Fatal("Signer resolved a different key than GenerateKey created")
			}
		})
	}
}

// TestResolverFunc_Adapts confirms the function adapter forwards both the
// context and the backend ID, which the production resolvers rely on for
// per-request cancellation and tenant scoping.
func TestResolverFunc_Adapts(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "tenant-a")

	var gotID string
	var gotVal any
	var r Resolver = ResolverFunc(func(c context.Context, backendID string) (types.KeyProvider, error) {
		gotID = backendID
		gotVal = c.Value(ctxKey{})
		return nil, errBackendDown
	})

	if _, err := r.ResolveKeyProvider(ctx, "tpm2"); !errors.Is(err, errBackendDown) {
		t.Fatalf("ResolveKeyProvider error = %v, want errBackendDown", err)
	}
	if gotID != "tpm2" {
		t.Errorf("backendID = %q, want %q", gotID, "tpm2")
	}
	if gotVal != "tenant-a" {
		t.Errorf("context value = %v, want tenant-a (context not forwarded)", gotVal)
	}
}
