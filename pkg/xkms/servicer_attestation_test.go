// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	stderrors "errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/errors"
)

// =============================================================================
// Test fixtures
// =============================================================================

// attestationKeypair is a self-signed ECDSA attesting identity: the leaf
// certificate plus the private key that signs attestation data with it. It
// stands in for a TPM attestation key without requiring a TPM — the
// verification path under test is pure x509 and ECDSA.
type attestationKeypair struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// newAttestationKeypair mints a self-signed ECDSA certificate valid from an
// hour ago to an hour from now.
func newAttestationKeypair(t *testing.T, commonName string) *attestationKeypair {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return &attestationKeypair{cert: cert, certPEM: der, key: key}
}

// sign produces an ASN.1 ECDSA signature over the SHA-256 of data, matching
// what x509.ECDSAWithSHA256 denotes.
func (k *attestationKeypair) sign(t *testing.T, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

// publicKeyDER returns the PKIX DER encoding of the keypair's public key.
func (k *attestationKeypair) publicKeyDER(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// newSelfSignedVerifyRequest builds a well-formed request that verifies
// against a self-signed anchor, the shape a simulator or lab TPM produces.
func newSelfSignedVerifyRequest(t *testing.T, kp *attestationKeypair, data []byte) *VerifyAttestationRequest {
	t.Helper()
	return &VerifyAttestationRequest{
		Format:             "tpm2",
		Backend:            "tpm2",
		ChainPEM:           [][]byte{kp.certPEM},
		AttestedKeyDER:     kp.publicKeyDER(t),
		AttestationData:    data,
		Signature:          kp.sign(t, data),
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		Options: &VerifyAttestationOptions{
			AllowSelfSigned: true,
		},
	}
}

// =============================================================================
// Verify
// =============================================================================

func TestAttestationService_Verify(t *testing.T) {
	kp := newAttestationKeypair(t, "attestation-key")
	svc := NewAttestationService(nil, nil)

	t.Run("ValidStatement", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("statement should verify, reason: %s", resp.Reason)
		}
		if !resp.ChainValid || !resp.SignatureValid {
			t.Fatalf("component flags should both be set: %+v", resp)
		}
		if resp.Format != "tpm2" || resp.Backend != "tpm2" {
			t.Errorf("format/backend not echoed: %+v", resp)
		}
	})

	t.Run("TamperedDataFailsSignature", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.AttestationData = []byte("tampered")

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify returned a transport error rather than a verdict: %v", err)
		}
		if resp.Valid {
			t.Fatal("a tampered statement must not verify")
		}
		if !resp.ChainValid {
			t.Error("the chain is untouched and should still validate")
		}
		if resp.SignatureValid {
			t.Error("the signature must not validate over tampered data")
		}
		if resp.Reason == "" {
			t.Error("an invalid result must carry a reason")
		}
	})

	t.Run("WrongSignerFailsSignature", func(t *testing.T) {
		other := newAttestationKeypair(t, "impostor")
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Signature = other.sign(t, []byte("tpms-attest"))

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if resp.Valid || resp.SignatureValid {
			t.Fatal("a signature from a different key must not verify")
		}
	})

	t.Run("SelfSignedRejectedWithoutOptIn", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Options.AllowSelfSigned = false

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if resp.Valid {
			t.Fatal("a self-signed chain must not verify without an explicit opt-in")
		}
	})

	t.Run("AnchoredAgainstConfiguredRoot", func(t *testing.T) {
		anchored := NewAttestationService([]*x509.Certificate{kp.cert}, nil)
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Options = &VerifyAttestationOptions{}

		resp, err := anchored.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("statement should verify against the configured anchor, reason: %s", resp.Reason)
		}
	})

	t.Run("PerRequestAnchor", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Options = &VerifyAttestationOptions{TrustedRootsPEM: [][]byte{kp.certPEM}}

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("statement should verify against the per-request anchor, reason: %s", resp.Reason)
		}
	})

	t.Run("InferredSignatureAlgorithm", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.SignatureAlgorithm = ""

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("algorithm should be inferred from the leaf, reason: %s", resp.Reason)
		}
	})
}

func TestAttestationService_Verify_InvalidInput(t *testing.T) {
	kp := newAttestationKeypair(t, "attestation-key")
	svc := NewAttestationService(nil, nil)

	tests := []struct {
		name   string
		mutate func(*VerifyAttestationRequest)
		wantIs error
	}{
		{name: "NoFormat", mutate: func(r *VerifyAttestationRequest) { r.Format = "" }, wantIs: ErrAttestationEmptyFormat},
		{name: "NoSignature", mutate: func(r *VerifyAttestationRequest) { r.Signature = nil }, wantIs: ErrAttestationNoSignature},
		{name: "NoAttestedKey", mutate: func(r *VerifyAttestationRequest) { r.AttestedKeyDER = nil }, wantIs: ErrAttestationNoAttestedKey},
		{name: "NoChain", mutate: func(r *VerifyAttestationRequest) { r.ChainPEM = nil }, wantIs: ErrAttestationEmptyChain},
		{name: "EmptyChainEntry", mutate: func(r *VerifyAttestationRequest) { r.ChainPEM = [][]byte{{}} }},
		{name: "MalformedChainEntry", mutate: func(r *VerifyAttestationRequest) { r.ChainPEM = [][]byte{[]byte("not a certificate")} }},
		{name: "MalformedAttestedKey", mutate: func(r *VerifyAttestationRequest) { r.AttestedKeyDER = []byte("not a key") }},
		{
			name:   "UnknownSignatureAlgorithm",
			mutate: func(r *VerifyAttestationRequest) { r.SignatureAlgorithm = "PQC-Dilithium" },
		},
		{
			name: "MalformedTrustAnchor",
			mutate: func(r *VerifyAttestationRequest) {
				r.Options = &VerifyAttestationOptions{TrustedRootsPEM: [][]byte{[]byte("nope")}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newSelfSignedVerifyRequest(t, kp, []byte("data"))
			tt.mutate(req)

			_, err := svc.Verify(t.Context(), req)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.wantIs != nil && !stderrors.Is(err, tt.wantIs) {
				t.Fatalf("error %v is not %v", err, tt.wantIs)
			}
		})
	}

	t.Run("NilRequest", func(t *testing.T) {
		if _, err := svc.Verify(t.Context(), nil); !stderrors.Is(err, ErrAttestationNilRequest) {
			t.Fatalf("error %v is not ErrAttestationNilRequest", err)
		}
	})

	t.Run("CanceledContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		req := newSelfSignedVerifyRequest(t, kp, []byte("data"))
		if _, err := svc.Verify(ctx, req); err == nil {
			t.Fatal("expected a canceled context to be refused")
		}
	})
}

// TestAttestationService_Verify_Freshness exercises the option pass-through:
// the freshness window is enforced by go-xkms, and this proves the service
// hands it the caller's parameters rather than dropping them.
func TestAttestationService_Verify_Freshness(t *testing.T) {
	kp := newAttestationKeypair(t, "attestation-key")
	svc := NewAttestationService(nil, nil)
	nonce := []byte("challenge")

	t.Run("FreshAttestationPasses", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Nonce = nonce
		req.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		req.Options = &VerifyAttestationOptions{
			AllowSelfSigned:        true,
			CheckFreshness:         true,
			ExpectedNonce:          nonce,
			FreshnessWindowSeconds: 300,
		}

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("a fresh attestation should verify, reason: %s", resp.Reason)
		}
		if !resp.FreshnessValid {
			t.Error("freshness flag should be set when the check ran and passed")
		}
	})

	t.Run("StaleAttestationFails", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Nonce = nonce
		req.CreatedAt = time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
		req.Options = &VerifyAttestationOptions{
			AllowSelfSigned:        true,
			CheckFreshness:         true,
			ExpectedNonce:          nonce,
			FreshnessWindowSeconds: 60,
		}

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if resp.Valid {
			t.Fatal("a stale attestation must not verify")
		}
	})

	t.Run("ReplayedNonceFails", func(t *testing.T) {
		req := newSelfSignedVerifyRequest(t, kp, []byte("tpms-attest"))
		req.Nonce = []byte("some-other-nonce")
		req.Options = &VerifyAttestationOptions{
			AllowSelfSigned:        true,
			CheckFreshness:         true,
			ExpectedNonce:          nonce,
			FreshnessWindowSeconds: 300,
		}

		resp, err := svc.Verify(t.Context(), req)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if resp.Valid {
			t.Fatal("a nonce mismatch must not verify")
		}
	})
}

// =============================================================================
// VerifyChain
// =============================================================================

func TestAttestationService_VerifyChain(t *testing.T) {
	kp := newAttestationKeypair(t, "attestation-key")

	t.Run("SelfSignedAcceptedWhenAllowed", func(t *testing.T) {
		svc := NewAttestationService(nil, nil)
		resp, err := svc.VerifyChain(t.Context(), &VerifyAttestationChainRequest{
			Format:   "tpm2",
			ChainPEM: [][]byte{kp.certPEM},
			Options:  &VerifyAttestationOptions{AllowSelfSigned: true},
		})
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("chain should validate, reason: %s", resp.Reason)
		}
	})

	t.Run("SelfSignedRejectedByDefault", func(t *testing.T) {
		svc := NewAttestationService(nil, nil)
		resp, err := svc.VerifyChain(t.Context(), &VerifyAttestationChainRequest{
			Format:   "tpm2",
			ChainPEM: [][]byte{kp.certPEM},
		})
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if resp.Valid {
			t.Fatal("an unanchored self-signed chain must not validate by default")
		}
		if resp.Reason == "" {
			t.Error("an invalid result must carry a reason")
		}
	})

	t.Run("AnchoredAccepted", func(t *testing.T) {
		svc := NewAttestationService([]*x509.Certificate{kp.cert}, nil)
		resp, err := svc.VerifyChain(t.Context(), &VerifyAttestationChainRequest{
			Format:   "tpm2",
			ChainPEM: [][]byte{kp.certPEM},
		})
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("chain should validate against the anchor, reason: %s", resp.Reason)
		}
	})

	t.Run("FormatDefaulted", func(t *testing.T) {
		svc := NewAttestationService([]*x509.Certificate{kp.cert}, nil)
		resp, err := svc.VerifyChain(t.Context(), &VerifyAttestationChainRequest{
			ChainPEM: [][]byte{kp.certPEM},
		})
		if err != nil {
			t.Fatalf("VerifyChain with no format must not error: %v", err)
		}
		if !resp.Valid {
			t.Fatalf("chain should validate, reason: %s", resp.Reason)
		}
	})
}

func TestAttestationService_VerifyChain_InvalidInput(t *testing.T) {
	svc := NewAttestationService(nil, nil)

	t.Run("NilRequest", func(t *testing.T) {
		if _, err := svc.VerifyChain(t.Context(), nil); !stderrors.Is(err, ErrAttestationNilRequest) {
			t.Fatalf("error %v is not ErrAttestationNilRequest", err)
		}
	})

	t.Run("EmptyChain", func(t *testing.T) {
		_, err := svc.VerifyChain(t.Context(), &VerifyAttestationChainRequest{Format: "tpm2"})
		if !stderrors.Is(err, ErrAttestationEmptyChain) {
			t.Fatalf("error %v is not ErrAttestationEmptyChain", err)
		}
	})

	t.Run("MalformedChain", func(t *testing.T) {
		_, err := svc.VerifyChain(t.Context(), &VerifyAttestationChainRequest{
			Format:   "tpm2",
			ChainPEM: [][]byte{[]byte("not a certificate")},
		})
		if err == nil {
			t.Fatal("expected an error for a malformed chain")
		}
	})

	t.Run("CanceledContext", func(t *testing.T) {
		kp := newAttestationKeypair(t, "attestation-key")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := svc.VerifyChain(ctx, &VerifyAttestationChainRequest{
			Format:   "tpm2",
			ChainPEM: [][]byte{kp.certPEM},
		})
		if err == nil {
			t.Fatal("expected a canceled context to be refused")
		}
	})
}

// =============================================================================
// AttestContainer — the orchestration seam
// =============================================================================

// stubAttestor is a ContainerAttestor that records its input and replays a
// fixed response, standing in for go-trusted-platform's fleet attestor.
type stubAttestor struct {
	lastRequest *AttestContainerRequest
	response    *AttestContainerResponse
	err         error
}

func (s *stubAttestor) AttestContainer(_ context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error) {
	s.lastRequest = req
	if s.err != nil {
		return nil, s.err
	}
	return s.response, nil
}

// TestAttestationService_AttestContainer_NoAttestor pins the nil-seam
// contract: with nothing registered the verb reports "not configured", not a
// generic failure, so a caller can distinguish an unconfigured deployment from
// a host that failed attestation.
func TestAttestationService_AttestContainer_NoAttestor(t *testing.T) {
	svc := NewAttestationService(nil, nil)

	_, err := svc.AttestContainer(t.Context(), &AttestContainerRequest{Image: "alpine@sha256:abc"})
	if !stderrors.Is(err, ErrAttestationNoAttestor) {
		t.Fatalf("error %v is not ErrAttestationNoAttestor", err)
	}

	var qbErr *errors.QBError
	if !stderrors.As(err, &qbErr) {
		t.Fatalf("expected a *errors.QBError, got %T", err)
	}
	if qbErr.Code != errors.ErrUnavailable {
		t.Fatalf("code = %v, want ErrUnavailable so callers can tell 'not configured' from 'failed'", qbErr.Code)
	}
}

func TestAttestationService_AttestContainer(t *testing.T) {
	t.Run("ForwardsToRegisteredAttestor", func(t *testing.T) {
		attestor := &stubAttestor{
			response: &AttestContainerResponse{
				Attested:     true,
				ContainerID:  "container-1",
				Image:        "alpine@sha256:abc",
				TrustLevel:   "measured",
				Measured:     true,
				ConfigDigest: "sha256:cfg",
				AttestedAt:   time.Now().UTC(),
			},
		}
		svc := NewAttestationService(nil, attestor)

		req := &AttestContainerRequest{
			DeviceID:     "device-1",
			ContainerID:  "container-1",
			Image:        "alpine@sha256:abc",
			TrustLevel:   "measured",
			ExpectedPCRs: map[uint32][]byte{7: {0x01}},
		}

		resp, err := svc.AttestContainer(t.Context(), req)
		if err != nil {
			t.Fatalf("AttestContainer: %v", err)
		}
		if !resp.Attested || !resp.Measured {
			t.Fatalf("evidence not passed through: %+v", resp)
		}
		if attestor.lastRequest.DeviceID != "device-1" {
			t.Errorf("device id not forwarded: %+v", attestor.lastRequest)
		}
		if len(attestor.lastRequest.ExpectedPCRs) != 1 {
			t.Errorf("expected PCRs not forwarded: %+v", attestor.lastRequest)
		}
	})

	t.Run("AttestorErrorPropagates", func(t *testing.T) {
		sentinel := stderrors.New("host quarantined")
		svc := NewAttestationService(nil, &stubAttestor{err: sentinel})

		_, err := svc.AttestContainer(t.Context(), &AttestContainerRequest{Image: "alpine@sha256:abc"})
		if !stderrors.Is(err, sentinel) {
			t.Fatalf("error %v does not wrap the attestor error", err)
		}
	})

	t.Run("NilEvidenceIsAnError", func(t *testing.T) {
		svc := NewAttestationService(nil, &stubAttestor{})

		_, err := svc.AttestContainer(t.Context(), &AttestContainerRequest{Image: "alpine@sha256:abc"})
		if err == nil {
			t.Fatal("an attestor returning no evidence must be an error, not a silent success")
		}
	})

	t.Run("InvalidInput", func(t *testing.T) {
		svc := NewAttestationService(nil, &stubAttestor{})

		if _, err := svc.AttestContainer(t.Context(), nil); !stderrors.Is(err, ErrAttestationNilRequest) {
			t.Fatalf("error %v is not ErrAttestationNilRequest", err)
		}
		if _, err := svc.AttestContainer(t.Context(), &AttestContainerRequest{}); !stderrors.Is(err, ErrAttestationEmptyImage) {
			t.Fatalf("error %v is not ErrAttestationEmptyImage", err)
		}
	})

	t.Run("CanceledContext", func(t *testing.T) {
		svc := NewAttestationService(nil, &stubAttestor{})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := svc.AttestContainer(ctx, &AttestContainerRequest{Image: "alpine@sha256:abc"}); err == nil {
			t.Fatal("expected a canceled context to be refused")
		}
	})
}

func TestNewRuntimeContainerAttestor_NilRuntime(t *testing.T) {
	// A nil runtime must yield a nil attestor so callers can pass an
	// optional runtime straight through and inherit the not-configured
	// contract.
	if attestor := NewRuntimeContainerAttestor(nil); attestor != nil {
		t.Fatalf("expected nil, got %T", attestor)
	}
}

func TestSignatureAlgorithmIndex(t *testing.T) {
	// The index is derived from x509's own String method, so every entry
	// must round-trip. A drift here would silently reject a valid
	// algorithm name.
	for name, alg := range signatureAlgorithmByName {
		if alg.String() != name {
			t.Fatalf("index key %q does not match %v.String()", name, alg)
		}
	}
	for _, name := range []string{"ECDSA-SHA256", "SHA256-RSA", "Ed25519"} {
		if _, ok := signatureAlgorithmByName[name]; !ok {
			t.Errorf("signature algorithm %q missing from the index", name)
		}
	}
}

func TestParseCertChainPEM(t *testing.T) {
	kp := newAttestationKeypair(t, "leaf")

	t.Run("AcceptsDER", func(t *testing.T) {
		chain, err := parseCertChainPEM([][]byte{kp.certPEM}, "test")
		if err != nil {
			t.Fatalf("parseCertChainPEM: %v", err)
		}
		if len(chain) != 1 || chain[0].Subject.CommonName != "leaf" {
			t.Fatalf("unexpected chain: %+v", chain)
		}
	})

	t.Run("Errors", func(t *testing.T) {
		if _, err := parseCertChainPEM(nil, "test"); !stderrors.Is(err, ErrAttestationEmptyChain) {
			t.Fatalf("error %v is not ErrAttestationEmptyChain", err)
		}
		if _, err := parseCertChainPEM([][]byte{{}}, "test"); err == nil {
			t.Fatal("expected an error for an empty chain entry")
		}
		if _, err := parseCertChainPEM([][]byte{[]byte("garbage")}, "test"); err == nil {
			t.Fatal("expected an error for a malformed chain entry")
		}
	})
}

func TestVerifyOptions_Defaults(t *testing.T) {
	t.Run("NilSelectsSecureDefaults", func(t *testing.T) {
		opts, err := verifyOptions(nil)
		if err != nil {
			t.Fatalf("verifyOptions: %v", err)
		}
		if !opts.CheckFreshness {
			t.Error("the default must check freshness")
		}
		if opts.AllowSelfSigned {
			t.Error("the default must not accept self-signed chains")
		}
	})

	t.Run("ExplicitOptionsPassThrough", func(t *testing.T) {
		opts, err := verifyOptions(&VerifyAttestationOptions{
			CheckFreshness:         true,
			FreshnessWindowSeconds: 42,
			VerifyPCRs:             true,
			ExpectedPCRs:           map[uint32][]byte{7: {0x01}},
			AllowSelfSigned:        true,
		})
		if err != nil {
			t.Fatalf("verifyOptions: %v", err)
		}
		if opts.FreshnessWindow != 42 || !opts.VerifyPCRs || len(opts.ExpectedPCRs) != 1 || !opts.AllowSelfSigned {
			t.Fatalf("options were not passed through: %+v", opts)
		}
	})
}
