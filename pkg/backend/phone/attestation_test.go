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

package phone

import (
	"context"
	"testing"

	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

func TestBackend_AttestKey_Success(t *testing.T) {
	certChain := [][]byte{
		[]byte("leaf-cert-der"),
		[]byte("intermediate-cert-der"),
		[]byte("root-cert-der"),
	}
	nonce := []byte("challenge-nonce-12345")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalAttestKey {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalAttestKey, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: certChain,
				SecurityLevel:    "strongbox",
				Nonce:            nonce,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	result, err := b.AttestKey(attrs, nonce)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	attestResult, ok := result.(*AttestationResult)
	if !ok {
		t.Fatalf("expected *AttestationResult, got %T", result)
	}

	if attestResult.Format != "android-keystore" {
		t.Errorf("expected format android-keystore, got %s", attestResult.Format)
	}
	if len(attestResult.CertificateChain) != 3 {
		t.Errorf("expected 3 certs in chain, got %d", len(attestResult.CertificateChain))
	}
	if attestResult.Backend != "android-keystore-strongbox" {
		t.Errorf("expected backend android-keystore-strongbox, got %s", attestResult.Backend)
	}
	if string(attestResult.Nonce) != string(nonce) {
		t.Errorf("expected nonce %q, got %q", nonce, attestResult.Nonce)
	}
	if attestResult.Verified {
		t.Error("expected Verified=false when no trust store configured")
	}
}

func TestBackend_AttestKey_TEE(t *testing.T) {
	nonce := []byte("nonce")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: [][]byte{[]byte("cert")},
				SecurityLevel:    "tee",
				Nonce:            nonce,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	result, err := b.AttestKey(ecdsaP256Attrs("test-key"), nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attestResult := result.(*AttestationResult)
	if attestResult.Backend != "android-keystore-tee" {
		t.Errorf("expected android-keystore-tee, got %s", attestResult.Backend)
	}
}

func TestBackend_AttestKey_UnknownSecurityLevel(t *testing.T) {
	nonce := []byte("nonce")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: [][]byte{[]byte("cert")},
				SecurityLevel:    "software",
				Nonce:            nonce,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	result, err := b.AttestKey(ecdsaP256Attrs("test-key"), nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attestResult := result.(*AttestationResult)
	if attestResult.Backend != "android-keystore-software" {
		t.Errorf("expected android-keystore-software for unknown level, got %s", attestResult.Backend)
	}
}

func TestBackend_AttestKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.AttestKey(ecdsaP256Attrs("test-key"), []byte("nonce"))
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_AttestKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.AttestKey(nil, []byte("nonce"))
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_AttestKey_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeAttestFailed, "attestation failed"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.AttestKey(ecdsaP256Attrs("test-key"), []byte("nonce"))
	if err != ErrAttestationFailed {
		t.Errorf("expected ErrAttestationFailed, got %v", err)
	}
}

func TestBackend_AttestKey_NilNonce(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: [][]byte{[]byte("cert")},
				SecurityLevel:    "tee",
				Nonce:            nil,
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.AttestKey(ecdsaP256Attrs("test-key"), nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	attestResult := result.(*AttestationResult)
	if attestResult.Nonce != nil {
		t.Errorf("expected nil nonce, got %v", attestResult.Nonce)
	}
}

func TestBackend_AttestKey_VerifiedFalseWithoutTrustStore(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: [][]byte{[]byte("cert")},
				SecurityLevel:    "strongbox",
				Nonce:            []byte("nonce"),
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	result, err := b.AttestKey(ecdsaP256Attrs("test-key"), []byte("nonce"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attestResult := result.(*AttestationResult)
	if attestResult.Verified {
		t.Error("expected Verified=false when no trust store is configured")
	}
	if attestResult.PlatformData != nil {
		t.Error("expected nil PlatformData when verification is skipped")
	}
}

func TestBackend_AttestKey_WithVerifier(t *testing.T) {
	nonce := []byte("nonce")
	platformData := "test-platform-data"

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: [][]byte{[]byte("cert")},
				SecurityLevel:    "tee",
				Nonce:            nonce,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	b.verifier = &mockPlatformVerifier{
		platform: "android",
		result: &VerifiedAttestation{
			SecurityBackend: "android-keystore-strongbox",
			PlatformData:    platformData,
		},
	}

	result, err := b.AttestKey(ecdsaP256Attrs("test-key"), nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attestResult := result.(*AttestationResult)
	if !attestResult.Verified {
		t.Error("expected Verified=true with verifier")
	}
	if attestResult.Backend != "android-keystore-strongbox" {
		t.Errorf("expected android-keystore-strongbox, got %s", attestResult.Backend)
	}
	if attestResult.PlatformData != platformData {
		t.Errorf("expected platform data %q, got %v", platformData, attestResult.PlatformData)
	}
}

func TestBackend_AttestKey_VerifierError(t *testing.T) {
	nonce := []byte("nonce")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalAttestKeyResult{
				Format:           "android-keystore",
				CertificateChain: [][]byte{[]byte("cert")},
				SecurityLevel:    "tee",
				Nonce:            nonce,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	b.verifier = &mockPlatformVerifier{
		platform: "android",
		err:      ErrChainVerificationFailed,
	}

	_, err := b.AttestKey(ecdsaP256Attrs("test-key"), nonce)
	if err != ErrChainVerificationFailed {
		t.Errorf("expected ErrChainVerificationFailed, got %v", err)
	}
}

// --- mapSecurityLevel ---

func TestMapSecurityLevel_StrongBox(t *testing.T) {
	result := mapSecurityLevel("strongbox")
	if result != "android-keystore-strongbox" {
		t.Errorf("expected android-keystore-strongbox, got %s", result)
	}
}

func TestMapSecurityLevel_TEE(t *testing.T) {
	result := mapSecurityLevel("tee")
	if result != "android-keystore-tee" {
		t.Errorf("expected android-keystore-tee, got %s", result)
	}
}

func TestMapSecurityLevel_Unknown(t *testing.T) {
	result := mapSecurityLevel("custom-level")
	if result != "android-keystore-custom-level" {
		t.Errorf("expected android-keystore-custom-level, got %s", result)
	}
}

// --- Error types ---

func TestErrorTypes_ChainVerificationFailed(t *testing.T) {
	if ErrChainVerificationFailed == nil {
		t.Fatal("ErrChainVerificationFailed should not be nil")
	}
	if ErrChainVerificationFailed.Error() != "phone backend: certificate chain verification failed" {
		t.Errorf("unexpected error message: %s", ErrChainVerificationFailed.Error())
	}
}

func TestErrorTypes_InsufficientSecurityLevel(t *testing.T) {
	if ErrInsufficientSecurityLevel == nil {
		t.Fatal("ErrInsufficientSecurityLevel should not be nil")
	}
	if ErrInsufficientSecurityLevel.Error() != "phone backend: security level below minimum" {
		t.Errorf("unexpected error message: %s", ErrInsufficientSecurityLevel.Error())
	}
}

func TestErrorTypes_InvalidCertificate(t *testing.T) {
	if ErrInvalidCertificate == nil {
		t.Fatal("ErrInvalidCertificate should not be nil")
	}
	if ErrInvalidCertificate.Error() != "phone backend: invalid certificate in chain" {
		t.Errorf("unexpected error message: %s", ErrInvalidCertificate.Error())
	}
}

func TestErrorTypes_TrustStoreInit(t *testing.T) {
	if ErrTrustStoreInit == nil {
		t.Fatal("ErrTrustStoreInit should not be nil")
	}
	if ErrTrustStoreInit.Error() != "phone backend: trust store initialization failed" {
		t.Errorf("unexpected error message: %s", ErrTrustStoreInit.Error())
	}
}

func TestErrorTypes_UnsupportedPlatform(t *testing.T) {
	if ErrUnsupportedPlatform == nil {
		t.Fatal("ErrUnsupportedPlatform should not be nil")
	}
	if ErrUnsupportedPlatform.Error() != "phone backend: unsupported platform" {
		t.Errorf("unexpected error message: %s", ErrUnsupportedPlatform.Error())
	}
}
