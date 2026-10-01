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

package luks

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// These tests exercise TPMSealer's dispatch, error propagation and token
// encoding against a fake TPMSealUnsealer, without a real or simulated TPM.
// Round-trip proofs that a real TPM enforces the PCR policy live in
// tpm_simulator_test.go, gated behind the tpm_simulator build tag.

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeTPM is a TPMSealUnsealer double whose every method is driven by a
// field the test sets directly.
type fakeTPM struct {
	platformAttrs *types.KeyAttributes
	platformErr   error
	ssrkAttrs     *types.KeyAttributes
	ssrkErr       error
	sealFn        func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error)
	unsealFn      func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error)
	transport     transport.TPM
	sealCalled    bool
	unsealCalled  bool
}

func (f *fakeTPM) PlatformSRKAttributes() (*types.KeyAttributes, error) {
	return f.platformAttrs, f.platformErr
}

func (f *fakeTPM) SSRKAttributes() (*types.KeyAttributes, error) {
	return f.ssrkAttrs, f.ssrkErr
}

func (f *fakeTPM) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	f.sealCalled = true
	if f.sealFn != nil {
		return f.sealFn(ctx, data, opts)
	}
	return nil, errors.New("fakeTPM: Seal not configured")
}

func (f *fakeTPM) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	f.unsealCalled = true
	if f.unsealFn != nil {
		return f.unsealFn(ctx, sealed, opts)
	}
	return nil, errors.New("fakeTPM: Unseal not configured")
}

func (f *fakeTPM) Transport() transport.TPM { return f.transport }

// failTransport fails every Send with the same error, simulating a TPM that
// is unreachable partway through a trial-session PCR policy computation.
type failTransport struct{ err error }

func (t *failTransport) Send([]byte) ([]byte, error) { return nil, t.err }

// fakeParentAttrs builds minimal KeyAttributes for a parent SRK at handle.
func fakeParentAttrs(handle uint32) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            "test-srk",
		TPMAttributes: &types.TPMAttributes{Handle: libtpm2.TPMHandle(handle)},
	}
}

// fakeSealedData returns a minimal, decodable SealedData result.
func fakeSealedData() *types.SealedData {
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		TPMPublic:  []byte{0x01, 0x02, 0x03},
		TPMPrivate: []byte{0x10, 0x11},
	}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewTPMSealer_NilTPM(t *testing.T) {
	_, err := NewTPMSealer(nil, TPMSealerConfig{})
	if !errors.Is(err, ErrTPMNoTransport) {
		t.Fatalf("expected ErrTPMNoTransport, got %v", err)
	}
}

func TestNewTPMSealer_InvalidParent(t *testing.T) {
	_, err := NewTPMSealer(&fakeTPM{}, TPMSealerConfig{Parent: SealParent(99)})
	var target *SealParentInvalidError
	if !errors.As(err, &target) {
		t.Fatalf("expected *SealParentInvalidError, got %v (%T)", err, err)
	}
}

func TestNewTPMSealer_InvalidPCRBank(t *testing.T) {
	_, err := NewTPMSealer(&fakeTPM{}, TPMSealerConfig{Parent: SealParentSSRK, PCRBank: "md5"})
	if !errors.Is(err, ErrInvalidPCRBank) {
		t.Fatalf("expected ErrInvalidPCRBank, got %v", err)
	}
}

func TestNewTPMSealer_DefaultsToPSRK(t *testing.T) {
	s, err := NewTPMSealer(&fakeTPM{}, TPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	if s.Parent() != SealParentPSRK {
		t.Fatalf("Parent() = %v, want SealParentPSRK", s.Parent())
	}
}

// ---------------------------------------------------------------------------
// SealPassphrase — SealParentPSRK
// ---------------------------------------------------------------------------

func TestTPMSealer_SealPassphrase_PSRK_RejectsPCRSelection(t *testing.T) {
	s, err := NewTPMSealer(&fakeTPM{}, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.SealPassphrase(context.Background(), []int32{7})
	if !errors.Is(err, ErrTPMPCRSelectionNotSupported) {
		t.Fatalf("expected ErrTPMPCRSelectionNotSupported, got %v", err)
	}
}

func TestTPMSealer_SealPassphrase_PSRK_PlatformSRKError(t *testing.T) {
	wantErr := errors.New("no platform srk")
	tpm := &fakeTPM{platformErr: wantErr}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.SealPassphrase(context.Background(), nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
	if tpm.sealCalled {
		t.Fatal("Seal must not be called when PlatformSRKAttributes fails")
	}
}

func TestTPMSealer_SealPassphrase_PSRK_SealError(t *testing.T) {
	tpm := &fakeTPM{
		platformAttrs: fakeParentAttrs(0x81000002),
		sealFn: func(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
			return nil, errors.New("tpm2_create failed")
		},
	}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.SealPassphrase(context.Background(), nil)
	if !errors.Is(err, ErrTPMSealFailed) {
		t.Fatalf("expected ErrTPMSealFailed, got %v", err)
	}
}

func TestTPMSealer_SealPassphrase_PSRK_Success(t *testing.T) {
	var gotOpts *types.SealOptions
	tpm := &fakeTPM{
		platformAttrs: fakeParentAttrs(0x81000002),
		sealFn: func(_ context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			if len(data) != 32 {
				t.Fatalf("seal data length = %d, want 32", len(data))
			}
			gotOpts = opts
			return fakeSealedData(), nil
		},
	}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	res, err := s.SealPassphrase(context.Background(), nil)
	if err != nil {
		t.Fatalf("SealPassphrase: %v", err)
	}
	defer res.Passphrase.Destroy()

	if res.Passphrase.Size() != 32 {
		t.Fatalf("passphrase length = %d, want 32", res.Passphrase.Size())
	}
	if res.Token.Type != XKMSTPMTokenType {
		t.Fatalf("token type = %q, want %q", res.Token.Type, XKMSTPMTokenType)
	}
	if res.Token.TPM2KeyHandle != 0x81000002 {
		t.Fatalf("token handle = %#x, want 0x81000002", res.Token.TPM2KeyHandle)
	}
	pub, priv, err := DecodeTPMSealBlobs(res.Token.TPM2Blob)
	if err != nil {
		t.Fatalf("DecodeTPMSealBlobs: %v", err)
	}
	if !bytes.Equal(pub, []byte{0x01, 0x02, 0x03}) || !bytes.Equal(priv, []byte{0x10, 0x11}) {
		t.Fatalf("decoded blobs do not match sealed data")
	}
	if gotOpts.KeyAttributes.TPMPolicy != types.TPMPolicyPlatform {
		t.Fatalf("KeyAttributes.TPMPolicy = %q, want %q", gotOpts.KeyAttributes.TPMPolicy, types.TPMPolicyPlatform)
	}
	if gotOpts.KeyAttributes.Password != nil {
		t.Fatal("the sealed object carries no password: its platform policy alone protects it")
	}
}

// ---------------------------------------------------------------------------
// SealPassphrase — SealParentSSRK
// ---------------------------------------------------------------------------

func TestTPMSealer_SealPassphrase_SSRK_SSRKAttributesError(t *testing.T) {
	wantErr := errors.New("no ssrk")
	tpm := &fakeTPM{ssrkErr: wantErr}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentSSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.SealPassphrase(context.Background(), []int32{7})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
}

func TestTPMSealer_SealPassphrase_SSRK_PolicyDigestFailure(t *testing.T) {
	tpm := &fakeTPM{
		ssrkAttrs: fakeParentAttrs(0x81000001),
		transport: &failTransport{err: errors.New("bus down")},
	}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentSSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.SealPassphrase(context.Background(), []int32{7})
	if !errors.Is(err, ErrTPMPolicyFailed) {
		t.Fatalf("expected ErrTPMPolicyFailed, got %v", err)
	}
	if tpm.sealCalled {
		t.Fatal("Seal must not be called when the policy digest cannot be computed")
	}
}

// ---------------------------------------------------------------------------
// UnsealPassphrase
// ---------------------------------------------------------------------------

func TestTPMSealer_UnsealPassphrase_NilToken(t *testing.T) {
	s, err := NewTPMSealer(&fakeTPM{}, TPMSealerConfig{})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.UnsealPassphrase(context.Background(), nil)
	if !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken, got %v", err)
	}
}

func TestTPMSealer_UnsealPassphrase_SSRK_Unsupported(t *testing.T) {
	tpm := &fakeTPM{}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentSSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.UnsealPassphrase(context.Background(), &luks2.Token{Type: TPMTokenType})
	if !errors.Is(err, ErrTPMSSRKUnsealUnsupported) {
		t.Fatalf("expected ErrTPMSSRKUnsealUnsupported, got %v", err)
	}
	if tpm.unsealCalled {
		t.Fatal("Unseal must never be called for SealParentSSRK")
	}
}

func TestTPMSealer_UnsealPassphrase_PSRK_InvalidBlob(t *testing.T) {
	s, err := NewTPMSealer(&fakeTPM{}, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = s.UnsealPassphrase(context.Background(), &luks2.Token{Type: XKMSTPMTokenType, TPM2Blob: "not base64!!"})
	if !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken, got %v", err)
	}
}

func TestTPMSealer_UnsealPassphrase_PSRK_PlatformSRKError(t *testing.T) {
	wantErr := errors.New("no platform srk")
	tpm := &fakeTPM{platformErr: wantErr}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	token := &luks2.Token{Type: XKMSTPMTokenType, TPM2Blob: EncodeTPMSealBlobs([]byte{1}, []byte{2})}
	_, err = s.UnsealPassphrase(context.Background(), token)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
}

func TestTPMSealer_UnsealPassphrase_PSRK_UnsealError(t *testing.T) {
	tpm := &fakeTPM{
		platformAttrs: fakeParentAttrs(0x81000002),
		unsealFn: func(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
			return nil, errors.New("policy failed")
		},
	}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	token := &luks2.Token{Type: XKMSTPMTokenType, TPM2Blob: EncodeTPMSealBlobs([]byte{1}, []byte{2})}
	_, err = s.UnsealPassphrase(context.Background(), token)
	if !errors.Is(err, ErrTPMUnsealFailed) {
		t.Fatalf("expected ErrTPMUnsealFailed, got %v", err)
	}
}

func TestTPMSealer_UnsealPassphrase_PSRK_Success(t *testing.T) {
	want := []byte("the-luks-passphrase-32-bytes!!!")
	tpm := &fakeTPM{
		platformAttrs: fakeParentAttrs(0x81000002),
		unsealFn: func(_ context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			if opts.KeyAttributes.TPMPolicy != types.TPMPolicyPlatform {
				t.Fatalf("unseal KeyAttributes.TPMPolicy = %q, want %q", opts.KeyAttributes.TPMPolicy, types.TPMPolicyPlatform)
			}
			if !bytes.Equal(sealed.TPMPublic, []byte{1}) || !bytes.Equal(sealed.TPMPrivate, []byte{2}) {
				t.Fatal("unseal did not receive the decoded blob")
			}
			return want, nil
		},
	}
	s, err := NewTPMSealer(tpm, TPMSealerConfig{Parent: SealParentPSRK})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	token := &luks2.Token{Type: XKMSTPMTokenType, TPM2Blob: EncodeTPMSealBlobs([]byte{1}, []byte{2})}
	got, err := s.UnsealPassphrase(context.Background(), token)
	if err != nil {
		t.Fatalf("UnsealPassphrase: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unsealed = %x, want %x", got, want)
	}
}

// ---------------------------------------------------------------------------
// Token blob encoding
// ---------------------------------------------------------------------------

func TestEncodeDecodeTPMSealBlobs_RoundTrip(t *testing.T) {
	pub := []byte{0x01, 0x02, 0x03}
	priv := []byte{0x10, 0x11, 0x12, 0x13}
	s := EncodeTPMSealBlobs(pub, priv)
	gotPub, gotPriv, err := DecodeTPMSealBlobs(s)
	if err != nil {
		t.Fatalf("DecodeTPMSealBlobs: %v", err)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatalf("public mismatch: got %x want %x", gotPub, pub)
	}
	if !bytes.Equal(gotPriv, priv) {
		t.Fatalf("private mismatch: got %x want %x", gotPriv, priv)
	}
}

func TestEncodeDecodeTPMSealBlobs_EmptyPrivate(t *testing.T) {
	pub := []byte{0x01, 0x02}
	s := EncodeTPMSealBlobs(pub, nil)
	gotPub, gotPriv, err := DecodeTPMSealBlobs(s)
	if err != nil {
		t.Fatalf("DecodeTPMSealBlobs: %v", err)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatalf("public mismatch")
	}
	if len(gotPriv) != 0 {
		t.Fatalf("expected empty private, got %x", gotPriv)
	}
}

func TestDecodeTPMSealBlobs_Short(t *testing.T) {
	if _, _, err := DecodeTPMSealBlobs("AAAA"); !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken for short blob, got %v", err)
	}
}

func TestDecodeTPMSealBlobs_NotBase64(t *testing.T) {
	if _, _, err := DecodeTPMSealBlobs("not base64!!"); !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken for non-base64 input, got %v", err)
	}
}

func TestDecodeTPMSealBlobs_LengthMismatch(t *testing.T) {
	// Length prefix claims 100 bytes of public blob, but only 2 bytes of
	// payload follow the 4-byte prefix.
	raw := []byte{0x00, 0x00, 0x00, 0x64, 0x01, 0x02}
	encoded := base64.StdEncoding.EncodeToString(raw)
	_, _, err := DecodeTPMSealBlobs(encoded)
	if !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken for length mismatch, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// PCR selection
// ---------------------------------------------------------------------------

const pcrBankSHA256 = 0x000B

func TestBuildPCRSelection_EmptyReturnsZeroSelection(t *testing.T) {
	sel := buildPCRSelection(pcrBankSHA256, nil)
	if len(sel.PCRSelections) != 1 {
		t.Fatalf("selections = %d, want 1", len(sel.PCRSelections))
	}
	for _, b := range sel.PCRSelections[0].PCRSelect {
		if b != 0 {
			t.Fatalf("non-empty pcr select bitmap: %x", sel.PCRSelections[0].PCRSelect)
		}
	}
}

func TestBuildPCRSelection_SetsBitsCorrectly(t *testing.T) {
	sel := buildPCRSelection(pcrBankSHA256, []int32{0, 7, 15})
	bm := sel.PCRSelections[0].PCRSelect
	if bm[0] != 0x81 { // bits 0 and 7
		t.Fatalf("byte 0 = %#x, want 0x81", bm[0])
	}
	if bm[1] != 0x80 { // bit 15 = byte 1 bit 7
		t.Fatalf("byte 1 = %#x, want 0x80", bm[1])
	}
}

func TestBuildPCRSelection_IgnoresOutOfRange(t *testing.T) {
	sel := buildPCRSelection(pcrBankSHA256, []int32{-1, 24, 100, 3})
	bm := sel.PCRSelections[0].PCRSelect
	if bm[0] != 0x08 {
		t.Fatalf("byte 0 = %#x, want 0x08", bm[0])
	}
	if bm[1] != 0 || bm[2] != 0 {
		t.Fatalf("out-of-range PCR leaked into bitmap: %x", bm)
	}
}
