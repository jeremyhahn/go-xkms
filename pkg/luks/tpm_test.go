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
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// These tests exercise the non-TPM portions of the LUKS TPM sealer
// (constructor, handle resolution, token encoding, PCR selection). Full
// round-trip tests against a software TPM live in tpm_simulator_test.go and
// are gated behind the `tpm_simulator` build tag so they only run in
// environments that ship the go-tpm-tools simulator.

// ---------------------------------------------------------------------------
// Constructor & opener behaviour
// ---------------------------------------------------------------------------

func TestNewTPMSealer_NilOpener(t *testing.T) {
	_, err := NewTPMSealer(nil, nil)
	if !errors.Is(err, ErrTPMNoTransport) {
		t.Fatalf("expected ErrTPMNoTransport, got %v", err)
	}
}

func TestTPMSealer_WithParentHandle_ZeroResetsToDefault(t *testing.T) {
	h, err := NewTPMSealer(nil, erroringOpener{err: ErrTPMNoTransport})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	h = h.WithParentHandle(0x81000099)
	if h.parentHandle != 0x81000099 {
		t.Fatalf("parentHandle = %#x, want 0x81000099", h.parentHandle)
	}
	h = h.WithParentHandle(0)
	if h.parentHandle != DefaultTPMParentHandle {
		t.Fatalf("parentHandle after zero = %#x, want default", h.parentHandle)
	}
}

func TestTPMSealer_OpenFailure_Surfaces(t *testing.T) {
	h, err := NewTPMSealer(nil, erroringOpener{err: ErrTPMNoTransport})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = h.SealPassphrase(context.Background(), "", []int32{7})
	if !errors.Is(err, ErrTPMNoTransport) {
		t.Fatalf("expected ErrTPMNoTransport, got %v", err)
	}

	_, err = h.UnsealPassphrase(context.Background(), []byte(`{"tpm2-blob":"AAAAAA=="}`))
	if !errors.Is(err, ErrTPMNoTransport) {
		t.Fatalf("expected ErrTPMNoTransport from unseal, got %v", err)
	}
}

func TestTPMSealer_Seal_InvalidHandle(t *testing.T) {
	h, err := NewTPMSealer(nil, erroringOpener{err: ErrTPMNoTransport})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = h.SealPassphrase(context.Background(), "not-a-number", nil)
	if !errors.Is(err, ErrTPMInvalidHandle) {
		t.Fatalf("expected ErrTPMInvalidHandle, got %v", err)
	}
}

func TestTPMSealer_Unseal_InvalidTokenJSON(t *testing.T) {
	h, err := NewTPMSealer(nil, erroringOpener{err: ErrTPMNoTransport})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = h.UnsealPassphrase(context.Background(), []byte("not-json"))
	if !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken, got %v", err)
	}
}

func TestTPMSealer_Unseal_InvalidBlob(t *testing.T) {
	h, err := NewTPMSealer(nil, erroringOpener{err: ErrTPMNoTransport})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	_, err = h.UnsealPassphrase(context.Background(), []byte(`{"tpm2-blob":"AAAA"}`))
	if !errors.Is(err, ErrTPMInvalidToken) {
		t.Fatalf("expected ErrTPMInvalidToken for short blob, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Handle parsing
// ---------------------------------------------------------------------------

func TestResolveParentHandle_Defaults(t *testing.T) {
	h, err := resolveParentHandle("", 0x81000001)
	if err != nil || h != 0x81000001 {
		t.Fatalf("resolveParentHandle empty = %#x/%v, want 0x81000001/nil", h, err)
	}
}

func TestResolveParentHandle_HexAndDecimal(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"0x81000002", 0x81000002},
		{"81000002", 0x81000002},
		{"2164260865", 2164260865}, // decimal == 0x81000001
	}
	for _, tc := range cases {
		got, err := resolveParentHandle(tc.in, 0)
		if err != nil {
			t.Fatalf("resolveParentHandle(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("resolveParentHandle(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

func TestResolveParentHandle_Invalid(t *testing.T) {
	_, err := resolveParentHandle("not-a-number", 0x81000001)
	if !errors.Is(err, ErrTPMInvalidHandle) {
		t.Fatalf("expected ErrTPMInvalidHandle, got %v", err)
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

// ---------------------------------------------------------------------------
// PCR selection
// ---------------------------------------------------------------------------

// pcrBankSHA256 is the SHA-256 algorithm id from the TCG spec. We use the
// numeric value to avoid re-importing the tpm2 alg constants.
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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// erroringOpener is a TPMOpener stub that short-circuits with the configured
// error. It lets us exercise the sealer's error surface without pulling in
// the simulator.
type erroringOpener struct {
	err error
}

// Open satisfies the TPMOpener contract.
func (e erroringOpener) Open(context.Context) (transport.TPMCloser, error) {
	return nil, e.err
}
