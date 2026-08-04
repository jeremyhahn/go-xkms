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
	"context"
	"encoding/base64"
	"errors"
	"testing"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// These tests close gaps left by tpm_test.go that do not require a live TPM
// (real or simulated): the TPMOpenerFunc adapter, the pcrBankName lookup
// table, and DecodeTPMSealBlobs' length-mismatch guard. None of them touch
// /dev/tpmrm0 or any other host device.

// ---------------------------------------------------------------------------
// TPMOpenerFunc adapter
// ---------------------------------------------------------------------------

// TestTPMOpenerFunc_Open proves the function-adapter forwards both the
// context and the return values to the wrapped function without alteration.
func TestTPMOpenerFunc_Open(t *testing.T) {
	wantErr := errors.New("gaps: injected open failure")
	var called context.Context
	f := TPMOpenerFunc(func(ctx context.Context) (transport.TPMCloser, error) {
		called = ctx
		return nil, wantErr
	})

	ctx := context.WithValue(context.Background(), struct{ key string }{"k"}, "v")
	tpm, err := f.Open(ctx)
	if tpm != nil {
		t.Fatalf("expected nil TPMCloser, got %v", tpm)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Open() err = %v, want %v", err, wantErr)
	}
	if called != ctx {
		t.Fatal("Open() did not forward the context to the wrapped function")
	}
}

// ---------------------------------------------------------------------------
// DefaultTPMOpener construction
//
// DefaultTPMOpener() itself only builds and returns a TPMOpenerFunc closure;
// invoking that closure's Open() would dial the host's real /dev/tpmrm0,
// which project policy forbids in unit tests (tests must never touch host
// hardware/state). We therefore only assert on construction, never call
// Open() on the result — the closure body that touches /dev/tpmrm0 is
// intentionally left to the tpm_simulator-gated round-trip tests, which
// substitute an in-memory simulator via a distinct TPMOpener.
// ---------------------------------------------------------------------------

// TestDefaultTPMOpener_ReturnsNonNilOpener proves the constructor produces a
// usable TPMOpener value without dialing any transport.
func TestDefaultTPMOpener_ReturnsNonNilOpener(t *testing.T) {
	opener := DefaultTPMOpener()
	if opener == nil {
		t.Fatal("DefaultTPMOpener() returned nil")
	}
	if _, ok := opener.(TPMOpenerFunc); !ok {
		t.Fatalf("DefaultTPMOpener() returned %T, want TPMOpenerFunc", opener)
	}
}

// ---------------------------------------------------------------------------
// pcrBankName
// ---------------------------------------------------------------------------

func TestPCRBankName_AllBanks(t *testing.T) {
	cases := []struct {
		alg  libtpm2.TPMAlgID
		want string
	}{
		{libtpm2.TPMAlgSHA1, "sha1"},
		{libtpm2.TPMAlgSHA256, "sha256"},
		{libtpm2.TPMAlgSHA384, "sha384"},
		{libtpm2.TPMAlgSHA512, "sha512"},
		{libtpm2.TPMAlgID(0xFFFF), "sha256"}, // unknown alg falls back to sha256
	}
	for _, tc := range cases {
		if got := pcrBankName(tc.alg); got != tc.want {
			t.Errorf("pcrBankName(%#x) = %q, want %q", tc.alg, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// DecodeTPMSealBlobs length-mismatch guard (distinct from the "too short"
// case already covered in tpm_test.go — here the blob is long enough to
// carry a length prefix, but the prefix claims more public-key bytes than
// actually follow it).
// ---------------------------------------------------------------------------

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
// Seal wrapper error propagation
// ---------------------------------------------------------------------------

// TestTPMSealer_Seal_PropagatesSealPassphraseError proves the narrow Seal()
// wrapper returns SealPassphrase's error untouched (with nil passphrase and
// token) instead of masking it. The success path is exercised against the
// simulator in tpm_simulator_fault_test.go.
func TestTPMSealer_Seal_PropagatesSealPassphraseError(t *testing.T) {
	h, err := NewTPMSealer(nil, erroringOpener{err: ErrTPMNoTransport})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	passphrase, tokenJSON, err := h.Seal(context.Background(), "", nil)
	if !errors.Is(err, ErrTPMNoTransport) {
		t.Fatalf("Seal() err = %v, want ErrTPMNoTransport", err)
	}
	if passphrase != nil || tokenJSON != nil {
		t.Fatalf("Seal() on error = (%v, %v), want (nil, nil)", passphrase, tokenJSON)
	}
}
