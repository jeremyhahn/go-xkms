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

//go:build tpm_simulator

package tpm2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newSimBackend boots an in-memory go-tpm-tools simulator (never the host
// /dev/tpm* device — UseSimulator with an empty SimulatorHost selects the
// process-local simulator) and returns a provisioned Backend. The simulator
// and its temp key directory are torn down by t.Cleanup so no state escapes
// the test.
//
// go-tpm-tools' simulator.Get() is a process-wide singleton guarded by a
// mutex, so exactly one live simulator backend may exist at a time. Each test
// must therefore create at most one backend and let Cleanup close it before
// the next test runs; never nest two newSimBackend calls.
func newSimBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := NewBackend(&Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
		CN:           "importexport-test",
	})
	if err != nil {
		t.Fatalf("NewBackend on simulator: %v", err)
	}
	t.Cleanup(func() {
		if cerr := b.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	return b
}

// wrapMaterial runs the production GetImportParameters → WrapKey sequence and
// returns both artifacts.
func wrapMaterial(t *testing.T, b *Backend, material []byte) (*backend.ImportParameters, *backend.WrappedKeyMaterial) {
	t.Helper()
	ctx := context.Background()
	params, err := b.GetImportParameters(ctx, &types.KeyAttributes{CN: "wrap-target", StoreType: types.StoreTPM2}, importExportAlgorithm)
	if err != nil {
		t.Fatalf("GetImportParameters: %v", err)
	}
	wrapped, err := b.WrapKey(ctx, material, params)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	return params, wrapped
}

// TestImportExport_WrapUnwrapRoundTrip is the core contract of the TCG
// duplication path: material wrapped to the SRK must come back byte-identical
// after TPM2_Import + TPM2_Load + TPM2_Unseal, and the wrapped blob must never
// contain the plaintext. The plaintext-leak assertion is the security-critical
// half: a regression that skipped CreateDuplicate and shipped the sensitive
// area in the clear would still round-trip successfully.
func TestImportExport_WrapUnwrapRoundTrip(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()

	// Cover a short symmetric key, an AES-256 key, and an over-a-block secret
	// so the keyedhash sensitive-area sizing is exercised at several lengths.
	sizes := []int{16, 32, 64}
	for _, size := range sizes {
		material := make([]byte, size)
		if _, err := rand.Read(material); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}

		params, wrapped := wrapMaterial(t, b, material)

		if wrapped.Algorithm != importExportAlgorithm {
			t.Errorf("size %d: wrapped algorithm = %q, want %q", size, wrapped.Algorithm, importExportAlgorithm)
		}
		if wrapped.Metadata[tpmDuplicateMetaKey] != "1" {
			t.Errorf("size %d: duplication metadata marker missing: %v", size, wrapped.Metadata)
		}
		if bytes.Contains(wrapped.WrappedKey, material) {
			t.Fatalf("size %d: plaintext key material appears verbatim in the wrapped blob", size)
		}

		// The serialized blob must carry all three duplication fields.
		var blob duplicationBlob
		if err := json.Unmarshal(wrapped.WrappedKey, &blob); err != nil {
			t.Fatalf("size %d: wrapped blob is not valid JSON: %v", size, err)
		}
		if len(blob.Public) == 0 || len(blob.Duplicate) == 0 || len(blob.EncSecret) == 0 {
			t.Fatalf("size %d: duplication blob missing fields: public=%d duplicate=%d encSecret=%d",
				size, len(blob.Public), len(blob.Duplicate), len(blob.EncSecret))
		}
		if bytes.Contains(blob.Duplicate, material) || bytes.Contains(blob.EncSecret, material) {
			t.Fatalf("size %d: plaintext leaked into the duplication or seed field", size)
		}

		recovered, err := b.UnwrapKey(ctx, wrapped, params)
		if err != nil {
			t.Fatalf("size %d: UnwrapKey: %v", size, err)
		}
		if !bytes.Equal(recovered, material) {
			t.Fatalf("size %d: unwrapped material differs from the original\n got %x\nwant %x", size, recovered, material)
		}
	}
}

// TestWrapKey_IsNonDeterministic proves each WrapKey call draws fresh
// randomness (the obfuscation value and the duplication seed). Two identical
// inputs producing an identical blob would mean the seed was fixed, which
// breaks the confidentiality of the duplication protocol.
func TestWrapKey_IsNonDeterministic(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	material := bytes.Repeat([]byte{0xA5}, 32)

	params, first := wrapMaterial(t, b, material)
	second, err := b.WrapKey(ctx, material, params)
	if err != nil {
		t.Fatalf("WrapKey (second): %v", err)
	}
	if bytes.Equal(first.WrappedKey, second.WrappedKey) {
		t.Fatal("two WrapKey calls on identical material produced identical blobs; the duplication seed is not random")
	}

	// Both must still unwrap to the same plaintext.
	for i, w := range []*backend.WrappedKeyMaterial{first, second} {
		got, err := b.UnwrapKey(ctx, w, params)
		if err != nil {
			t.Fatalf("UnwrapKey #%d: %v", i, err)
		}
		if !bytes.Equal(got, material) {
			t.Fatalf("UnwrapKey #%d recovered %x, want %x", i, got, material)
		}
	}
}

// TestGetImportParameters_ReturnsSRKWrappingKey verifies the returned wrapping
// key really is the TPM's Storage Root Key public area and that ImportToken
// carries the SRK Name. Wrapping to the wrong key would produce blobs the TPM
// silently refuses to import later, far from the point of failure.
func TestGetImportParameters_ReturnsSRKWrappingKey(t *testing.T) {
	b := newSimBackend(t)

	params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{CN: "k"}, importExportAlgorithm)
	if err != nil {
		t.Fatalf("GetImportParameters: %v", err)
	}
	if params.Algorithm != importExportAlgorithm {
		t.Errorf("Algorithm = %q, want %q", params.Algorithm, importExportAlgorithm)
	}
	if params.KeySpec != "TPM2_KEYEDHASH" {
		t.Errorf("KeySpec = %q, want TPM2_KEYEDHASH", params.KeySpec)
	}

	srkName, srkPub, err := b.srkPublicContents()
	if err != nil {
		t.Fatalf("srkPublicContents: %v", err)
	}
	if !bytes.Equal(params.ImportToken, srkName.Buffer) {
		t.Errorf("ImportToken does not match the SRK Name\n got %x\nwant %x", params.ImportToken, srkName.Buffer)
	}

	// The default SRK in this config is RSA-2048; the wrapping public key must
	// be the very same modulus the TPM reports.
	rsaPub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("WrappingPublicKey type = %T, want *rsa.PublicKey", params.WrappingPublicKey)
	}
	expected, err := b.tpm.ParsePublicKey(gotpm2.Marshal(srkPub))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	expectedRSA, ok := expected.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("SRK public key type = %T, want *rsa.PublicKey", expected)
	}
	if !rsaPub.Equal(expectedRSA) {
		t.Error("WrappingPublicKey is not the SRK public key")
	}
}

// TestGetImportParameters_Errors covers every rejection branch: a nil
// attribute set, a wrapping algorithm the TPM cannot honor (the TPM uses TCG
// duplication, never RSA-OAEP/AES-KWP), and a closed backend.
func TestGetImportParameters_Errors(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	attrs := &types.KeyAttributes{CN: "k"}

	if _, err := b.GetImportParameters(ctx, nil, importExportAlgorithm); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("nil attrs error = %v, want ErrInvalidKeyAttributes", err)
	}

	for _, algo := range []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		backend.WrappingAlgorithm(""),
	} {
		if _, err := b.GetImportParameters(ctx, attrs, algo); !errors.Is(err, ErrUnsupportedOperation) {
			t.Errorf("algorithm %q error = %v, want ErrUnsupportedOperation", algo, err)
		}
	}
}

// TestWrapKey_Errors covers the input-validation branches. Empty material in
// particular must be rejected: a sealed object with a zero-length secret would
// unwrap to an empty key and silently weaken whatever consumed it.
func TestWrapKey_Errors(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	params, _ := wrapMaterial(t, b, []byte("seed material"))

	if _, err := b.WrapKey(ctx, nil, params); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("nil material error = %v, want ErrInvalidKeyAttributes", err)
	}
	if _, err := b.WrapKey(ctx, []byte{}, params); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("empty material error = %v, want ErrInvalidKeyAttributes", err)
	}
	if _, err := b.WrapKey(ctx, []byte("material"), nil); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("nil params error = %v, want ErrInvalidKeyAttributes", err)
	}

	wrongAlgo := &backend.ImportParameters{Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_1}
	if _, err := b.WrapKey(ctx, []byte("material"), wrongAlgo); !errors.Is(err, ErrUnsupportedOperation) {
		t.Errorf("wrong algorithm error = %v, want ErrUnsupportedOperation", err)
	}
}

// TestUnwrapKey_RejectsCorruptBlobs proves a tampered or truncated duplication
// blob is refused with a typed error instead of yielding garbage key material.
// Each case corrupts a different layer: the JSON envelope, the marshaled
// public area, the outer-wrapped private area, and the encrypted seed.
func TestUnwrapKey_RejectsCorruptBlobs(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	material := bytes.Repeat([]byte{0x5A}, 32)
	params, wrapped := wrapMaterial(t, b, material)

	var good duplicationBlob
	if err := json.Unmarshal(wrapped.WrappedKey, &good); err != nil {
		t.Fatalf("unmarshal reference blob: %v", err)
	}

	reencode := func(t *testing.T, blob duplicationBlob) *backend.WrappedKeyMaterial {
		t.Helper()
		encoded, err := json.Marshal(blob)
		if err != nil {
			t.Fatalf("re-encode blob: %v", err)
		}
		return &backend.WrappedKeyMaterial{WrappedKey: encoded, Algorithm: importExportAlgorithm}
	}

	t.Run("nil wrapped", func(t *testing.T) {
		if _, err := b.UnwrapKey(ctx, nil, params); !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("error = %v, want ErrInvalidKeyAttributes", err)
		}
	})

	t.Run("empty wrapped key", func(t *testing.T) {
		if _, err := b.UnwrapKey(ctx, &backend.WrappedKeyMaterial{}, params); !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("error = %v, want ErrInvalidKeyAttributes", err)
		}
	})

	t.Run("not JSON", func(t *testing.T) {
		w := &backend.WrappedKeyMaterial{WrappedKey: []byte("\x00\x01 definitely not json")}
		if _, err := b.UnwrapKey(ctx, w, params); !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("error = %v, want ErrInvalidKeyAttributes", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		w := &backend.WrappedKeyMaterial{WrappedKey: wrapped.WrappedKey[:len(wrapped.WrappedKey)/2]}
		if _, err := b.UnwrapKey(ctx, w, params); !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("error = %v, want ErrInvalidKeyAttributes", err)
		}
	})

	t.Run("malformed public area", func(t *testing.T) {
		bad := good
		bad.Public = []byte{0x00, 0x01, 0x02}
		if _, err := b.UnwrapKey(ctx, reencode(t, bad), params); !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("error = %v, want ErrInvalidKeyAttributes", err)
		}
	})

	t.Run("tampered duplicate blob", func(t *testing.T) {
		bad := good
		bad.Duplicate = append([]byte(nil), good.Duplicate...)
		bad.Duplicate[len(bad.Duplicate)-1] ^= 0xFF
		got, err := b.UnwrapKey(ctx, reencode(t, bad), params)
		if err == nil {
			t.Fatalf("UnwrapKey accepted a tampered duplication blob and returned %x", got)
		}
		if !errors.Is(err, ErrUnsupportedOperation) {
			t.Errorf("error = %v, want ErrUnsupportedOperation (TPM2_Import rejection)", err)
		}
	})

	t.Run("tampered encrypted seed", func(t *testing.T) {
		bad := good
		bad.EncSecret = append([]byte(nil), good.EncSecret...)
		bad.EncSecret[0] ^= 0xFF
		got, err := b.UnwrapKey(ctx, reencode(t, bad), params)
		if err == nil {
			t.Fatalf("UnwrapKey accepted a tampered seed and returned %x", got)
		}
		if !errors.Is(err, ErrUnsupportedOperation) {
			t.Errorf("error = %v, want ErrUnsupportedOperation (TPM2_Import rejection)", err)
		}
	})

	t.Run("truncated encrypted seed", func(t *testing.T) {
		bad := good
		bad.EncSecret = good.EncSecret[:len(good.EncSecret)-8]
		if _, err := b.UnwrapKey(ctx, reencode(t, bad), params); err == nil {
			t.Fatal("UnwrapKey accepted a truncated seed")
		}
	})

	// The reference blob must still unwrap after all the tampering attempts —
	// proves the failures above did not leave the TPM in a broken state.
	recovered, err := b.UnwrapKey(ctx, wrapped, params)
	if err != nil {
		t.Fatalf("UnwrapKey on the untampered blob after the corruption cases: %v", err)
	}
	if !bytes.Equal(recovered, material) {
		t.Fatal("untampered blob no longer round-trips")
	}
}

// TestImportKey_PersistsUnderCN proves ImportKey does more than run
// TPM2_Import: it must persist the imported public/private blobs so the key
// survives a restart. The test asserts the key becomes visible to ListKeys and
// that the persisted blobs are the ones the TPM produced.
func TestImportKey_PersistsUnderCN(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	material := bytes.Repeat([]byte{0x77}, 32)
	_, wrapped := wrapMaterial(t, b, material)

	before, err := b.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys (before): %v", err)
	}

	attrs := &types.KeyAttributes{CN: "imported-secret", KeyType: types.KeyTypeStorage}
	if err := b.ImportKey(ctx, attrs, wrapped); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	// ImportKey must normalize the attributes so the key is addressable.
	if attrs.StoreType != types.StoreTPM2 {
		t.Errorf("StoreType = %v, want StoreTPM2", attrs.StoreType)
	}
	if attrs.Parent == nil {
		t.Error("Parent was not defaulted to the SRK; the key cannot be reloaded")
	} else if attrs.Parent != b.srkAttrs {
		t.Error("Parent is not the backend SRK attributes")
	}

	after, err := b.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys (after): %v", err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("ListKeys returned %d keys after import, want %d", len(after), len(before)+1)
	}
	var found bool
	for _, k := range after {
		if k.CN == "imported-secret" {
			found = true
			if k.StoreType != types.StoreTPM2 {
				t.Errorf("listed key StoreType = %v, want StoreTPM2", k.StoreType)
			}
		}
	}
	if !found {
		t.Fatalf("imported key not enumerated by ListKeys: %+v", after)
	}
}

// TestImportKey_HonorsExplicitParent verifies an explicitly supplied parent is
// preserved rather than being overwritten by the SRK default.
func TestImportKey_HonorsExplicitParent(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	_, wrapped := wrapMaterial(t, b, bytes.Repeat([]byte{0x11}, 32))

	parent := b.srkAttrs
	attrs := &types.KeyAttributes{CN: "imported-explicit-parent", Parent: parent}
	if err := b.ImportKey(ctx, attrs, wrapped); err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if attrs.Parent != parent {
		t.Error("ImportKey replaced an explicitly supplied parent")
	}
}

// TestImportKey_Errors covers the rejection branches, including a corrupt blob
// that must fail before anything is written to the key store.
func TestImportKey_Errors(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()
	attrs := &types.KeyAttributes{CN: "bad-import"}

	if err := b.ImportKey(ctx, nil, &backend.WrappedKeyMaterial{WrappedKey: []byte("{}")}); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("nil attrs error = %v, want ErrInvalidKeyAttributes", err)
	}
	if err := b.ImportKey(ctx, attrs, nil); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("nil wrapped error = %v, want ErrInvalidKeyAttributes", err)
	}
	if err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{}); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("empty wrapped error = %v, want ErrInvalidKeyAttributes", err)
	}
	if err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{WrappedKey: []byte("not json")}); !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("corrupt blob error = %v, want ErrInvalidKeyAttributes", err)
	}

	// Nothing should have been persisted for the failed imports.
	keys, err := b.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	for _, k := range keys {
		if k.CN == "bad-import" {
			t.Fatal("a failed ImportKey persisted key blobs")
		}
	}
}

// TestImportExport_ClosedBackendRefusesAll covers the shutdown guard on every
// import/export entry point in a single test, because the go-tpm-tools
// simulator singleton allows only one live backend per process. A closed
// backend must return ErrNotInitialized rather than dereference a torn-down
// transport, which would panic inside the TPM command path.
func TestImportExport_ClosedBackendRefusesAll(t *testing.T) {
	ctx := context.Background()
	b := newSimBackend(t)

	// Capture a valid blob while the backend is still live so the closed-state
	// assertions exercise the guard rather than an input-validation branch.
	params, wrapped := wrapMaterial(t, b, bytes.Repeat([]byte{0x33}, 32))
	attrs := &types.KeyAttributes{CN: "post-close"}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close must be idempotent; a second Close from t.Cleanup must not fault.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := b.GetImportParameters(ctx, attrs, importExportAlgorithm); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("GetImportParameters error = %v, want ErrNotInitialized", err)
	}
	if _, err := b.WrapKey(ctx, []byte("material"), params); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("WrapKey error = %v, want ErrNotInitialized", err)
	}
	if _, err := b.UnwrapKey(ctx, wrapped, params); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("UnwrapKey error = %v, want ErrNotInitialized", err)
	}
	if err := b.ImportKey(ctx, attrs, wrapped); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("ImportKey error = %v, want ErrNotInitialized", err)
	}
}

// TestSetTPM_AdoptsExternalInstance covers the connection-sharing seam used by
// xkey, which hands its own TPM into the xkms backend so both reach the same
// PlatformKeyStore and policy state. After SetTPM the backend must (a) use the
// supplied instance and (b) mark it externally owned so Close() does not tear
// down a connection the caller still needs — the regression that previously
// produced "transport closed" faults in the GUI.
func TestSetTPM_AdoptsExternalInstance(t *testing.T) {
	owner := newSimBackend(t)

	// A consumer backend that has no TPM of its own, mirroring how xkey
	// constructs a backend and then injects the GUI's shared TPM.
	consumer := &Backend{}
	if consumer.TPM() != nil {
		t.Fatal("a zero-value Backend unexpectedly has a TPM")
	}

	consumer.SetTPM(owner.TPM())
	if consumer.TPM() != owner.TPM() {
		t.Fatal("SetTPM did not install the supplied TPM instance")
	}
	if !consumer.externalTPM {
		t.Fatal("SetTPM did not mark the TPM as externally owned")
	}

	// Closing the consumer must be a no-op for the shared TPM.
	if err := consumer.Close(); err != nil {
		t.Fatalf("Close after SetTPM: %v", err)
	}
	if _, _, err := owner.srkPublicContents(); err != nil {
		t.Fatalf("owner TPM unusable after the consumer closed the shared instance: %v", err)
	}
}
