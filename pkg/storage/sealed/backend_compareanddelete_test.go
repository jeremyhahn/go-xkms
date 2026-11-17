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

package sealed

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The contract body lives in storagetest so every backend is held to one
// definition of the semantics. This file supplies the fixture and then adds the
// one property the shared contract cannot see: which bytes reach the inner
// backend as the guard.
//
// AllowsEmptyValue is TRUE, measured rather than assumed. It was the one value
// worth checking here, because the stored form is a sealed envelope and an
// empty plaintext is NOT an empty stored value: Put seals []byte{} into a
// non-empty JSON envelope, Exists reports true, and Get unseals back to a
// zero-length plaintext that a nil guard must match.
func TestBackend_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b := newTestBackend(t)
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		Key:              "keys/contract-subject",
		AllowsEmptyValue: true,
	})
}

// randomizingSealer is a test sealer whose Seal is NON-DETERMINISTIC: it draws a
// fresh random nonce per call and uses it as the XOR keystream, so sealing the
// same plaintext twice produces different stored bytes. It is not
// cryptographically meaningful and must never be used outside tests.
//
// The package's existing mockSealer XORs with a constant 0xFF and is therefore
// deterministic, which makes it blind to the defect the tests below exist to
// catch: an implementation that re-sealed `expected` to build the guard would
// still produce matching bytes under mockSealer and pass. Real sealers
// (AES-GCM, TPM) are randomised, so the property has to be tested against a
// randomised one.
type randomizingSealer struct{}

func (randomizingSealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	for i, b := range data {
		ciphertext[i] = b ^ nonce[i%len(nonce)]
	}
	return &types.SealedData{
		Backend:    "software",
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (randomizingSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	plaintext := make([]byte, len(sealed.Ciphertext))
	for i, b := range sealed.Ciphertext {
		plaintext[i] = b ^ sealed.Nonce[i%len(sealed.Nonce)]
	}
	return plaintext, nil
}

func (randomizingSealer) CanSeal() bool { return true }

// Sealing is randomised, so the guard handed to the inner backend MUST be the
// envelope that was read, never a fresh seal of expected.
//
// This is the difference between a working guarded release and one that refuses
// every release forever — a silent no-op, worse than the race it was meant to
// close, because the caller is told deleted=false and believes some other
// holder won.
//
// The first assertion is what makes the bug possible and is stated explicitly so
// the reason for the second is not left implicit: two Puts of the SAME plaintext
// produce DIFFERENT stored bytes. The second is the property: a release guarded
// on the correct plaintext succeeds anyway.
func TestBackend_CompareAndDelete_GuardsOnStoredEnvelopeNotAFreshSeal(t *testing.T) {
	ctx := context.Background()
	inner := storage.NewMemory()
	b, err := New(inner, randomizingSealer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	const key = "keys/contract-subject"
	plaintext := []byte("the same plaintext, twice")

	if err := b.Put(ctx, key, plaintext); err != nil {
		t.Fatalf("Put (first): %v", err)
	}
	firstEnvelope, err := inner.Get(ctx, key)
	if err != nil {
		t.Fatalf("inner Get (first): %v", err)
	}
	firstEnvelope = append([]byte(nil), firstEnvelope...)

	if err := b.Put(ctx, key, plaintext); err != nil {
		t.Fatalf("Put (second): %v", err)
	}
	secondEnvelope, err := inner.Get(ctx, key)
	if err != nil {
		t.Fatalf("inner Get (second): %v", err)
	}

	if bytes.Equal(firstEnvelope, secondEnvelope) {
		t.Fatal("this sealer is supposed to be randomised: two seals of the same " +
			"plaintext produced identical bytes, so the test below would prove nothing")
	}

	// A re-encrypting implementation would compare a third, freshly sealed
	// envelope against the stored one, never match, and refuse here.
	deleted, err := b.CompareAndDelete(ctx, key, plaintext)
	if err != nil {
		t.Fatalf("CompareAndDelete: %v", err)
	}
	if !deleted {
		t.Fatal("a release guarded on the correct plaintext must succeed against a " +
			"randomised sealer; the guard must be the STORED envelope, not a fresh seal")
	}
	if ok, err := b.Exists(ctx, key); err != nil || ok {
		t.Fatalf("key must be gone after the release: exists=%v err=%v", ok, err)
	}
}

// The plaintext compare must still be a real compare under a randomised sealer:
// a wrong guard is refused and the envelope is left exactly as it was.
func TestBackend_CompareAndDelete_RandomisedSealerStillRefusesAWrongGuard(t *testing.T) {
	ctx := context.Background()
	inner := storage.NewMemory()
	b, err := New(inner, randomizingSealer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	const key = "keys/contract-subject"
	if err := b.Put(ctx, key, []byte("value-A")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before, err := inner.Get(ctx, key)
	if err != nil {
		t.Fatalf("inner Get: %v", err)
	}
	before = append([]byte(nil), before...)

	deleted, err := b.CompareAndDelete(ctx, key, []byte("value-B"))
	if err != nil {
		t.Fatalf("mismatched guard must not be an error, got %v", err)
	}
	if deleted {
		t.Fatal("mismatched guard must report deleted=false")
	}

	after, err := inner.Get(ctx, key)
	if err != nil {
		t.Fatalf("inner Get after refusal: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused release must not rewrite the stored envelope")
	}
}

// sealForTest produces an envelope the way the backend stores one, so the
// enclave tests operate on a real sealed value rather than a hand-built struct.
func sealForTest(t *testing.T, s types.Sealer, plaintext []byte) *types.SealedData {
	t.Helper()
	sealed, err := s.Seal(context.Background(), plaintext, nil)
	require.NoError(t, err)
	return sealed
}

// THE ESCAPE CHECK. Decryption APPENDS, so a destination too small to hold the
// plaintext does not fail — it allocates a new slice on the heap, decrypts into
// that, and returns it. Every subsequent line then works perfectly, on plaintext
// sitting in ordinary swappable memory, and the comparison still produces the
// right answer. Nothing about the result would reveal it.
//
// That silent success is the failure mode this whole path exists to prevent, so
// it is tested by deliberately under-sizing the locked region by one byte and
// asserting the escape is caught rather than compared.
func TestCompareInEnclave_DetectsPlaintextEscapingToTheHeap(t *testing.T) {
	ctx := context.Background()
	sealer := randomizingSealer{}
	plaintext := []byte("super-secret-material")
	sealed := sealForTest(t, sealer, plaintext)

	n, err := sealer.PlaintextLen(sealed)
	require.NoError(t, err)
	require.Equal(t, len(plaintext), n, "the sizing must be exact for this test to mean anything")

	// One byte short: go-enclave slices its region with cap == len, so the
	// decryption cannot fit and must reallocate onto the heap.
	enc, err := enclave.NewMemorySized(n - 1)
	require.NoError(t, err)
	defer enc.Destroy()

	matched, err := compareInEnclave(ctx, enc, sealer, sealed, plaintext)

	require.Error(t, err, "a decryption that landed on the heap must not be reported as a comparison")
	assert.ErrorIs(t, err, ErrGuardEscapedEnclave)
	assert.ErrorIs(t, err, ErrGuardEnclaveFailed, "and it surfaces as an enclave failure to the caller")
	assert.False(t, matched)
}

// The correctly sized region is the control: the same call succeeds and compares
// both ways, so the guard above cannot be satisfied by a function that simply
// always errors.
func TestCompareInEnclave_CorrectlySizedEnclaveComparesBothWays(t *testing.T) {
	ctx := context.Background()
	sealer := randomizingSealer{}
	plaintext := []byte("super-secret-material")

	for _, tc := range []struct {
		name      string
		expected  []byte
		wantMatch bool
	}{
		{"match", plaintext, true},
		{"mismatch", []byte("something-else-entirely"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed := sealForTest(t, sealer, plaintext)
			n, err := sealer.PlaintextLen(sealed)
			require.NoError(t, err)

			enc, err := enclave.NewMemorySized(n)
			require.NoError(t, err)
			defer enc.Destroy()

			matched, err := compareInEnclave(ctx, enc, sealer, sealed, tc.expected)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatch, matched)
		})
	}
}

// An enclave that cannot be read must produce an ERROR, never (false, nil).
//
// deleted=false is a load-bearing claim -- "the guard was evaluated and it lost"
// -- and a caller acts on it by giving up its claim. A comparison that never ran
// reporting false would make the caller abandon a claim it still holds.
//
// It is reachable rather than theoretical: NewMemoryEnclaveSized documents that
// it can return a successful but ALREADY-DESTROYED enclave when WipeAll runs
// between publication and return. Destroying explicitly reproduces that state
// deterministically instead of trying to win a race in a test.
func TestCompareInEnclave_UnreadableEnclaveIsAnErrorNotARefusal(t *testing.T) {
	ctx := context.Background()
	sealer := randomizingSealer{}
	plaintext := []byte("super-secret-material")
	sealed := sealForTest(t, sealer, plaintext)
	n, err := sealer.PlaintextLen(sealed)
	require.NoError(t, err)

	t.Run("destroyed before the comparison", func(t *testing.T) {
		enc, err := enclave.NewMemorySized(n)
		require.NoError(t, err)
		enc.Destroy()

		matched, err := compareInEnclave(ctx, enc, sealer, sealed, plaintext)
		require.Error(t, err)
		assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
		assert.ErrorIs(t, err, ErrGuardEnclaveFailed)
		assert.False(t, matched)
	})

	t.Run("nil enclave", func(t *testing.T) {
		matched, err := compareInEnclave(ctx, nil, sealer, sealed, plaintext)
		require.Error(t, err)
		assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
		assert.False(t, matched)
	})
}

// An empty plaintext cannot go in an enclave -- go-enclave refuses a zero-length
// region -- and holds no secret. It must still be DECRYPTED rather than assumed:
// skipping the unseal would skip the AEAD tag check, so a corrupt envelope would
// silently "match" an empty guard. nil and empty stay equivalent per the
// storage.Backend contract.
func TestUnsealAndCompare_EmptyPlaintextIsStillAuthenticated(t *testing.T) {
	ctx := context.Background()
	sealer := randomizingSealer{}
	sealed := sealForTest(t, sealer, []byte{})

	for _, tc := range []struct {
		name      string
		expected  []byte
		wantMatch bool
	}{
		{"nil guard", nil, true},
		{"empty guard", []byte{}, true},
		{"non-empty guard", []byte("x"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := unsealAndCompare(ctx, sealer, sealed, tc.expected)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatch, matched)
		})
	}

	// The unseal is real: a sealer that fails reports an error rather than a
	// vacuous match against an empty guard.
	failing := &mockSealer{canSeal: true, unsealErr: assert.AnError}
	matched, err := unsealAndCompare(ctx, failing, &types.SealedData{}, nil)
	require.Error(t, err, "an empty plaintext must not skip authentication")
	assert.False(t, matched)
}

// A sealer without the capability must REFUSE, not fall back to the heap. The
// fallback would work and would silently put the barrier's plaintext in ordinary
// memory for that sealer only.
func TestCompareAndDelete_RefusesASealerThatCannotUnsealIntoLockedMemory(t *testing.T) {
	ctx := context.Background()
	inner := storage.NewMemory()
	t.Cleanup(func() { _ = inner.Close() })

	b, err := New(inner, heapOnlySealer{}, nil)
	require.NoError(t, err)

	const key = "keys/heap-only"
	require.NoError(t, b.Put(ctx, key, []byte("value-A")))

	deleted, err := b.CompareAndDelete(ctx, key, []byte("value-A"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsealIntoUnsupported)
	assert.False(t, deleted)

	// And nothing was removed on the way out.
	ok, existsErr := b.Exists(ctx, key)
	require.NoError(t, existsErr)
	assert.True(t, ok, "a refused release must leave the value in place")
}

// heapOnlySealer implements types.Sealer but NOT types.UnsealerInto, which is
// the combination the refusal above exists for.
type heapOnlySealer struct{}

func (heapOnlySealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	ciphertext := make([]byte, len(data))
	for i, b := range data {
		ciphertext[i] = b ^ 0xFF
	}
	return &types.SealedData{Backend: "software", Ciphertext: ciphertext}, nil
}

func (heapOnlySealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	plaintext := make([]byte, len(sealed.Ciphertext))
	for i, b := range sealed.Ciphertext {
		plaintext[i] = b ^ 0xFF
	}
	return plaintext, nil
}

func (heapOnlySealer) CanSeal() bool { return true }

// A corrupt or tampered envelope is an UNSEAL failure, not a locked-memory one.
// The enclave was readable and did its job; what failed is the AEAD tag check.
//
// The classification is load-bearing rather than cosmetic. Both faults arrive at
// the same place -- the error WithBytes returns -- so it would be easy to label
// them alike, and then an operator seeing an enclave failure would go looking at
// RLIMIT_MEMLOCK for what is actually damaged or tampered data. It also has to
// agree with the empty-plaintext path, which reports the same class as
// ErrUnsealFailed.
func TestCompareInEnclave_CorruptEnvelopeIsAnUnsealFailureNotAnEnclaveFailure(t *testing.T) {
	ctx := context.Background()
	sealer := randomizingSealer{}
	plaintext := []byte("super-secret-material")
	sealed := sealForTest(t, sealer, plaintext)

	n, err := sealer.PlaintextLen(sealed)
	require.NoError(t, err)

	enc, err := enclave.NewMemorySized(n)
	require.NoError(t, err)
	defer enc.Destroy()

	// A sealer whose unseal fails stands in for the corrupt envelope, so the
	// test does not depend on how a particular AEAD reports tampering.
	failing := &mockSealer{canSeal: true, unsealErr: assert.AnError}

	matched, err := compareInEnclave(ctx, enc, failing, sealed, plaintext)

	require.Error(t, err)
	assert.False(t, matched)
	assert.ErrorIs(t, err, ErrUnsealFailed, "a failed unseal is reported as one")
	assert.NotErrorIs(t, err, ErrGuardEnclaveFailed,
		"and must not be mistaken for a locked-memory failure")
	assert.ErrorIs(t, err, assert.AnError, "the underlying cause stays reachable")
}
