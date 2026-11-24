//go:build tpm_simulator

// Tests behind docs/enclaveprovider/tpm-equivalence.md: the enclave provider
// over this package's Sealer leaves no TPM handle behind, reports tampering as
// sealed-data authentication, and honours a context that ends between TPM
// commands, as go-enclave's backends/tpm did.

package tpm2

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// transientCount returns the number of transient objects loaded in the TPM.
func transientCount(t *testing.T, tr transport.TPM) int {
	t.Helper()
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 255,
	}.Execute(tr)
	require.NoError(t, err)
	handles, err := resp.CapabilityData.Data.Handles()
	require.NoError(t, err)
	return len(handles.Handle)
}

// handleCounts is the number of transient objects and loaded sessions.
type handleCounts struct{ transients, sessions int }

func countHandles(t *testing.T, h *simHarness) handleCounts {
	t.Helper()
	return handleCounts{transientCount(t, h.TPM.transport), loadedSessionCount(t, h.TPM.transport)}
}

// newEquivalenceProtector builds the provider as
// TestEnclaveProvider_Conformance_Simulator does, under the sealed-key name cn.
func newEquivalenceProtector(t *testing.T, h *simHarness, cn string) (*enclaveprovider.KeyProtector, *types.KeyAttributes) {
	t.Helper()
	attrs := sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword))
	p, err := enclaveprovider.NewKeyProtector(h.TPM, attrs)
	require.NoError(t, err)
	return p, attrs
}

// envelopeTPMPrivate returns the offsets of the TPMPrivate field's contents
// in an envelope: a 6-byte header, then length-prefixed fields Backend,
// KeyID, Ciphertext, Nonce, Tag, WrappedDEK, TPMPublic, TPMPrivate
// (pkg/enclaveprovider/envelope.go decodeEnvelope).
func envelopeTPMPrivate(t *testing.T, blob []byte) (start, end int) {
	t.Helper()
	off := 6
	for i := 0; i < 8; i++ {
		require.LessOrEqual(t, off+4, len(blob))
		n := int(binary.BigEndian.Uint32(blob[off:]))
		start, end = off+4, off+4+n
		require.LessOrEqual(t, end, len(blob))
		off = end
	}
	require.Greater(t, end, start, "the envelope carries a sealed private area")
	return start, end
}

func protectKey(t *testing.T, p *enclaveprovider.KeyProtector) ([]byte, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x5c}, enclave.RootKeyBytes)
	blob, err := p.Protect(context.Background(), key)
	require.NoError(t, err)
	return key, blob
}

// TestEnclaveProvider_NoHandleResidue_Simulator: every provider call, on
// success and on each refusal, leaves the TPM's transient objects and loaded
// sessions as it found them (tpm-equivalence.md rows 17 and 31a).
func TestEnclaveProvider_NoHandleResidue_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	p, _ := newEquivalenceProtector(t, h, "enclave-residue")
	ctx := context.Background()

	// Warm up the caches (SRK name, salt key) the first call fills.
	key, blob := protectKey(t, p)
	baseline := countHandles(t, h)

	blob, err := p.Protect(ctx, key)
	require.NoError(t, err)
	require.Equal(t, baseline, countHandles(t, h), "after Protect")

	dst := make([]byte, enclave.RootKeyBytes)
	require.NoError(t, p.Unprotect(ctx, blob, dst))
	require.Equal(t, key, dst)
	require.Equal(t, baseline, countHandles(t, h), "after Unprotect")

	tampered := bytes.Clone(blob)
	start, end := envelopeTPMPrivate(t, tampered)
	tampered[(start+end)/2] ^= 0x01
	err = p.Unprotect(ctx, tampered, make([]byte, enclave.RootKeyBytes))
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.Equal(t, baseline, countHandles(t, h), "after a tampered Unprotect")

	err = p.Unprotect(ctx, blob, make([]byte, enclave.RootKeyBytes-1))
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.Equal(t, baseline, countHandles(t, h), "after a wrong-length Unprotect")
}

// TestEnclaveProvider_AuthenticationFailure_Simulator: a sealed private area
// changed in the envelope, or spliced in from another envelope, is refused by
// TPM2_Load and reported as enclave.ErrSealedAuthentication with the
// destination untouched (tpm-equivalence.md row 12). The envelope tag is
// keyed by the sealed key itself and checked only after a successful unseal,
// so the TPM layer is the one that refuses here.
func TestEnclaveProvider_AuthenticationFailure_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	p, _ := newEquivalenceProtector(t, h, "enclave-auth-a")
	other, _ := newEquivalenceProtector(t, h, "enclave-auth-b")

	_, blob := protectKey(t, p)
	_, foreign := protectKey(t, other)
	baseline := countHandles(t, h)

	flipped := bytes.Clone(blob)
	start, end := envelopeTPMPrivate(t, flipped)
	flipped[(start+end)/2] ^= 0x01

	spliced := bytes.Clone(blob)
	fs, fe := envelopeTPMPrivate(t, foreign)
	require.Equal(t, end-start, fe-fs, "both envelopes carry the same size of private area")
	copy(spliced[start:end], foreign[fs:fe])

	for name, tampered := range map[string][]byte{
		"private area byte flipped":          flipped,
		"private area of another sealed key": spliced,
	} {
		t.Run(name, func(t *testing.T) {
			dst := bytes.Repeat([]byte{0xA5}, enclave.RootKeyBytes)
			err := p.Unprotect(context.Background(), tampered, dst)
			require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication, "the TPM sealer, not the envelope tag, refused")
			require.Equal(t, bytes.Repeat([]byte{0xA5}, enclave.RootKeyBytes), dst)
			require.Equal(t, baseline, countHandles(t, h))
		})
	}
}
