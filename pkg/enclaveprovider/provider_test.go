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

package enclaveprovider

import (
	"bytes"
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealerDouble wraps a real sealer. It records every plaintext Unseal hands
// back, so a test can prove the provider wiped it, and injects the failures
// a backend can return.
type sealerDouble struct {
	types.Sealer
	cannotSeal bool
	sealErr    error
	sealNil    bool
	unsealErr  error
	// unsealLen, when non-zero, truncates or extends the recovered plaintext.
	unsealLen int
	// mutate is applied to the attributes each call receives.
	mutate     func(*types.KeyAttributes)
	attrsSeen  []*types.KeyAttributes
	plaintexts [][]byte
	unseals    int
}

func (d *sealerDouble) CanSeal() bool { return !d.cannotSeal && d.Sealer.CanSeal() }

func (d *sealerDouble) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	d.observe(opts.KeyAttributes)
	if d.sealErr != nil {
		return nil, d.sealErr
	}
	if d.sealNil {
		return nil, nil
	}
	return d.Sealer.Seal(ctx, data, opts)
}

func (d *sealerDouble) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	d.unseals++
	d.observe(opts.KeyAttributes)
	plaintext, err := d.Sealer.Unseal(ctx, sealed, opts)
	if err == nil && d.unsealLen != 0 {
		resized := make([]byte, d.unsealLen)
		copy(resized, plaintext)
		plaintext = resized
	}
	d.plaintexts = append(d.plaintexts, plaintext)
	if d.unsealErr != nil {
		return plaintext, d.unsealErr
	}
	return plaintext, err
}

func (d *sealerDouble) observe(attrs *types.KeyAttributes) {
	d.attrsSeen = append(d.attrsSeen, attrs)
	if d.mutate != nil {
		d.mutate(attrs)
	}
}

// requireWiped fails unless every plaintext the double handed out is zero.
func (d *sealerDouble) requireWiped(t *testing.T) {
	t.Helper()
	require.NotEmpty(t, d.plaintexts, "the test must reach Unseal")
	for _, p := range d.plaintexts {
		require.Equal(t, make([]byte, len(p)), p, "the provider must wipe the backend's plaintext")
	}
}

func newDouble(t *testing.T) (*sealerDouble, *types.KeyAttributes) {
	t.Helper()
	sb, attrs := newSoftwareSealer(t)
	return &sealerDouble{Sealer: sb}, attrs
}

func newProtector(t *testing.T, d *sealerDouble, attrs *types.KeyAttributes) *KeyProtector {
	t.Helper()
	p, err := NewKeyProtector(d, attrs)
	require.NoError(t, err)
	return p
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

var errBackend = errors.New("backend unreachable")

func TestNewKeyProtector_RefusesUnusableInputs(t *testing.T) {
	d, attrs := newDouble(t)

	_, err := NewKeyProtector(nil, attrs)
	require.ErrorIs(t, err, ErrNilSealer)

	_, err = NewKeyProtector(d, nil)
	require.ErrorIs(t, err, ErrNilKeyAttributes)

	d.cannotSeal = true
	_, err = NewKeyProtector(d, attrs)
	require.ErrorIs(t, err, ErrSealerUnavailable)
}

func TestKeyProtector_RoundTripWipesThePlaintext(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)

	blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)
	require.False(t, bytes.Contains(blob, testKey), "the blob must not carry the key")

	dst := make([]byte, enclave.RootKeyBytes)
	require.NoError(t, p.Unprotect(context.Background(), blob, dst))
	require.Equal(t, testKey, dst)
	d.requireWiped(t)
	require.NoError(t, p.Health())
}

func TestKeyProtector_Protect_RefusesWrongLengthKey(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)

	for _, n := range []int{0, enclave.RootKeyBytes - 1, enclave.RootKeyBytes + 1} {
		_, err := p.Protect(context.Background(), make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidKeyLength)
	}
	require.Empty(t, d.attrsSeen, "a wrong-length key never reaches the backend")
}

func TestKeyProtector_Protect_EndedContext(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)

	_, err := p.Protect(canceledContext(), bytes.Clone(testKey))
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrProtectFailed)
	require.NotErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.Empty(t, d.attrsSeen, "an ended context is refused before the backend")
}

func TestKeyProtector_Protect_BackendFailures(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)

	d.sealErr = errBackend
	_, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.ErrorIs(t, err, ErrProtectFailed)
	require.ErrorIs(t, err, errBackend)

	d.sealErr, d.sealNil = nil, true
	_, err = p.Protect(context.Background(), bytes.Clone(testKey))
	require.ErrorIs(t, err, ErrProtectFailed)
}

func TestKeyProtector_Unprotect_EndedContextTouchesNothing(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)
	blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)

	dst := make([]byte, enclave.RootKeyBytes)
	err = p.Unprotect(canceledContext(), blob, dst)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrUnprotectFailed)
	require.NotErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.Equal(t, make([]byte, enclave.RootKeyBytes), dst)
	require.Zero(t, d.unseals, "an ended context is refused before the backend")
}

func TestKeyProtector_Unprotect_WrongLengthDestination(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)
	blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)

	for _, n := range []int{0, enclave.RootKeyBytes - 1, enclave.RootKeyBytes + 1} {
		dst := make([]byte, n)
		err := p.Unprotect(context.Background(), blob, dst)
		require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
		require.ErrorIs(t, err, ErrKeyLengthMismatch)
		require.Equal(t, make([]byte, n), dst)
	}
}

func TestKeyProtector_Unprotect_SealedKeyOfAnotherLength(t *testing.T) {
	for _, n := range []int{enclave.RootKeyBytes - 1, enclave.RootKeyBytes + 1} {
		d, attrs := newDouble(t)
		p := newProtector(t, d, attrs)
		blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
		require.NoError(t, err)

		d.unsealLen = n
		dst := make([]byte, enclave.RootKeyBytes)
		err = p.Unprotect(context.Background(), blob, dst)
		require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
		require.ErrorIs(t, err, ErrKeyLengthMismatch)
		require.Equal(t, make([]byte, enclave.RootKeyBytes), dst)
		d.requireWiped(t)
	}
}

func TestKeyProtector_Unprotect_BackendVerdicts(t *testing.T) {
	authFailure := types.SealedDataAuthenticationError("tampered", errBackend)
	cases := []struct {
		name          string
		err           error
		authenticated bool
	}{
		{"authentication failure", authFailure, true},
		{"environment failure", errBackend, false},
		{"context ended mid-call", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, attrs := newDouble(t)
			p := newProtector(t, d, attrs)
			blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
			require.NoError(t, err)

			d.unsealErr = tc.err
			dst := make([]byte, enclave.RootKeyBytes)
			err = p.Unprotect(context.Background(), blob, dst)
			require.ErrorIs(t, err, tc.err, "the backend's error stays reachable")
			if tc.authenticated {
				require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
				require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
			} else {
				require.ErrorIs(t, err, ErrUnprotectFailed)
				require.NotErrorIs(t, err, enclave.ErrSealedAuthentication)
			}
			require.Equal(t, make([]byte, enclave.RootKeyBytes), dst)
			d.requireWiped(t)
		})
	}
}

func TestKeyProtector_Unprotect_TagCoversFieldsTheBackendIgnores(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)
	blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)
	env, err := decodeEnvelope(blob, purposeKey)
	require.NoError(t, err)

	// The software backend does not read KeyVersion or Metadata, so only the
	// tag can notice them change. Re-encoding under another key models an
	// attacker who can rewrite the envelope but not recover the key.
	env.sealed.KeyVersion = 9
	env.sealed.Metadata = map[string][]byte{"note": []byte("forged")}
	forged, err := encodeEnvelope(purposeKey, env.sealed, bytes.Repeat([]byte{1}, enclave.RootKeyBytes))
	require.NoError(t, err)

	dst := make([]byte, enclave.RootKeyBytes)
	err = p.Unprotect(context.Background(), forged, dst)
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.ErrorIs(t, err, ErrEnvelopeTag)
	require.Equal(t, make([]byte, enclave.RootKeyBytes), dst)
	d.requireWiped(t)
}

func TestKeyProtector_Unprotect_BackendBindsThePurpose(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)

	// A key sealed under the sealed-root AAD, framed and tagged as a protected
	// key: only the backend's AAD binding can refuse it.
	rootBlob, err := p.box.seal(context.Background(), purposeRoot, testKey, ErrProtectFailed)
	require.NoError(t, err)
	env, err := decodeEnvelope(rootBlob, purposeRoot)
	require.NoError(t, err)
	reframed, err := encodeEnvelope(purposeKey, env.sealed, testKey)
	require.NoError(t, err)

	err = p.Unprotect(context.Background(), reframed, make([]byte, enclave.RootKeyBytes))
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
}

func TestKeyProtector_EachCallGetsItsOwnAttributes(t *testing.T) {
	d, attrs := newDouble(t)
	attrs.TPMAttributes = &types.TPMAttributes{Handle: 0x81000002}
	p := newProtector(t, d, attrs)

	// The caller's later edits and a sealer writing into the attributes it is
	// handed (as the TPM 2.0 sealer does) must not reach the next call.
	attrs.CN = "edited-by-caller"
	attrs.TPMAttributes.Handle = 1
	d.mutate = func(a *types.KeyAttributes) {
		a.TPMAttributes.Handle = 2
		a.SealData = types.NewSealData([]byte("staged"))
	}
	blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)
	require.NoError(t, p.Unprotect(context.Background(), blob, make([]byte, enclave.RootKeyBytes)))

	require.Len(t, d.attrsSeen, 2)
	require.NotSame(t, d.attrsSeen[0], d.attrsSeen[1])
	require.NotSame(t, d.attrsSeen[0].TPMAttributes, d.attrsSeen[1].TPMAttributes)
	require.Equal(t, "enclave-provider-seal", p.box.attrs.CN)
	require.Equal(t, uint32(0x81000002), uint32(p.box.attrs.TPMAttributes.Handle))
	require.Nil(t, p.box.attrs.SealData)
}

func TestKeyProtector_ParentAttributesAreCopied(t *testing.T) {
	d, attrs := newDouble(t)
	attrs.Parent = &types.KeyAttributes{
		CN:            "srk",
		TPMAttributes: &types.TPMAttributes{Handle: 0x81000001},
		Parent:        &types.KeyAttributes{CN: "root", TPMAttributes: &types.TPMAttributes{Handle: 0x40000001}},
	}
	p := newProtector(t, d, attrs)

	// The parent's handle is the SRK a TPM sealer seals under: neither the
	// caller's later edits to its parent attributes nor a sealer writing
	// into the copy it is handed may move it.
	attrs.Parent.TPMAttributes.Handle = 1
	attrs.Parent.Parent.TPMAttributes.Handle = 1
	d.mutate = func(a *types.KeyAttributes) {
		a.Parent.TPMAttributes.Handle = 2
		a.Parent.Parent.TPMAttributes.Handle = 2
	}
	blob, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)
	require.NoError(t, p.Unprotect(context.Background(), blob, make([]byte, enclave.RootKeyBytes)))

	require.Len(t, d.attrsSeen, 2)
	require.NotSame(t, d.attrsSeen[0].Parent, d.attrsSeen[1].Parent)
	require.NotSame(t, d.attrsSeen[0].Parent.TPMAttributes, d.attrsSeen[1].Parent.TPMAttributes)
	require.Equal(t, uint32(0x81000001), uint32(p.box.attrs.Parent.TPMAttributes.Handle))
	require.Equal(t, uint32(0x40000001), uint32(p.box.attrs.Parent.Parent.TPMAttributes.Handle))
}

func TestNewRootUnsealer_RefusesUnusableInputs(t *testing.T) {
	d, attrs := newDouble(t)
	p := newProtector(t, d, attrs)
	protected, err := p.Protect(context.Background(), bytes.Clone(testKey))
	require.NoError(t, err)

	_, err = NewRootUnsealer(nil, attrs, nil)
	require.ErrorIs(t, err, ErrNilSealer)

	_, err = NewRootUnsealer(d, nil, nil)
	require.ErrorIs(t, err, ErrNilKeyAttributes)

	_, err = NewRootUnsealer(d, attrs, []byte("not an envelope"))
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.ErrorIs(t, err, ErrMalformedEnvelope)

	_, err = NewRootUnsealer(d, attrs, protected)
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.ErrorIs(t, err, ErrWrongPurpose)
}

func TestRootUnsealer_UnsealsTheProvisionedRoot(t *testing.T) {
	d, attrs := newDouble(t)
	sealedRoot, err := ProvisionRoot(context.Background(), d, attrs)
	require.NoError(t, err)

	u, err := NewRootUnsealer(d, attrs, sealedRoot)
	require.NoError(t, err)
	sealedRoot[len(sealedRoot)-1] ^= 0xff // the unsealer keeps its own copy

	first := make([]byte, enclave.RootKeyBytes)
	second := make([]byte, enclave.RootKeyBytes)
	require.NoError(t, u.UnsealRoot(context.Background(), first))
	require.NoError(t, u.UnsealRoot(context.Background(), second))
	require.Equal(t, first, second, "every call yields the same root")
	require.NotEqual(t, make([]byte, enclave.RootKeyBytes), first)
	d.requireWiped(t)
}

func TestRootUnsealer_UnsealRoot_Failures(t *testing.T) {
	d, attrs := newDouble(t)
	sealedRoot, err := ProvisionRoot(context.Background(), d, attrs)
	require.NoError(t, err)
	u, err := NewRootUnsealer(d, attrs, sealedRoot)
	require.NoError(t, err)

	dst := make([]byte, enclave.RootKeyBytes)
	err = u.UnsealRoot(canceledContext(), dst)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrUnsealRootFailed)

	err = u.UnsealRoot(context.Background(), make([]byte, enclave.RootKeyBytes-1))
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)

	d.unsealErr = errBackend
	err = u.UnsealRoot(context.Background(), dst)
	require.ErrorIs(t, err, ErrUnsealRootFailed)
	require.ErrorIs(t, err, errBackend)
	require.Equal(t, make([]byte, enclave.RootKeyBytes), dst)

	d.unsealErr = nil
	require.NoError(t, u.UnsealRoot(context.Background(), dst), "a refused call consumes nothing")
}

func TestProvisionRoot_Failures(t *testing.T) {
	d, attrs := newDouble(t)

	_, err := ProvisionRoot(context.Background(), nil, attrs)
	require.ErrorIs(t, err, ErrNilSealer)

	_, err = ProvisionRoot(context.Background(), d, nil)
	require.ErrorIs(t, err, ErrNilKeyAttributes)

	_, err = ProvisionRoot(canceledContext(), d, attrs)
	require.ErrorIs(t, err, ErrProvisionRootFailed)
	require.ErrorIs(t, err, context.Canceled)

	d.sealErr = errBackend
	_, err = ProvisionRoot(context.Background(), d, attrs)
	require.ErrorIs(t, err, ErrProvisionRootFailed)
	require.ErrorIs(t, err, errBackend)

	d.sealErr, d.cannotSeal = nil, true
	_, err = ProvisionRoot(context.Background(), d, attrs)
	require.ErrorIs(t, err, ErrSealerUnavailable)
}

func TestProvisionRoot_EachRootIsFresh(t *testing.T) {
	d, attrs := newDouble(t)
	roots := make([][]byte, 2)
	for i := range roots {
		sealedRoot, err := ProvisionRoot(context.Background(), d, attrs)
		require.NoError(t, err)
		u, err := NewRootUnsealer(d, attrs, sealedRoot)
		require.NoError(t, err)
		roots[i] = make([]byte, enclave.RootKeyBytes)
		require.NoError(t, u.UnsealRoot(context.Background(), roots[i]))
	}
	require.NotEqual(t, roots[0], roots[1])
}
