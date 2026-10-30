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

//go:build qrdb_vlog

package tlog

import (
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jeremyhahn/go-xkms/pkg/ca/checkpoint"
)

func testEntries() []Entry {
	return []Entry{
		CertIssued{CertSHA256: sha256.Sum256([]byte("leaf DER")), Serial: big.NewInt(4242), Profile: "tls-server", Tenant: "acme"},
		ImageSigned{ImageDigest: "sha256:aa11", EnvelopeDigest: "sha256:bb22", Signer: "spiffe://acme/release"},
		Revoked{Serial: big.NewInt(4242), Reason: 1},
	}
}

func appendEntry(ctx context.Context, l *Log, e Entry) (uint64, error) {
	switch e := e.(type) {
	case CertIssued:
		return l.AppendCertIssued(ctx, e)
	case ImageSigned:
		return l.AppendImageSigned(ctx, e)
	case Revoked:
		return l.AppendRevoked(ctx, e)
	}
	return 0, ErrUnknownKind
}

// TestLogAppendProveAndVerify appends each entry kind under each CA key
// type, reads it back, and verifies its inclusion against the CA-signed
// tree head and the consistency of every earlier head with the last.
func TestLogAppendProveAndVerify(t *testing.T) {
	for name, newKey := range caKeyTypes {
		t.Run(name, func(t *testing.T) {
			l, _, ctx := newLog(t, newKey(t))
			var heads []*TreeHead
			for i, want := range testEntries() {
				index, err := appendEntry(ctx, l, want)
				require.NoError(t, err)
				require.Equal(t, uint64(i), index)

				got, body, err := l.Entry(ctx, index)
				require.NoError(t, err)
				require.Equal(t, want, got)

				head, err := l.SignedTreeHead(ctx)
				require.NoError(t, err)
				require.Equal(t, testOrigin, head.Checkpoint.Origin)
				require.Equal(t, index+1, head.Checkpoint.Size)

				hashes, err := l.InclusionProof(ctx, index, head.Checkpoint.Size)
				require.NoError(t, err)
				leaf := rfc6962.DefaultHasher.HashLeaf(body)
				require.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher, index, head.Checkpoint.Size, leaf, hashes, head.Checkpoint.Hash))
				heads = append(heads, head)
			}

			last := heads[len(heads)-1].Checkpoint
			for _, h := range heads[:len(heads)-1] {
				hashes, err := l.ConsistencyProof(ctx, h.Checkpoint.Size, last.Size)
				require.NoError(t, err)
				require.NoError(t, proof.VerifyConsistency(rfc6962.DefaultHasher, h.Checkpoint.Size, last.Size, hashes, h.Checkpoint.Hash, last.Hash))
			}
		})
	}
}

// TestSignedTreeHeadVerifiesUnderCAKey checks the published note verifies
// under the CA key alone, through pkg/ca/checkpoint.
func TestSignedTreeHeadVerifiesUnderCAKey(t *testing.T) {
	signer := newEd25519(t)
	l, _, ctx := newLog(t, signer)
	_, err := l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(7), Reason: 4})
	require.NoError(t, err)
	head, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)

	caVerifier, err := checkpoint.NewSigner(testKeyName, signer)
	require.NoError(t, err)
	c, _, err := checkpoint.OpenCheckpoint(head.Note, caVerifier.Verifier())
	require.NoError(t, err)
	require.Equal(t, head.Checkpoint, c)

	otherVerifier, err := checkpoint.NewSigner(testKeyName, newEd25519(t))
	require.NoError(t, err)
	_, _, err = checkpoint.OpenCheckpoint(head.Note, otherVerifier.Verifier())
	require.Error(t, err)
}
