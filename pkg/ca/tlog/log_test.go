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
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/vlogwire"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jeremyhahn/go-xkms/pkg/ca/checkpoint"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

func testEntries() []Entry {
	return []Entry{
		CertIssued{CertSHA256: sha256.Sum256([]byte("leaf DER")), Serial: big.NewInt(4242), Profile: "tls-server", Tenant: "acme"},
		ImageSigned{ImageDigest: "sha256:aa11", EnvelopeDigest: "sha256:bb22", Signer: "spiffe://acme/release"},
		Revoked{Serial: big.NewInt(4242), Reason: 1},
		External{SPIFFEID: "spiffe://acme/svc/billing", Payload: []byte("invoice 7")},
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
	case External:
		return l.AppendExternal(ctx, e)
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

// TestOpen_ReadsTheCreatedLog opens a second handle on a created log and
// reads and verifies through it, and refuses a handle without a verifier or
// with an incomplete configuration.
func TestOpen_ReadsTheCreatedLog(t *testing.T) {
	signer := newEd25519(t)
	l, client, ctx := newLog(t, signer)
	_, err := l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(9), Reason: 0})
	require.NoError(t, err)

	v, err := newProvider(t, signer).Verifier(ctx)
	require.NoError(t, err)
	opened, err := Open(client, Config{Name: "certs", Origin: testOrigin}, v)
	require.NoError(t, err)
	got, _, err := opened.Entry(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, Revoked{Serial: big.NewInt(9), Reason: 0}, got)
	head, err := opened.SignedTreeHead(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), head.Checkpoint.Size)

	_, err = Open(client, Config{Name: "certs", Origin: testOrigin}, nil)
	require.ErrorIs(t, err, ErrNoVerifier)
	for _, cfg := range []Config{{Origin: testOrigin}, {Name: "certs"}} {
		_, err = Open(client, cfg, v)
		require.ErrorIs(t, err, ErrInvalidConfig)
	}
}

func TestOpenOrCreate_CreatesThenOpens(t *testing.T) {
	signer := newEd25519(t)
	p := newProvider(t, signer)
	client, ctx := newVlogClient(t, p)
	cfg := Config{Name: "certs", Origin: testOrigin}

	created, err := OpenOrCreate(ctx, client, cfg, p)
	require.NoError(t, err)
	_, err = created.AppendRevoked(ctx, Revoked{Serial: big.NewInt(3), Reason: 1})
	require.NoError(t, err)

	opened, err := OpenOrCreate(ctx, client, cfg, p)
	require.NoError(t, err, "a log that exists is opened, not created again")
	got, _, err := opened.Entry(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, Revoked{Serial: big.NewInt(3), Reason: 1}, got)
}

func TestOpenOrCreate_Errors(t *testing.T) {
	signer := newEd25519(t)
	p := newProvider(t, signer)
	client, ctx := newVlogClient(t, p)

	_, err := OpenOrCreate(ctx, client, Config{Name: "certs", Origin: testOrigin}, nil)
	require.ErrorIs(t, err, ErrNoKeyProvider)

	_, err = OpenOrCreate(ctx, nil, Config{Name: "certs", Origin: testOrigin}, p)
	require.ErrorIs(t, err, ErrNoClient)

	_, err = OpenOrCreate(ctx, client, Config{Name: "certs"}, p)
	require.ErrorIs(t, err, ErrInvalidConfig)

	unavailable, err := NewHeadSignerProvider(failingCAKeys(nil, &qrdbsdk.CAKeyNotInitializedError{}), testKeyName)
	require.NoError(t, err)
	_, err = OpenOrCreate(ctx, client, Config{Name: "certs", Origin: testOrigin}, unavailable)
	require.ErrorIs(t, err, ErrCAKeyUnavailable)

	// A context without the service principal cannot read the head, and
	// cannot create the log either: the caller learns at once.
	_, err = OpenOrCreate(t.Context(), client, Config{Name: "certs", Origin: testOrigin}, p)
	require.ErrorIs(t, err, ErrLogRequest)
}

// TestSignedTreeHead_CheckpointMismatch refuses a head that does not verify
// under the handle's CA key, or that names another origin.
func TestSignedTreeHead_CheckpointMismatch(t *testing.T) {
	l, client, ctx := newLog(t, newEd25519(t))
	_, err := l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(9), Reason: 0})
	require.NoError(t, err)

	other, err := newProvider(t, newEd25519(t)).Verifier(ctx)
	require.NoError(t, err)
	wrongKey, err := Open(client, Config{Name: "certs", Origin: testOrigin}, other)
	require.NoError(t, err)
	_, err = wrongKey.SignedTreeHead(ctx)
	require.ErrorIs(t, err, ErrCheckpointMismatch)

	head, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)
	wrongOrigin, err := Open(client, Config{Name: "certs", Origin: "other.example.com/tlog"}, l.verifier)
	require.NoError(t, err)
	_, err = wrongOrigin.VerifyCheckpoint(head.Note)
	require.ErrorIs(t, err, ErrCheckpointMismatch)
	_, err = wrongOrigin.SignedTreeHead(ctx)
	require.ErrorIs(t, err, ErrCheckpointMismatch)
}

// TestSignedTreeHead_RepeatedAndConcurrent asks for the head many times at
// one tree size, in turn and at once: go-qrdb keeps one checkpoint per
// size, and every caller gets that checkpoint.
func TestSignedTreeHead_RepeatedAndConcurrent(t *testing.T) {
	l, _, ctx := newLog(t, newP256(t))
	_, err := l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(9), Reason: 0})
	require.NoError(t, err)

	first, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)
	again, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)
	require.Equal(t, first.Note, again.Note)

	_, err = l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(10), Reason: 0})
	require.NoError(t, err)
	const callers = 8
	notes := make([][]byte, callers)
	failures := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			head, err := l.SignedTreeHead(ctx)
			failures[i] = err
			if err == nil {
				notes[i] = head.Note
			}
		}()
	}
	wg.Wait()
	for i := range callers {
		require.NoError(t, failures[i])
		require.Equal(t, notes[0], notes[i])
	}
	c, err := l.VerifyCheckpoint(notes[0])
	require.NoError(t, err)
	require.Equal(t, uint64(2), c.Size)
}

// TestLog_RequestFailures maps every go-qrdb refusal to ErrLogRequest, and
// an invalid entry to ErrInvalidEntry before any request.
func TestLog_RequestFailures(t *testing.T) {
	signer := newEd25519(t)
	p := newProvider(t, signer)
	client, ctx := newVlogClient(t, p)
	l, err := Create(ctx, client, Config{Name: "certs", Origin: testOrigin}, p)
	require.NoError(t, err)
	_, err = l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(9), Reason: 0})
	require.NoError(t, err)

	_, err = Create(ctx, client, Config{Name: "certs", Origin: testOrigin}, p)
	require.ErrorIs(t, err, ErrLogRequest, "the log already exists")

	_, err = l.AppendRevoked(ctx, Revoked{Serial: big.NewInt(9), Reason: 7})
	require.ErrorIs(t, err, ErrInvalidEntry)
	_, err = l.AppendCertIssued(ctx, CertIssued{})
	require.ErrorIs(t, err, ErrInvalidEntry)
	_, err = l.AppendImageSigned(ctx, ImageSigned{})
	require.ErrorIs(t, err, ErrInvalidEntry)
	_, err = l.AppendExternal(ctx, External{Payload: []byte{1}})
	require.ErrorIs(t, err, ErrInvalidEntry)

	_, _, err = l.Entry(ctx, 5)
	require.ErrorIs(t, err, ErrLogRequest)
	_, err = l.InclusionProof(ctx, 5, 1)
	require.ErrorIs(t, err, ErrLogRequest)
	_, err = l.ConsistencyProof(ctx, 2, 1)
	require.ErrorIs(t, err, ErrLogRequest)

	missing, err := Open(client, Config{Name: "missing", Origin: testOrigin}, l.verifier)
	require.NoError(t, err)
	_, err = missing.AppendImageSigned(ctx, ImageSigned{ImageDigest: "i", EnvelopeDigest: "e", Signer: "s"})
	require.ErrorIs(t, err, ErrLogRequest)
	_, _, err = missing.Entry(ctx, 0)
	require.ErrorIs(t, err, ErrLogRequest)
	_, err = missing.SignedTreeHead(ctx)
	require.ErrorIs(t, err, ErrLogRequest)
}

// TestEntry_Expired reads back an entry whose body an operator expired on a
// log created with AllowExpireBodies: Entry answers ErrEntryExpired, and
// the entry's inclusion in a later CA-signed head still verifies.
func TestEntry_Expired(t *testing.T) {
	// The xkms service principal never expires bodies, so production does
	// not grant it vlog:expire (serviceprincipal.Grant). Here the same role
	// also stands in for the operator who does; the grant exists only in
	// this test binary.
	qrdbsdk.RegisterPermissionRoleGrant(serviceprincipal.Name, "vlog:expire")

	l, client, ctx := newLogWith(t, newP256(t), Config{Name: "certs", Origin: testOrigin, AllowExpireBodies: true})
	want := testEntries()
	for _, e := range want {
		_, err := appendEntry(ctx, l, e)
		require.NoError(t, err)
	}
	_, body, err := l.Entry(ctx, 0)
	require.NoError(t, err)

	_, err = client.VlogExpireBodies(ctx, &vlogwire.ExpireRequest{Log: "certs", Cutoff: 1})
	require.NoError(t, err)

	_, _, err = l.Entry(ctx, 0)
	require.ErrorIs(t, err, ErrEntryExpired)
	got, _, err := l.Entry(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, want[1], got)

	head, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)
	hashes, err := l.InclusionProof(ctx, 0, head.Checkpoint.Size)
	require.NoError(t, err)
	leaf := rfc6962.DefaultHasher.HashLeaf(body)
	require.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher, 0, head.Checkpoint.Size, leaf, hashes, head.Checkpoint.Hash))
}
