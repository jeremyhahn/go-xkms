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

package tlog

import (
	"bytes"
	"context"
	"strconv"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/vlogwire"

	"github.com/jeremyhahn/go-xkms/pkg/ca/checkpoint"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Log is the CA's transparency log: one go-qrdb verifiable log, in the
// client's tenant and database, whose heads the CA key signs. The log, its
// Merkle tree and its proofs are go-qrdb's; Log encodes the entries, and
// checks every signed tree head under the CA key before answering it.
type Log struct {
	client   transport.VlogClient
	name     string
	origin   string
	verifier *checkpoint.Verifier
}

// Config names a log.
type Config struct {
	// Name is the log's name within its database.
	Name string

	// Origin is the log's identity, the first line of every checkpoint
	// (tlog-checkpoint §Note text), e.g. "ca.example.com/tlog".
	Origin string
}

// TreeHead is a signed tree head: the checkpoint the CA key signed, and the
// signed note that carries it.
type TreeHead struct {
	// Checkpoint is the verified checkpoint body.
	Checkpoint *checkpoint.Checkpoint

	// Note is the checkpoint as a C2SP signed note.
	Note []byte
}

// Create creates the log, its heads signed by the node's HeadSignerProvider
// over the CA key, and returns it. signers is that provider: the log's key
// type is the CA key's, and its checkpoints verify under the CA key.
func Create(ctx context.Context, client transport.VlogClient, cfg Config, signers *HeadSignerProvider) (*Log, error) {
	if signers == nil {
		return nil, ErrNoKeyProvider
	}
	cp, sigType, err := signers.checkpointSigner(ctx)
	if err != nil {
		return nil, err
	}
	l, err := Open(client, cfg, cp.Verifier())
	if err != nil {
		return nil, err
	}
	req := &vlogwire.CreateRequest{Log: cfg.Name, Origin: cfg.Origin, SigningKeyType: sigType}
	if _, err := client.VlogCreate(ctx, req); err != nil {
		return nil, &errs.Joined{Lead: ErrLogRequest, Detail: "create " + cfg.Name, Cause: err}
	}
	return l, nil
}

// Open returns the log cfg names, created earlier with Create.
func Open(client transport.VlogClient, cfg Config, verifier *checkpoint.Verifier) (*Log, error) {
	if client == nil {
		return nil, ErrNoClient
	}
	if verifier == nil {
		return nil, ErrNoVerifier
	}
	if cfg.Name == "" || cfg.Origin == "" {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "name and origin are required"}
	}
	return &Log{client: client, name: cfg.Name, origin: cfg.Origin, verifier: verifier}, nil
}

// AppendCertIssued appends a cert-issued entry and returns its index.
func (l *Log) AppendCertIssued(ctx context.Context, e CertIssued) (uint64, error) {
	return l.append(ctx, e)
}

// AppendImageSigned appends an image-signed entry and returns its index.
func (l *Log) AppendImageSigned(ctx context.Context, e ImageSigned) (uint64, error) {
	return l.append(ctx, e)
}

// AppendRevoked appends a revoked entry and returns its index.
func (l *Log) AppendRevoked(ctx context.Context, e Revoked) (uint64, error) {
	return l.append(ctx, e)
}

func (l *Log) append(ctx context.Context, e Entry) (uint64, error) {
	body, err := Marshal(e)
	if err != nil {
		return 0, err
	}
	res, err := l.client.VlogAppend(ctx, &vlogwire.AppendRequest{Log: l.name, Entries: [][]byte{body}})
	if err != nil {
		return 0, &errs.Joined{Lead: ErrLogRequest, Detail: "append " + e.Kind().String(), Cause: err}
	}
	return res.FirstIndex, nil
}

// Entry reads back the entry at index, its encoded bytes beside it: the
// bytes the entry's leaf hash covers.
func (l *Log) Entry(ctx context.Context, index uint64) (Entry, []byte, error) {
	res, err := l.client.VlogGet(ctx, &vlogwire.GetRequest{Log: l.name, From: index, Limit: 1})
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrLogRequest, Detail: "get " + strconv.FormatUint(index, 10), Cause: err}
	}
	if len(res.Entries) != 1 || res.Entries[0].Index != index {
		return nil, nil, &errs.Detail{Err: ErrLogRequest, Detail: "get " + strconv.FormatUint(index, 10) + ": no such entry"}
	}
	if res.Entries[0].Expired {
		return nil, nil, &errs.Detail{Err: ErrEntryExpired, Detail: strconv.FormatUint(index, 10)}
	}
	body := res.Entries[0].Body
	e, err := Unmarshal(body)
	if err != nil {
		return nil, nil, err
	}
	return e, body, nil
}

// SignedTreeHead signs the log's current head with the CA key and returns
// it, after verifying the checkpoint go-qrdb rendered under the CA key, its
// origin, and that it describes the head go-qrdb signed.
func (l *Log) SignedTreeHead(ctx context.Context) (*TreeHead, error) {
	res, err := l.client.VlogSignHead(ctx, &vlogwire.LogRequest{Log: l.name})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrLogRequest, Detail: "sign head", Cause: err}
	}
	c, err := l.VerifyCheckpoint(res.Checkpoint)
	if err != nil {
		return nil, err
	}
	if c.Size != res.Head.Size || !bytes.Equal(c.Hash, res.Head.Root) {
		return nil, &errs.Detail{Err: ErrCheckpointMismatch, Detail: "checkpoint describes another tree"}
	}
	return &TreeHead{Checkpoint: c, Note: res.Checkpoint}, nil
}

// VerifyCheckpoint verifies note, a checkpoint of this log, under the CA key
// and returns its body.
func (l *Log) VerifyCheckpoint(note []byte) (*checkpoint.Checkpoint, error) {
	c, _, err := checkpoint.OpenCheckpoint(note, l.verifier)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrCheckpointMismatch, Detail: "signature", Cause: err}
	}
	if c.Origin != l.origin {
		return nil, &errs.Detail{Err: ErrCheckpointMismatch, Detail: "origin " + strconv.Quote(c.Origin)}
	}
	return c, nil
}

// InclusionProof returns the RFC 9162 §2.1.3 inclusion proof of the entry
// at index in the tree of size entries.
func (l *Log) InclusionProof(ctx context.Context, index, size uint64) ([][]byte, error) {
	res, err := l.client.VlogProveInclusion(ctx, &vlogwire.InclusionRequest{Log: l.name, Index: index, Size: size})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrLogRequest, Detail: "inclusion proof", Cause: err}
	}
	return res.Hashes, nil
}

// ConsistencyProof returns the RFC 9162 §2.1.4 consistency proof that the
// tree of size1 entries is a prefix of the tree of size2.
func (l *Log) ConsistencyProof(ctx context.Context, size1, size2 uint64) ([][]byte, error) {
	res, err := l.client.VlogProveConsistency(ctx, &vlogwire.ConsistencyRequest{Log: l.name, Size1: size1, Size2: size2})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrLogRequest, Detail: "consistency proof", Cause: err}
	}
	return res.Hashes, nil
}
