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

package xkms

import (
	"context"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// TransparencyLogReader is the read side of the CA's transparency log: its
// signed tree head, its entries and its RFC 9162 proofs. *tlog.Log
// satisfies it.
type TransparencyLogReader interface {
	// SignedTreeHead returns the log's current signed tree head.
	SignedTreeHead(ctx context.Context) (*tlog.TreeHead, error)

	// Entry returns the entry at index and its encoded bytes.
	Entry(ctx context.Context, index uint64) (tlog.Entry, []byte, error)

	// InclusionProof returns the inclusion proof of index in the tree of size.
	InclusionProof(ctx context.Context, index, size uint64) ([][]byte, error)

	// ConsistencyProof returns the consistency proof between the trees of
	// size1 and size2.
	ConsistencyProof(ctx context.Context, size1, size2 uint64) ([][]byte, error)
}

// TransparencyLogExternalAppender is the one write the layers above make to
// the CA's transparency log: an external entry. *tlog.Log satisfies it.
type TransparencyLogExternalAppender interface {
	// AppendExternal appends an external entry and returns its index.
	AppendExternal(ctx context.Context, e tlog.External) (uint64, error)
}

// TransparencyLog is the CA's transparency log as the XKMSService serves it:
// its reads and the external append.
type TransparencyLog interface {
	TransparencyLogReader
	TransparencyLogExternalAppender
}

var _ TransparencyLog = (*tlog.Log)(nil)

// SetTransparencyLog sets the log the transparency-log verbs serve; nil
// removes it, and the verbs then return ErrTransparencyLogNotConfigured.
//
// Thread-safe: Yes (atomic store)
func (s *XKMSService) SetTransparencyLog(l TransparencyLog) {
	s.transparencyLog.store(l)
}

// getTransparencyLog returns the configured log, or
// ErrTransparencyLogNotConfigured when none is.
func (s *XKMSService) getTransparencyLog() (TransparencyLog, error) {
	l := s.transparencyLog.load()
	if l == nil {
		return nil, ErrTransparencyLogNotConfigured
	}
	return l, nil
}

// transparencyLogHeadSize returns the size of the log's current signed tree
// head, the bound every index and size a read names is checked against.
func transparencyLogHeadSize(ctx context.Context, l TransparencyLogReader) (uint64, error) {
	head, err := l.SignedTreeHead(ctx)
	if err != nil {
		return 0, err
	}
	return head.Checkpoint.Size, nil
}

// rangeError reports an index or size outside the log's signed tree head.
func rangeError(detail string) error {
	return &errs.Detail{Err: ErrTransparencyLogRange, Detail: detail}
}

// GetTransparencyLogHead returns the log's current signed tree head: the
// C2SP checkpoint note and the size and root hash it signs.
func (s *XKMSService) GetTransparencyLogHead(ctx context.Context, _ *transport.GetTransparencyLogHeadRequest) (resp *transport.GetTransparencyLogHeadResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpGet, caMetricsBackend, start, err) }()

	l, err := s.getTransparencyLog()
	if err != nil {
		return nil, err
	}
	head, err := l.SignedTreeHead(ctx)
	if err != nil {
		return nil, err
	}
	return &transport.GetTransparencyLogHeadResponse{
		Checkpoint: head.Note,
		Origin:     head.Checkpoint.Origin,
		Size:       head.Checkpoint.Size,
		RootHash:   head.Checkpoint.Hash,
	}, nil
}

// GetTransparencyLogEntry returns the encoded entry at req.Index, which must
// be below the current signed tree head's size.
func (s *XKMSService) GetTransparencyLogEntry(ctx context.Context, req *transport.GetTransparencyLogEntryRequest) (resp *transport.GetTransparencyLogEntryResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpGet, caMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilRequest
	}
	l, err := s.getTransparencyLog()
	if err != nil {
		return nil, err
	}
	size, err := transparencyLogHeadSize(ctx, l)
	if err != nil {
		return nil, err
	}
	if req.Index >= size {
		return nil, rangeError("index " + strconv.FormatUint(req.Index, 10) + " is not below tree size " + strconv.FormatUint(size, 10))
	}
	_, body, err := l.Entry(ctx, req.Index)
	if err != nil {
		return nil, err
	}
	return &transport.GetTransparencyLogEntryResponse{Index: req.Index, Entry: body}, nil
}

// GetTransparencyLogInclusionProof returns the RFC 9162 §2.1.3 inclusion
// proof of req.Index in the tree of req.TreeSize. The index must be below
// the tree size, and the tree size at least one and at most the current
// signed tree head's size.
func (s *XKMSService) GetTransparencyLogInclusionProof(ctx context.Context, req *transport.GetTransparencyLogInclusionProofRequest) (resp *transport.GetTransparencyLogInclusionProofResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpGet, caMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilRequest
	}
	l, err := s.getTransparencyLog()
	if err != nil {
		return nil, err
	}
	size, err := transparencyLogHeadSize(ctx, l)
	if err != nil {
		return nil, err
	}
	if req.TreeSize == 0 || req.TreeSize > size {
		return nil, rangeError("tree size " + strconv.FormatUint(req.TreeSize, 10) + " is not in 1.." + strconv.FormatUint(size, 10))
	}
	if req.Index >= req.TreeSize {
		return nil, rangeError("index " + strconv.FormatUint(req.Index, 10) + " is not below tree size " + strconv.FormatUint(req.TreeSize, 10))
	}
	hashes, err := l.InclusionProof(ctx, req.Index, req.TreeSize)
	if err != nil {
		return nil, err
	}
	return &transport.GetTransparencyLogInclusionProofResponse{Index: req.Index, TreeSize: req.TreeSize, Hashes: hashes}, nil
}

// GetTransparencyLogConsistencyProof returns the RFC 9162 §2.1.4 consistency
// proof between the trees of req.FirstSize and req.SecondSize, where
// 1 <= FirstSize <= SecondSize <= the current signed tree head's size.
func (s *XKMSService) GetTransparencyLogConsistencyProof(ctx context.Context, req *transport.GetTransparencyLogConsistencyProofRequest) (resp *transport.GetTransparencyLogConsistencyProofResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpGet, caMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilRequest
	}
	l, err := s.getTransparencyLog()
	if err != nil {
		return nil, err
	}
	size, err := transparencyLogHeadSize(ctx, l)
	if err != nil {
		return nil, err
	}
	if req.FirstSize == 0 || req.FirstSize > req.SecondSize || req.SecondSize > size {
		return nil, rangeError("sizes " + strconv.FormatUint(req.FirstSize, 10) + " and " + strconv.FormatUint(req.SecondSize, 10) +
			" are not 1 <= first <= second <= " + strconv.FormatUint(size, 10))
	}
	hashes, err := l.ConsistencyProof(ctx, req.FirstSize, req.SecondSize)
	if err != nil {
		return nil, err
	}
	return &transport.GetTransparencyLogConsistencyProofResponse{FirstSize: req.FirstSize, SecondSize: req.SecondSize, Hashes: hashes}, nil
}

// AppendTransparencyLogExternal appends an external entry holding
// req.Payload under the caller's SPIFFE ID and returns its leaf index. The
// SPIFFE ID is never a request field: it is the one the caller's verified
// mTLS client certificate names (callerSPIFFEID), so an entry always names
// the caller that appended it.
func (s *XKMSService) AppendTransparencyLogExternal(ctx context.Context, req *transport.AppendTransparencyLogExternalRequest) (resp *transport.AppendTransparencyLogExternalResponse, err error) {
	start := time.Now()
	defer func() { recordServiceOp(metrics.OpStore, caMetricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilRequest
	}
	l, err := s.getTransparencyLog()
	if err != nil {
		return nil, err
	}
	id, err := callerSPIFFEID(ctx)
	if err != nil {
		return nil, err
	}
	index, err := l.AppendExternal(ctx, tlog.External{SPIFFEID: id, Payload: req.Payload})
	if err != nil {
		return nil, err
	}
	return &transport.AppendTransparencyLogExternalResponse{Index: index}, nil
}

// callerSPIFFEID returns the SPIFFE ID of the request's caller: the one URI
// SAN pkg/spiffe accepts on the leaf of the connection's verified client
// certificate chain. Only a certificate the handshake verified counts, the
// rule peergate applies; a certificate naming no SPIFFE ID, or two, names no
// caller.
func callerSPIFFEID(ctx context.Context) (string, error) {
	state := auth.TLSStateFromContext(ctx)
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", &errs.Detail{Err: ErrTransparencyLogNoCallerSPIFFEID, Detail: "no verified client certificate"}
	}
	var found []spiffe.ID
	for _, u := range state.VerifiedChains[0][0].URIs {
		id, ok, err := spiffe.ParseID(u)
		if err != nil {
			return "", &errs.Joined{Lead: ErrTransparencyLogNoCallerSPIFFEID, Detail: "client certificate URI SAN", Cause: err}
		}
		if ok {
			found = append(found, id)
		}
	}
	if len(found) != 1 {
		return "", &errs.Detail{Err: ErrTransparencyLogNoCallerSPIFFEID, Detail: strconv.Itoa(len(found)) + " SPIFFE IDs in the client certificate"}
	}
	return found[0].String(), nil
}
