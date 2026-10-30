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

package server

import (
	"context"
	"strings"

	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// caTransparencyLogName is the CA's transparency log within the embedded
// node's verifiable logs.
const caTransparencyLogName = "ca"

// transparencyLogOrigin returns the CA log's origin: transparency_log.origin,
// or else the CA's first identity common name with its whitespace runs joined
// by "-", followed by "/tlog". tlog-checkpoint §Note text: the origin SHOULD
// be a schema-less URL without spaces.
func (s *Server) transparencyLogOrigin() string {
	if s.config.TransparencyLog.Origin != "" {
		return s.config.TransparencyLog.Origin
	}
	cn := s.config.CA.Identity[0].Subject.CommonName
	return strings.Join(strings.Fields(cn), "-") + "/tlog"
}

// transparencyLogNodeOptions returns the node option that gives the embedded
// node the CA log's head signer: the TrustedCA's issuing key, through a
// KeyProvider initializeCA binds once the CA exists. It returns no option
// when the server has no CA, no CA identity, or the log is switched off.
func (s *Server) transparencyLogNodeOptions() ([]qrdbnode.NodeOption, error) {
	if s.config.CA == nil || len(s.config.CA.Identity) == 0 || !s.config.TransparencyLogEnabled() {
		return nil, nil
	}
	keys := clustercapkg.NewKeyProvider("")
	signers, err := tlog.NewHeadSignerProvider(keys, s.transparencyLogOrigin())
	if err != nil {
		return nil, err
	}
	s.tlogKeys = keys
	s.tlogSigners = signers
	return []qrdbnode.NodeOption{qrdbnode.WithHeadSignerProvider(signers)}, nil
}

// openTransparencyLog opens the CA's transparency log on the embedded node,
// creating it on first start, and sets it on trustedCA, so every issuance
// after it appends a cert-issued entry and fails closed when it cannot. With
// the log switched off it does nothing. With it on, any failure is an
// *ErrTransparencyLog here, at start-up, never at the first issuance.
func (s *Server) openTransparencyLog(trustedCA ca.TrustedCA) error {
	if !s.config.TransparencyLogEnabled() {
		return nil
	}
	if s.qrdbNode == nil || s.tlogSigners == nil {
		return &ErrTransparencyLog{Operation: "open the CA log", Err: ErrTransparencyLogUnavailable}
	}
	target, ok := trustedCA.(*ca.CA)
	if !ok {
		return &ErrTransparencyLog{Operation: "attach the CA log", Err: ErrTransparencyLogCAUnsupported}
	}
	if err := s.tlogKeys.Bind(trustedCA); err != nil {
		return &ErrTransparencyLog{Operation: "bind the head-signing key", Err: err}
	}
	ctx, err := s.qrdbNode.ServiceContext(s.ctx)
	if err != nil {
		return &ErrTransparencyLog{Operation: "open the CA log", Err: err}
	}
	cfg := tlog.Config{Name: caTransparencyLogName, Origin: s.transparencyLogOrigin()}
	var opened *tlog.Log
	// Creating the log writes to the replicated store; on a cluster this
	// races the initial leader election (leader_retry.go).
	if err := retryNotLeader(s.ctx, s.logger, "ca transparency log", func() error {
		l, err := tlog.OpenOrCreate(ctx, s.qrdbNode.Client().Vlog(), cfg, s.tlogSigners)
		opened = l
		return err
	}); err != nil {
		return &ErrTransparencyLog{Operation: "open the CA log", Err: err}
	}
	s.tlogService = &serviceTransparencyLog{log: opened, callContext: s.qrdbNode.ServiceContext}
	target.SetTransparencyLog(s.tlogService)
	s.logger.Info("CA transparency log attached", "log", cfg.Name, "origin", cfg.Origin)
	return nil
}

// serviceTransparencyLog runs every append the CA makes, and every read the
// XKMSService serves, as the embedded node's service principal. Both run on
// the context of the request they serve, which carries the caller's identity
// or none; the log is xkms's own record, the transport already authorized the
// read against the vlog resource, and the node's authentication chain refuses
// a bare context.
type serviceTransparencyLog struct {
	log         *tlog.Log
	callContext func(context.Context) (context.Context, error)
}

var (
	_ ca.TransparencyLog         = (*serviceTransparencyLog)(nil)
	_ xkms.TransparencyLogReader = (*serviceTransparencyLog)(nil)
)

// wireTransparencyLog gives svc the CA log to serve the transparency-log read
// verbs from. With the log off or not opened, svc keeps answering
// ErrTransparencyLogNotConfigured.
func (s *Server) wireTransparencyLog(svc *xkms.XKMSService) {
	if s.tlogService != nil {
		svc.SetTransparencyLog(s.tlogService)
	}
}

// SignedTreeHead returns the log's signed tree head as the service principal.
func (l *serviceTransparencyLog) SignedTreeHead(ctx context.Context) (*tlog.TreeHead, error) {
	ctx, err := l.callContext(ctx)
	if err != nil {
		return nil, err
	}
	return l.log.SignedTreeHead(ctx)
}

// Entry returns the entry at index as the service principal.
func (l *serviceTransparencyLog) Entry(ctx context.Context, index uint64) (tlog.Entry, []byte, error) {
	ctx, err := l.callContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return l.log.Entry(ctx, index)
}

// InclusionProof returns the inclusion proof of index as the service
// principal.
func (l *serviceTransparencyLog) InclusionProof(ctx context.Context, index, size uint64) ([][]byte, error) {
	ctx, err := l.callContext(ctx)
	if err != nil {
		return nil, err
	}
	return l.log.InclusionProof(ctx, index, size)
}

// ConsistencyProof returns the consistency proof between two tree sizes as the
// service principal.
func (l *serviceTransparencyLog) ConsistencyProof(ctx context.Context, size1, size2 uint64) ([][]byte, error) {
	ctx, err := l.callContext(ctx)
	if err != nil {
		return nil, err
	}
	return l.log.ConsistencyProof(ctx, size1, size2)
}

// AppendCertIssued appends a cert-issued entry as the service principal.
func (l *serviceTransparencyLog) AppendCertIssued(ctx context.Context, e tlog.CertIssued) (uint64, error) {
	ctx, err := l.callContext(ctx)
	if err != nil {
		return 0, err
	}
	return l.log.AppendCertIssued(ctx, e)
}

// AppendRevoked appends a revoked entry as the service principal.
func (l *serviceTransparencyLog) AppendRevoked(ctx context.Context, e tlog.Revoked) (uint64, error) {
	ctx, err := l.callContext(ctx)
	if err != nil {
		return 0, err
	}
	return l.log.AppendRevoked(ctx, e)
}
