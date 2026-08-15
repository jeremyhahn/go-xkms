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
	"google.golang.org/grpc"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// registerQRDBControlPlane registers the embedded qrdb node's OWN control-plane
// services onto the given gRPC server, so xkmsd hosts qrdb's cluster admin
// (status/peers/membership), shard rebalance, and user-auth-factor surfaces with
// zero xkms-authored handlers. This is the sanctioned composition-root pattern
// (go-quicbaas registers the same surface onto its server the same way) and
// replaces the deleted xkms-authored cluster/auth-factor proxy planes.
//
// The KV servicer is deliberately nil: the data plane is NOT exposed through
// xkmsd (L5 — "go-xkms is not a database server product"). Every QRDBService RPC
// whose servicer is nil self-returns codes.Unimplemented, so only the
// control-plane subset below is functional:
//
//   - AdminServicer     — cluster status, peers, membership add/remove
//   - RebalanceServicer — shard stats, plan, execute, imbalance report
//   - UserServicer + UserAuthFactorServicer — the qrdb.v1.UserAuthFactorService
//     factor surface xkmsctl's factor verbs drive
//
// Authorization posture (transitional, recorded in
// plans/unified-api-server-2026-08-14.md): these RPCs sit behind xkmsd's
// transport authentication (TLS + adaptive auth; the unix socket adds
// filesystem-permission trust). Fine-grained authorization arrives with the
// stack-wide unified authz cutover (Phase 5); until then this matches the
// adaptive-auth posture of the rest of the xkmsd surface.
func (s *Server) registerQRDBControlPlane(gs *grpc.Server) {
	if s.qrdbNode == nil || gs == nil {
		return
	}

	opts := []qrdbsdk.GRPCRegisterOption{}
	if rebalance := s.qrdbNode.RebalanceService(); rebalance != nil {
		opts = append(opts, qrdbsdk.WithRegisterRebalanceService(rebalance))
	}
	if userSvc := s.qrdbNode.UserService(); userSvc != nil {
		opts = append(opts, qrdbsdk.WithRegisterUserService(userSvc))
	}
	if uaf := s.qrdbNode.UserAuthFactorService(); uaf != nil {
		opts = append(opts, qrdbsdk.WithRegisterUserAuthFactorService(uaf))
	}

	// kvSvc nil: data-plane RPCs answer Unimplemented (L5).
	qrdbsdk.RegisterGRPCService(gs, nil, s.qrdbNode.AdminService(), opts...)

	s.logger.Info("qrdb control plane registered on gRPC server " +
		"(cluster admin, rebalance, user auth factors; data plane unimplemented)")
}
