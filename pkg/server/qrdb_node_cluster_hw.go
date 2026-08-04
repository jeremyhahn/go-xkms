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

//go:build raft

package server

import (
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	clustertls "github.com/jeremyhahn/go-qrdb/sdk/go/clustertls"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrRaftLeafDecode is returned when the issued Raft node leaf PEM cannot be
// decoded — an internal error that must fail node startup rather than serve a
// malformed certificate.
type ErrRaftLeafDecode struct{}

// Error returns the error message.
func (e *ErrRaftLeafDecode) Error() string {
	return "server: cluster raft enrollment: issued node leaf PEM did not decode"
}

// provisionRaftClusterTLSHardware provisions the Raft node mTLS material with a
// hardware-resident node key. It generates (or, across restarts, loads) an ECDSA
// P-256 signing key on the configured backend (tpm2/pkcs11 — the private key
// never leaves the device), resolves the cluster CA via clusterenroll.ResolveCA,
// issues a node leaf for the hardware key's public part, and returns an
// RaftMTLSConfig that carries the signer-backed certificate through the quicraft
// Certificate seam. The returned Advertiser is non-nil only on the first node.
func (s *Server) provisionRaftClusterTLSHardware(members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
	enr := s.config.Cluster.RaftEnrollment

	b, err := s.xkmsService.LookupBackend(enr.KeyBackend)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: fmt.Sprintf("cluster raft enrollment: key backend %q", enr.KeyBackend), Err: err}
	}
	kp := b.KeyProvider()

	signer, err := s.raftNodeSigner(kp)
	if err != nil {
		return nil, nil, err
	}

	// Resolve ONLY the cluster CA (no software node leaf) — the node leaf is
	// issued below for the hardware key's public part.
	caCertPEM, caKeyPEM, adv, err := clusterenroll.ResolveCA(s.ctx, s.buildClusterEnrollOptions(members), s.logger)
	if err != nil {
		return nil, nil, err
	}

	trustDomain := enr.TrustDomain
	if trustDomain == "" {
		trustDomain = defaultRaftTrustDomain
	}
	nodeURI := clusterenroll.NodeURI(trustDomain, s.config.Cluster.RaftAddress)

	leafPEM, err := clustertls.IssueLeafForKey(caCertPEM, caKeyPEM, signer.Public(), nodeURI)
	if err != nil {
		return nil, nil, err
	}

	cert, err := signerCertificate(leafPEM, signer)
	if err != nil {
		return nil, nil, err
	}

	s.logger.Info("Raft inter-node mTLS auto-provisioned with hardware-resident key",
		"key_backend", enr.KeyBackend,
		"advertising", adv != nil)

	return &qrdbnode.RaftMTLSConfig{
		CACert:      caCertPEM,
		Certificate: cert,
	}, adv, nil
}

// raftNodeSigner returns the crypto.Signer for this node's Raft TLS key on kp,
// reusing an existing key across restarts and generating an ECDSA P-256 key on
// first boot. For hardware backends the private key never leaves the device; the
// returned signer drives all handshake signatures in-device.
func (s *Server) raftNodeSigner(kp types.KeyProvider) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:            fmt.Sprintf("raft-node-%d", s.config.Cluster.NodeID),
		StoreType:     types.ParseStoreType(string(kp.Type())),
		KeyType:       types.KeyTypeSigning,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	// Reuse the key if it already exists (restart); otherwise generate it.
	if signer, err := kp.Signer(s.ctx, attrs); err == nil {
		return signer, nil
	}
	if _, err := kp.GenerateKey(s.ctx, attrs); err != nil {
		return nil, &errs.Wrapped{Msg: "cluster raft enrollment: generate node key", Err: err}
	}
	signer, err := kp.Signer(s.ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "cluster raft enrollment: node signer", Err: err}
	}
	return signer, nil
}

// signerCertificate assembles a tls.Certificate from the issued leaf PEM and the
// backend-held signer. The signer (not exportable key bytes) drives all TLS
// handshake signatures, so a hardware-resident private key never leaves the
// device.
func signerCertificate(leafPEM []byte, signer crypto.Signer) (*tls.Certificate, error) {
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return nil, &ErrRaftLeafDecode{}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "cluster raft enrollment: parse node leaf", Err: err}
	}
	return &tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}
