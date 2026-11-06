// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"context"
	"crypto/rand"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	pkgsshkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// sshUnavailable returns a codes.Unavailable status when no SSH client is
// wired into the service.
func (s *Service) sshUnavailable() error {
	return status.Error(codes.Unavailable, "ssh subsystem not configured")
}

// SSHGenerateKey implements KeystoreService.SSHGenerateKey.
func (s *Service) SSHGenerateKey(ctx context.Context, req *pb.SSHGenerateKeyRequest) (*pb.SSHKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionWrite, "ssh-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	key, err := s.sshClient.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope:     req.GetScope(),
		Owner:     req.GetOwner(),
		Name:      req.GetName(),
		Algorithm: req.GetAlgorithm(),
		RSABits:   int(req.GetRsaBits()),
		Comment:   req.GetComment(),
		Backend:   req.GetBackend(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	return &pb.SSHKeyResponse{Key: sshKeyToProto(key)}, nil
}

// SSHImportKey implements KeystoreService.SSHImportKey. Only unencrypted PEMs
// are accepted over the wire (no passphrase channel); encrypted PEMs return
// an error from the SDK.
func (s *Service) SSHImportKey(ctx context.Context, req *pb.SSHImportKeyRequest) (*pb.SSHKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionWrite, "ssh-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	key, err := s.sshClient.Keys().Import(ctx, sdkssh.ImportRequest{
		Scope:   req.GetScope(),
		Owner:   req.GetOwner(),
		Name:    req.GetName(),
		PEM:     req.GetPem(),
		Comment: req.GetComment(),
	}, nil)
	if err != nil {
		return nil, sshStatus(err)
	}
	return &pb.SSHKeyResponse{Key: sshKeyToProto(key)}, nil
}

// SSHListKeys implements KeystoreService.SSHListKeys.
func (s *Service) SSHListKeys(ctx context.Context, req *pb.SSHListKeysRequest) (*pb.SSHListKeysResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionRead, "ssh-keys"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	keys, err := s.sshClient.Keys().List(ctx, sdkssh.ListKeysRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	out := make([]*pb.SSHKeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, sshKeyToProto(k))
	}
	return &pb.SSHListKeysResponse{Keys: out}, nil
}

// SSHGetKey implements KeystoreService.SSHGetKey.
func (s *Service) SSHGetKey(ctx context.Context, req *pb.SSHKeyRef) (*pb.SSHKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionRead, "ssh-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	key, err := s.sshClient.Keys().Get(ctx, sdkssh.GetKeyRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
		Name:  req.GetName(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	return &pb.SSHKeyResponse{Key: sshKeyToProto(key)}, nil
}

// SSHDeleteKey implements KeystoreService.SSHDeleteKey.
func (s *Service) SSHDeleteKey(ctx context.Context, req *pb.SSHKeyRef) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionDelete, "ssh-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	if err := s.sshClient.Keys().Delete(ctx, sdkssh.DeleteKeyRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
		Name:  req.GetName(),
	}); err != nil {
		return nil, sshStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// SSHExportPublic implements KeystoreService.SSHExportPublic.
func (s *Service) SSHExportPublic(ctx context.Context, req *pb.SSHKeyRef) (*pb.SSHPublicKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionRead, "ssh-public-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	pub, err := s.sshClient.Keys().ExportPublic(ctx, sdkssh.ExportRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
		Name:  req.GetName(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	return &pb.SSHPublicKeyResponse{
		Algorithm:   pub.Algorithm,
		Line:        pub.Line,
		Fingerprint: pub.Fingerprint,
	}, nil
}

// SSHSign implements KeystoreService.SSHSign. It resolves the key's signer
// (delegated to the backend for hardware-backed keys) and signs the digest.
func (s *Service) SSHSign(ctx context.Context, req *pb.SSHSignRequest) (*pb.SSHSignResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionWrite, "ssh-sign"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	ref := req.GetKey()
	signer, err := s.sshClient.Keys().Signer(ctx, sdkssh.GetKeyRequest{
		Scope: ref.GetScope(),
		Owner: ref.GetOwner(),
		Name:  ref.GetName(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	// A named algorithm signs through ssh.AlgorithmSigner (RFC 8332 §3); a
	// refused one is the caller's error, not the server's.
	sig, err := pkgsshkeys.SignWithAlgorithm(signer, rand.Reader, req.GetDigest(), req.GetAlgorithm())
	if pkgsshkeys.IsSignatureAlgorithmRefusal(err) {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err != nil {
		return nil, sshStatus(err)
	}
	return &pb.SSHSignResponse{Format: sig.Format, Blob: sig.Blob}, nil
}

// SSHAddKnownHost implements KeystoreService.SSHAddKnownHost.
func (s *Service) SSHAddKnownHost(ctx context.Context, req *pb.SSHAddKnownHostRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionWrite, "ssh-known-host"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	if err := s.sshClient.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope:       req.GetScope(),
		Owner:       req.GetOwner(),
		Host:        req.GetHost(),
		Fingerprint: req.GetFingerprint(),
		Algorithm:   req.GetAlgorithm(),
		Source:      req.GetSource(),
		PublicKey:   req.GetPublicKey(),
	}); err != nil {
		return nil, sshStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// SSHListKnownHosts implements KeystoreService.SSHListKnownHosts.
func (s *Service) SSHListKnownHosts(ctx context.Context, req *pb.SSHListKnownHostsRequest) (*pb.SSHListKnownHostsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionRead, "ssh-known-hosts"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	pins, err := s.sshClient.KnownHosts().List(ctx, sdkssh.ListKnownHostsRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	out := make([]*pb.SSHPin, 0, len(pins))
	for _, p := range pins {
		out = append(out, &pb.SSHPin{
			Scope:       p.Scope,
			Owner:       p.Owner,
			Host:        p.Host,
			Fingerprint: p.Fingerprint,
			Algorithm:   p.Algorithm,
			AddedAt:     timestamppb.New(p.AddedAt),
			Source:      p.Source,
			PublicKey:   p.PublicKey,
		})
	}
	return &pb.SSHListKnownHostsResponse{Pins: out}, nil
}

// SSHRemoveKnownHost implements KeystoreService.SSHRemoveKnownHost.
func (s *Service) SSHRemoveKnownHost(ctx context.Context, req *pb.SSHRemoveKnownHostRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionDelete, "ssh-known-host"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	if err := s.sshClient.KnownHosts().Remove(ctx, sdkssh.RemoveKnownHostRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
		Host:  req.GetHost(),
	}); err != nil {
		return nil, sshStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// SSHAddAuthorizedKey implements KeystoreService.SSHAddAuthorizedKey.
func (s *Service) SSHAddAuthorizedKey(ctx context.Context, req *pb.SSHAddAuthorizedKeyRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionWrite, "ssh-authorized-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	if err := s.sshClient.AuthorizedKeys().Add(ctx, sdkssh.AddAuthorizedKeyRequest{
		Scope:   req.GetScope(),
		Owner:   req.GetOwner(),
		Name:    req.GetName(),
		Line:    req.GetLine(),
		Options: req.GetOptions(),
		Comment: req.GetComment(),
	}); err != nil {
		return nil, sshStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// SSHListAuthorizedKeys implements KeystoreService.SSHListAuthorizedKeys.
func (s *Service) SSHListAuthorizedKeys(ctx context.Context, req *pb.SSHListAuthorizedKeysRequest) (*pb.SSHListAuthorizedKeysResponse, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionRead, "ssh-authorized-keys"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	entries, err := s.sshClient.AuthorizedKeys().List(ctx, sdkssh.ListAuthorizedKeysRequest{
		Scope: req.GetScope(),
		Owner: req.GetOwner(),
	})
	if err != nil {
		return nil, sshStatus(err)
	}
	out := make([]*pb.SSHAuthorizedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, &pb.SSHAuthorizedEntry{
			Scope:   e.Scope,
			Owner:   e.Owner,
			Name:    e.Name,
			Line:    e.Line,
			Options: e.Options,
			Comment: e.Comment,
		})
	}
	return &pb.SSHListAuthorizedKeysResponse{Entries: out}, nil
}

// SSHRemoveAuthorizedKey implements KeystoreService.SSHRemoveAuthorizedKey.
func (s *Service) SSHRemoveAuthorizedKey(ctx context.Context, req *pb.SSHAuthorizedKeyRef) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceSSH, auth.ActionDelete, "ssh-authorized-key"); err != nil {
		return nil, err
	}
	if s.sshClient == nil {
		return nil, s.sshUnavailable()
	}
	if err := s.sshClient.AuthorizedKeys().Remove(ctx, req.GetScope(), req.GetOwner(), req.GetName()); err != nil {
		return nil, sshStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// sshKeyToProto converts an SDK Key DTO to its proto representation.
func sshKeyToProto(k *sdkssh.Key) *pb.SSHKeyInfo {
	if k == nil {
		return nil
	}
	return &pb.SSHKeyInfo{
		Scope:        k.Scope,
		Owner:        k.Owner,
		Name:         k.Name,
		Algorithm:    k.Algorithm,
		PublicKey:    k.PublicKey,
		Fingerprint:  k.Fingerprint,
		CreatedAt:    timestamppb.New(k.CreatedAt),
		Comment:      k.Comment,
		Backend:      k.Backend,
		BackendKeyId: k.BackendKeyID,
	}
}

// sshStatus maps an SDK SSH error to a gRPC status, reusing
// sdkssh.GRPCCodeForError -- the single table shared with the REST transport
// (sdkssh.HTTPStatusForError) and the MCP transport (sdkssh.
// JSONRPCCodeForError) -- so a *pkgkeys.KeyNotFoundError, a
// *pkgknownhosts.NotFoundError/DuplicateError/MismatchError, and their
// authorized_keys siblings report the same NotFound/AlreadyExists/
// FailedPrecondition semantics here that REST already reports as 404/409,
// instead of every embedded-store error short of *sdkssh.NotFoundError
// falling through to codes.Internal (#769).
//
// A code this table cannot classify (codes.Internal) does not echo err's
// message: an error this table does not vouch for may wrap storage-backend
// detail (a filesystem path, a driver error) that should not reach an RPC
// caller. Every recognized class carries its own caller-facing typed
// message instead.
func sshStatus(err error) error {
	if err == nil {
		return nil
	}
	code := sdkssh.GRPCCodeForError(err)
	if code == codes.Internal {
		return status.Error(code, "ssh: internal error")
	}
	return status.Error(code, err.Error())
}
