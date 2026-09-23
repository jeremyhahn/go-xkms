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

package ssh

import (
	"context"
	"io"
	"net"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// GRPCOptions configures the gRPC transport for the SSH SDK client.
type GRPCOptions struct {
	// Endpoint is the dial target (host:port). Required.
	Endpoint string

	// TLSEnabled turns on TLS. When false an insecure connection is used
	// (suitable for unix-socket / loopback test rigs only).
	TLSEnabled bool

	// TLSCAFile is the PEM CA bundle used to verify the server. Optional.
	TLSCAFile string

	// TLSCertFile / TLSKeyFile enable mTLS client authentication. Optional.
	TLSCertFile string
	TLSKeyFile  string

	// ServerName overrides the TLS SNI / verification name. Optional.
	ServerName string

	// DialOptions are extra gRPC dial options appended verbatim. Optional.
	DialOptions []grpc.DialOption
}

// NewGRPC constructs an SSH Client over gRPC. The returned client dials the
// configured endpoint and speaks the KeystoreService SSH RPCs.
func NewGRPC(opts GRPCOptions) (Client, error) {
	if opts.Endpoint == "" {
		return nil, &NilInputError{Field: "Endpoint"}
	}

	dialOpts := make([]grpc.DialOption, 0, 2+len(opts.DialOptions))
	if opts.TLSEnabled {
		tlsConfig, err := buildTLSConfig(transport.TLSOptions{
			CAFile:     opts.TLSCAFile,
			CertFile:   opts.TLSCertFile,
			KeyFile:    opts.TLSKeyFile,
			ServerName: opts.ServerName,
		})
		if err != nil {
			return nil, err
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	dialOpts = append(dialOpts, opts.DialOptions...)

	conn, err := grpc.NewClient(opts.Endpoint, dialOpts...)
	if err != nil {
		return nil, &ProtocolError{Message: "dial grpc", Err: err}
	}
	return &grpcClient{conn: conn, svc: pb.NewKeystoreServiceClient(conn)}, nil
}

// grpcClient is the concrete Client for the gRPC transport.
type grpcClient struct {
	conn *grpc.ClientConn
	svc  pb.KeystoreServiceClient
}

func (c *grpcClient) Keys() KeysClient { return &grpcKeysClient{svc: c.svc} }

func (c *grpcClient) KnownHosts() KnownHostsClient { return &grpcKnownHostsClient{svc: c.svc} }

func (c *grpcClient) AuthorizedKeys() AuthorizedKeysClient {
	return &grpcAuthorizedKeysClient{svc: c.svc}
}

func (c *grpcClient) Session() SessionClient { return &grpcSessionClient{} }

// Console is not supported over gRPC (or the Unix socket, which serves the
// same service): the xkms server is a key vault and CA and never terminates an
// SSH session. Terminating SSH there would let an authenticated caller make
// the appliance open outbound connections to arbitrary hosts and proxy an
// interactive shell through them. The client (xkey) runs the SSH protocol
// itself and asks the server only to sign the authentication challenge with
// the stored key, which never leaves the vault.
func (c *grpcClient) Console(_ context.Context, _ ConsoleConnectRequest, _ ConsoleConfig) (ConsoleSession, error) {
	return nil, &ConsoleUnsupportedError{Transport: "grpc"}
}

// Close closes the gRPC connection.
func (c *grpcClient) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// ----------------------------------------------------------------------------
// Keys sub-client.
// ----------------------------------------------------------------------------

type grpcKeysClient struct {
	svc pb.KeystoreServiceClient
}

func (k *grpcKeysClient) Generate(ctx context.Context, req GenerateRequest) (*Key, error) {
	resp, err := k.svc.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{
		Scope:     req.Scope,
		Owner:     req.Owner,
		Name:      req.Name,
		Algorithm: req.Algorithm,
		RsaBits:   int32(req.RSABits),
		Comment:   req.Comment,
		Backend:   req.Backend,
	})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	return protoToKey(resp.GetKey()), nil
}

func (k *grpcKeysClient) Import(ctx context.Context, req ImportRequest, _ secure.PassphraseProvider) (*Key, error) {
	// The gRPC import path forwards the PEM bytes; encrypted PEMs are
	// rejected server-side (no passphrase channel over the wire).
	resp, err := k.svc.SSHImportKey(ctx, &pb.SSHImportKeyRequest{
		Scope:   req.Scope,
		Owner:   req.Owner,
		Name:    req.Name,
		Pem:     req.PEM,
		Comment: req.Comment,
	})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	return protoToKey(resp.GetKey()), nil
}

func (k *grpcKeysClient) Get(ctx context.Context, req GetKeyRequest) (*Key, error) {
	resp, err := k.svc.SSHGetKey(ctx, &pb.SSHKeyRef{Scope: req.Scope, Owner: req.Owner, Name: req.Name})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	return protoToKey(resp.GetKey()), nil
}

func (k *grpcKeysClient) List(ctx context.Context, req ListKeysRequest) ([]*Key, error) {
	resp, err := k.svc.SSHListKeys(ctx, &pb.SSHListKeysRequest{Scope: req.Scope, Owner: req.Owner})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	out := make([]*Key, 0, len(resp.GetKeys()))
	for _, pk := range resp.GetKeys() {
		out = append(out, protoToKey(pk))
	}
	return out, nil
}

func (k *grpcKeysClient) Delete(ctx context.Context, req DeleteKeyRequest) error {
	_, err := k.svc.SSHDeleteKey(ctx, &pb.SSHKeyRef{Scope: req.Scope, Owner: req.Owner, Name: req.Name})
	return mapGRPCError(err)
}

func (k *grpcKeysClient) ExportPublic(ctx context.Context, req ExportRequest) (*PublicKey, error) {
	resp, err := k.svc.SSHExportPublic(ctx, &pb.SSHKeyRef{Scope: req.Scope, Owner: req.Owner, Name: req.Name})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	return &PublicKey{Algorithm: resp.GetAlgorithm(), Line: resp.GetLine(), Fingerprint: resp.GetFingerprint()}, nil
}

func (k *grpcKeysClient) Signer(ctx context.Context, req GetKeyRequest) (gossh.Signer, error) {
	pub, err := k.ExportPublic(ctx, ExportRequest(req))
	if err != nil {
		return nil, err
	}
	sshPub, err := parseExportedPublicKey(pub.Line)
	if err != nil {
		return nil, err
	}
	return &grpcSigner{svc: k.svc, scope: req.Scope, owner: req.Owner, name: req.Name, pub: sshPub}, nil
}

// grpcSigner is a forward-signing proxy: each Sign forwards the digest to the
// server's SSHSign RPC (delegated to the backend for hardware-backed keys).
type grpcSigner struct {
	svc   pb.KeystoreServiceClient
	scope string
	owner string
	name  string
	pub   gossh.PublicKey
}

func (s *grpcSigner) PublicKey() gossh.PublicKey { return s.pub }

func (s *grpcSigner) Sign(_ io.Reader, data []byte) (*gossh.Signature, error) {
	resp, err := s.svc.SSHSign(context.Background(), &pb.SSHSignRequest{
		Key:    &pb.SSHKeyRef{Scope: s.scope, Owner: s.owner, Name: s.name},
		Digest: data,
	})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	return &gossh.Signature{Format: resp.GetFormat(), Blob: resp.GetBlob()}, nil
}

// ----------------------------------------------------------------------------
// KnownHosts sub-client.
// ----------------------------------------------------------------------------

type grpcKnownHostsClient struct {
	svc pb.KeystoreServiceClient
}

func (k *grpcKnownHostsClient) Add(ctx context.Context, req AddKnownHostRequest) error {
	_, err := k.svc.SSHAddKnownHost(ctx, &pb.SSHAddKnownHostRequest{
		Scope:       req.Scope,
		Owner:       req.Owner,
		Host:        req.Host,
		Fingerprint: req.Fingerprint,
		Algorithm:   req.Algorithm,
		Source:      req.Source,
		PublicKey:   req.PublicKey,
	})
	return mapGRPCError(err)
}

func (k *grpcKnownHostsClient) List(ctx context.Context, req ListKnownHostsRequest) ([]*Pin, error) {
	resp, err := k.svc.SSHListKnownHosts(ctx, &pb.SSHListKnownHostsRequest{Scope: req.Scope, Owner: req.Owner})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	out := make([]*Pin, 0, len(resp.GetPins()))
	for _, p := range resp.GetPins() {
		out = append(out, &Pin{
			Scope:       p.GetScope(),
			Owner:       p.GetOwner(),
			Host:        p.GetHost(),
			Fingerprint: p.GetFingerprint(),
			Algorithm:   p.GetAlgorithm(),
			AddedAt:     p.GetAddedAt().AsTime(),
			Source:      p.GetSource(),
			PublicKey:   p.GetPublicKey(),
		})
	}
	return out, nil
}

func (k *grpcKnownHostsClient) Remove(ctx context.Context, req RemoveKnownHostRequest) error {
	_, err := k.svc.SSHRemoveKnownHost(ctx, &pb.SSHRemoveKnownHostRequest{Scope: req.Scope, Owner: req.Owner, Host: req.Host})
	return mapGRPCError(err)
}

func (k *grpcKnownHostsClient) Verify(ctx context.Context, scope, owner, host string, received gossh.PublicKey) error {
	if received == nil {
		return &NilInputError{Field: "received"}
	}
	// Host-key trust is a local comparison against the pinned fingerprint;
	// fetch the scoped pins and compare on the client where the connection is
	// being made.
	pins, err := k.List(ctx, ListKnownHostsRequest{Scope: scope, Owner: owner})
	if err != nil {
		return err
	}
	want := gossh.FingerprintSHA256(received)
	for _, p := range pins {
		if p.Host == host {
			if p.Fingerprint == want {
				return nil
			}
			return &MismatchError{Host: host, Expected: p.Fingerprint, Received: want}
		}
	}
	return &NotFoundError{Resource: "known_host", Message: host}
}

func (k *grpcKnownHostsClient) Callback(ctx context.Context, scope, owner string) gossh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key gossh.PublicKey) error {
		return k.Verify(ctx, scope, owner, stripCallbackPort(hostname), key)
	}
}

// ----------------------------------------------------------------------------
// AuthorizedKeys sub-client.
// ----------------------------------------------------------------------------

type grpcAuthorizedKeysClient struct {
	svc pb.KeystoreServiceClient
}

func (a *grpcAuthorizedKeysClient) Add(ctx context.Context, req AddAuthorizedKeyRequest) error {
	_, err := a.svc.SSHAddAuthorizedKey(ctx, &pb.SSHAddAuthorizedKeyRequest{
		Scope:   req.Scope,
		Owner:   req.Owner,
		Name:    req.Name,
		Line:    req.Line,
		Options: req.Options,
		Comment: req.Comment,
	})
	return mapGRPCError(err)
}

func (a *grpcAuthorizedKeysClient) Get(ctx context.Context, scope, owner, name string) (*AuthorizedEntry, error) {
	entries, err := a.List(ctx, ListAuthorizedKeysRequest{Scope: scope, Owner: owner})
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, &NotFoundError{Resource: "authorized_key", Message: name}
}

func (a *grpcAuthorizedKeysClient) List(ctx context.Context, req ListAuthorizedKeysRequest) ([]*AuthorizedEntry, error) {
	resp, err := a.svc.SSHListAuthorizedKeys(ctx, &pb.SSHListAuthorizedKeysRequest{Scope: req.Scope, Owner: req.Owner})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	out := make([]*AuthorizedEntry, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		out = append(out, &AuthorizedEntry{
			Scope:   e.GetScope(),
			Owner:   e.GetOwner(),
			Name:    e.GetName(),
			Line:    e.GetLine(),
			Options: e.GetOptions(),
			Comment: e.GetComment(),
		})
	}
	return out, nil
}

func (a *grpcAuthorizedKeysClient) Remove(ctx context.Context, scope, owner, name string) error {
	_, err := a.svc.SSHRemoveAuthorizedKey(ctx, &pb.SSHAuthorizedKeyRef{Scope: scope, Owner: owner, Name: name})
	return mapGRPCError(err)
}

func (a *grpcAuthorizedKeysClient) Emit(_ context.Context, req EmitRequest) (string, error) {
	// Emit is a pure local normalization — parse the supplied public-key line,
	// apply options/comment, and re-emit. No server round-trip required.
	entry, err := pkgauthorized.ParseLine(req.PublicKey)
	if err != nil {
		return "", err
	}
	entry.Options = req.Options
	entry.Comment = req.Comment
	return pkgauthorized.Emit(entry)
}

func (a *grpcAuthorizedKeysClient) Verify(ctx context.Context, scope, owner string, received gossh.PublicKey) (*AuthorizedEntry, error) {
	if received == nil {
		return nil, &NilInputError{Field: "received"}
	}
	entries, err := a.List(ctx, ListAuthorizedKeysRequest{Scope: scope, Owner: owner})
	if err != nil {
		return nil, err
	}
	want := gossh.FingerprintSHA256(received)
	for _, e := range entries {
		pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(e.Line))
		if perr != nil {
			continue
		}
		if gossh.FingerprintSHA256(pub) == want {
			return e, nil
		}
	}
	return nil, &NotFoundError{Resource: "authorized_key", Message: want}
}

// ----------------------------------------------------------------------------
// Session sub-client.
// ----------------------------------------------------------------------------

// grpcSessionClient does not support interactive outbound SSH sessions over
// gRPC — sessions are an embedded-transport capability (the SDK dials the host
// directly). Remote callers should use the Signer proxy with their own dialer.
type grpcSessionClient struct{}

func (c *grpcSessionClient) Dial(_ context.Context, _ SessionDialRequest) (Session, error) {
	return nil, &NotImplementedError{Transport: "grpc", Op: "Session.Dial"}
}

// protoToKey converts a proto SSHKeyInfo to the SDK Key DTO.
func protoToKey(k *pb.SSHKeyInfo) *Key {
	if k == nil {
		return nil
	}
	return &Key{
		Scope:        k.GetScope(),
		Owner:        k.GetOwner(),
		Name:         k.GetName(),
		Algorithm:    k.GetAlgorithm(),
		PublicKey:    k.GetPublicKey(),
		Fingerprint:  k.GetFingerprint(),
		CreatedAt:    k.GetCreatedAt().AsTime(),
		Comment:      k.GetComment(),
		Backend:      k.GetBackend(),
		BackendKeyID: k.GetBackendKeyId(),
	}
}

// mapGRPCError maps a gRPC status error back to a transport-neutral SDK error.
func mapGRPCError(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return &ProtocolError{Message: "grpc call", Err: err}
	}
	switch st.Code() {
	case codes.NotFound:
		return &NotFoundError{Resource: "ssh", Message: st.Message()}
	case codes.InvalidArgument:
		return &InvalidRequestError{Message: st.Message()}
	case codes.FailedPrecondition, codes.Unavailable:
		return &ServerError{Message: st.Message()}
	default:
		return &ProtocolError{Message: st.Message(), Err: err}
	}
}
