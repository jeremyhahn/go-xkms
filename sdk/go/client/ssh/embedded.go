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
	"net"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	pkgscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	pkgsession "github.com/jeremyhahn/go-xkms/pkg/ssh/session"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// EmbeddedOptions configures the embedded (in-process) Client. All key
// material lives in the supplied storage.Backend; there is no
// cross-process transport.
type EmbeddedOptions struct {
	// Backend is the shared storage used by every sub-client. Required.
	Backend storage.Backend

	// BackendProvider, when set, enables backend-backed key generation:
	// a GenerateRequest carrying a Backend ID mints the key on that crypto
	// backend (software / tpm2 / pkcs11 / cloud) and delegates signing.
	// When nil, only software keys (sealed in-process) are supported and a
	// GenerateRequest with a Backend ID is rejected. Optional.
	BackendProvider pkgkeys.BackendProvider
}

// NewEmbedded constructs the embedded Client. Returns *NilInputError
// when required options are missing.
func NewEmbedded(opts EmbeddedOptions) (Client, error) {
	if opts.Backend == nil {
		return nil, &NilInputError{Field: "Backend"}
	}
	keyStore, err := pkgkeys.NewBackendStore(opts.Backend)
	if err != nil {
		return nil, err
	}
	hostStore, err := pkgknownhosts.NewBackendStore(opts.Backend)
	if err != nil {
		return nil, err
	}
	authStore, err := pkgauthorized.NewBackendStore(opts.Backend)
	if err != nil {
		return nil, err
	}
	return &embeddedClient{
		backend:      opts.Backend,
		keyStore:     keyStore,
		hostStore:    hostStore,
		authStore:    authStore,
		backendKeyer: opts.BackendProvider,
	}, nil
}

// embeddedClient is the concrete Client for the in-process transport.
// It delegates directly to the pkg/ssh/* implementations.
type embeddedClient struct {
	backend      storage.Backend
	keyStore     pkgkeys.Store
	hostStore    pkgknownhosts.Store
	authStore    pkgauthorized.Store
	backendKeyer pkgkeys.BackendProvider
}

// Keys implements Client.Keys.
func (c *embeddedClient) Keys() KeysClient {
	return &embeddedKeysClient{store: c.keyStore, backendKeyer: c.backendKeyer}
}

// KnownHosts implements Client.KnownHosts.
func (c *embeddedClient) KnownHosts() KnownHostsClient {
	return &embeddedKnownHostsClient{store: c.hostStore}
}

// AuthorizedKeys implements Client.AuthorizedKeys.
func (c *embeddedClient) AuthorizedKeys() AuthorizedKeysClient {
	return &embeddedAuthorizedKeysClient{store: c.authStore}
}

// Session implements Client.Session.
func (c *embeddedClient) Session() SessionClient {
	return &embeddedSessionClient{keys: c.keyStore, hosts: c.hostStore}
}

// Console implements Client.Console for the embedded transport: it resolves the
// key's signer (software enclave OR hardware-backed) and opens an in-process
// interactive PTY, verified against the embedded host-key store.
func (c *embeddedClient) Console(ctx context.Context, req ConsoleConnectRequest, cfg ConsoleConfig) (ConsoleSession, error) {
	signer, err := c.Keys().Signer(ctx, GetKeyRequest{Scope: req.KeyScope, Owner: req.KeyOwner, Name: req.KeyName})
	if err != nil {
		return nil, err
	}
	return OpenConsole(ctx, signer, ConsoleRequest{
		Host:     req.Host,
		Port:     req.Port,
		User:     req.User,
		HostKeys: c.hostStore,
		Scope:    req.KeyScope,
		Owner:    req.KeyOwner,
	}, cfg)
}

// Close implements Client.Close.
func (c *embeddedClient) Close() error {
	if c.backend == nil {
		return nil
	}
	err := c.backend.Close()
	c.backend = nil
	return err
}

// embeddedKeysClient is the embedded KeysClient.
type embeddedKeysClient struct {
	store        pkgkeys.Store
	backendKeyer pkgkeys.BackendProvider
}

// Generate implements KeysClient.Generate. When req.Backend is set the key
// is minted on that crypto backend (private key never leaves a hardware
// backend); otherwise a software key is generated and sealed in-process.
func (c *embeddedKeysClient) Generate(ctx context.Context, req GenerateRequest) (*Key, error) {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: req.Scope}
	}
	algo, err := parseAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	if req.Backend != "" {
		if c.backendKeyer == nil {
			return nil, &BackendUnavailableError{Backend: req.Backend}
		}
		k, gerr := pkgkeys.GenerateOnBackend(ctx, c.backendKeyer, req.Backend, pkgkeys.GenerateOptions{
			Algorithm: algo,
			RSABits:   req.RSABits,
			Comment:   req.Comment,
		}, sc, req.Owner, req.Name)
		if gerr != nil {
			return nil, gerr
		}
		if perr := c.store.Put(ctx, k); perr != nil {
			return nil, perr
		}
		return toDTO(k), nil
	}

	k, err := pkgkeys.Generate(pkgkeys.GenerateOptions{
		Algorithm: algo,
		RSABits:   req.RSABits,
		Comment:   req.Comment,
	})
	if err != nil {
		return nil, err
	}
	k.Scope = sc
	k.Owner = req.Owner
	k.Name = req.Name
	if err := c.store.Put(ctx, k); err != nil {
		k.Destroy()
		return nil, err
	}
	k.Destroy()
	return toDTO(k), nil
}

// Import implements KeysClient.Import.
func (c *embeddedKeysClient) Import(ctx context.Context, req ImportRequest, provider secure.PassphraseProvider) (*Key, error) {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: req.Scope}
	}
	// Wrap the incoming PEM bytes in a Buffer for the duration of the
	// parse. NewBufferFromBytes wipes the caller's slice; ImportRequest
	// is not reused after this call so that is safe.
	pemCopy := make([]byte, len(req.PEM))
	copy(pemCopy, req.PEM)
	buf, err := secure.NewBufferFromBytes(pemCopy)
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	k, err := pkgkeys.ParsePEM(ctx, buf, provider)
	if err != nil {
		return nil, err
	}
	k.Scope = sc
	k.Owner = req.Owner
	k.Name = req.Name
	k.Comment = req.Comment
	if err := c.store.Put(ctx, k); err != nil {
		k.Destroy()
		return nil, err
	}
	dto := toDTO(k)
	k.Destroy()
	return dto, nil
}

// Get implements KeysClient.Get.
func (c *embeddedKeysClient) Get(ctx context.Context, req GetKeyRequest) (*Key, error) {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: req.Scope}
	}
	k, err := c.store.Get(ctx, sc, req.Owner, req.Name)
	if err != nil {
		return nil, err
	}
	defer k.Destroy()
	return toDTO(k), nil
}

// List implements KeysClient.List.
func (c *embeddedKeysClient) List(ctx context.Context, req ListKeysRequest) ([]*Key, error) {
	var sc pkgscope.Scope
	if req.Scope != "" {
		parsed, err := pkgscope.Parse(req.Scope)
		if err != nil {
			return nil, &InvalidScopeError{Value: req.Scope}
		}
		sc = parsed
	}
	list, err := c.store.List(ctx, sc, req.Owner)
	if err != nil {
		return nil, err
	}
	out := make([]*Key, 0, len(list))
	for _, k := range list {
		out = append(out, toDTO(k))
	}
	return out, nil
}

// Delete implements KeysClient.Delete.
func (c *embeddedKeysClient) Delete(ctx context.Context, req DeleteKeyRequest) error {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return &InvalidScopeError{Value: req.Scope}
	}
	return c.store.Delete(ctx, sc, req.Owner, req.Name)
}

// ExportPublic implements KeysClient.ExportPublic.
func (c *embeddedKeysClient) ExportPublic(ctx context.Context, req ExportRequest) (*PublicKey, error) {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: req.Scope}
	}
	k, err := c.store.Get(ctx, sc, req.Owner, req.Name)
	if err != nil {
		return nil, err
	}
	defer k.Destroy()
	return &PublicKey{
		Algorithm:   string(k.Algorithm),
		Line:        strings.TrimRight(string(gossh.MarshalAuthorizedKey(k.PublicKey)), "\n"),
		Fingerprint: k.Fingerprint,
	}, nil
}

// Signer implements KeysClient.Signer. The returned signer keeps the
// underlying *keys.Key alive via closure — callers must call the
// Close() returned by the Session (or equivalent) to destroy the
// enclave. For standalone signer use, the caller is responsible for
// invoking (k.Destroy) on the returned key material out-of-band; at
// present no public API returns both the signer and the Destroy
// handle together, so long-lived signer callers should use Session
// which owns lifetime.
func (c *embeddedKeysClient) Signer(ctx context.Context, req GetKeyRequest) (gossh.Signer, error) {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: req.Scope}
	}
	k, err := c.store.Get(ctx, sc, req.Owner, req.Name)
	if err != nil {
		return nil, err
	}
	// Backend-backed keys delegate signing to the crypto backend; the
	// private key never leaves the device. Software keys use the
	// enclave-backed signer.
	if k.IsBackendBacked() {
		if c.backendKeyer == nil {
			return nil, &BackendUnavailableError{Backend: k.BackendID}
		}
		signer, serr := k.BackendSigner(ctx, c.backendKeyer)
		if serr != nil {
			return nil, serr
		}
		return signer, nil
	}
	signer, err := k.Signer()
	if err != nil {
		k.Destroy()
		return nil, err
	}
	// NOTE: The returned signer shares a reference to k. Because
	// Signer is infrequently consumed standalone (Session owns the
	// typical path), we wrap the signer in a closer-aware adapter
	// that destroys k when the signer is no longer referenced via
	// the pkgkeys.EnclaveSigner contract.
	//
	// The current pkg/ssh/keys.Signer implementation re-opens k for
	// every Sign call, so k must outlive the signer. Until Phase 1c
	// provides a SignerWithClose API, standalone callers should
	// prefer Session (which owns Destroy) — this comment documents
	// the constraint.
	return signer, nil
}

// embeddedKnownHostsClient implements KnownHostsClient.
type embeddedKnownHostsClient struct {
	store pkgknownhosts.Store
}

// Add implements KnownHostsClient.Add. PublicKey is required — the store no
// longer accepts a fingerprint-only pin. Fingerprint and Algorithm are
// derived from the parsed PublicKey rather than trusted from the request, so
// a caller cannot pin a fingerprint that does not match the key it supplied.
func (c *embeddedKnownHostsClient) Add(ctx context.Context, req AddKnownHostRequest) error {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return &InvalidScopeError{Value: req.Scope}
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return &MissingPublicKeyError{Host: req.Host}
	}
	pub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(req.PublicKey))
	if perr != nil {
		return &InvalidPublicKeyError{Host: req.Host, Err: perr}
	}
	source := req.Source
	if source == "" {
		source = pkgknownhosts.SourceManual
	}
	pin := pkgknownhosts.PinFromPublicKey(req.Host, sc, req.Owner, pub, source)
	return c.store.Add(ctx, pin)
}

// List implements KnownHostsClient.List.
func (c *embeddedKnownHostsClient) List(ctx context.Context, req ListKnownHostsRequest) ([]*Pin, error) {
	var sc pkgscope.Scope
	if req.Scope != "" {
		parsed, err := pkgscope.Parse(req.Scope)
		if err != nil {
			return nil, &InvalidScopeError{Value: req.Scope}
		}
		sc = parsed
	}
	list, err := c.store.List(ctx, sc, req.Owner)
	if err != nil {
		return nil, err
	}
	out := make([]*Pin, 0, len(list))
	for _, p := range list {
		out = append(out, &Pin{
			Scope:       string(p.Scope),
			Owner:       p.Owner,
			Host:        p.Host,
			Fingerprint: p.Fingerprint,
			Algorithm:   p.Algorithm,
			AddedAt:     p.AddedAt,
			Source:      p.Source,
			PublicKey:   authorizedKeysLine(p),
		})
	}
	return out, nil
}

// authorizedKeysLine renders a Pin's PublicKey as an authorized_keys-format
// line, or "" if Emit cannot render it (defensive only: Store.List already
// excludes legacy pins that have no PublicKey).
func authorizedKeysLine(p *pkgknownhosts.Pin) string {
	line, err := pkgknownhosts.Emit(p)
	if err != nil {
		return ""
	}
	// Emit returns "<host> <algo> <base64>"; the DTO carries only the
	// key portion (host is already a separate field).
	if idx := strings.Index(line, " "); idx >= 0 {
		return line[idx+1:]
	}
	return ""
}

// Remove implements KnownHostsClient.Remove.
func (c *embeddedKnownHostsClient) Remove(ctx context.Context, req RemoveKnownHostRequest) error {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return &InvalidScopeError{Value: req.Scope}
	}
	return c.store.Remove(ctx, sc, req.Owner, req.Host)
}

// Verify implements KnownHostsClient.Verify.
func (c *embeddedKnownHostsClient) Verify(ctx context.Context, scope, owner, host string, received gossh.PublicKey) error {
	sc, err := pkgscope.Parse(scope)
	if err != nil {
		return &InvalidScopeError{Value: scope}
	}
	return pkgknownhosts.Verify(ctx, c.store, sc, owner, host, received)
}

// Callback implements KnownHostsClient.Callback.
func (c *embeddedKnownHostsClient) Callback(ctx context.Context, scope, owner string) gossh.HostKeyCallback {
	sc, err := pkgscope.Parse(scope)
	if err != nil {
		// Return a callback that always rejects — consistent with the
		// no-TOFU design.
		return func(string, net.Addr, gossh.PublicKey) error {
			return &InvalidScopeError{Value: scope}
		}
	}
	return pkgknownhosts.Callback(ctx, c.store, sc, owner)
}

// embeddedAuthorizedKeysClient implements AuthorizedKeysClient.
type embeddedAuthorizedKeysClient struct {
	store pkgauthorized.Store
}

// Add implements AuthorizedKeysClient.Add. The caller supplies the
// authorized_keys-format line directly; this bypasses Emit so external
// tools can paste lines from ssh-copy-id output verbatim.
func (c *embeddedAuthorizedKeysClient) Add(ctx context.Context, req AddAuthorizedKeyRequest) error {
	sc, err := pkgscope.Parse(req.Scope)
	if err != nil {
		return &InvalidScopeError{Value: req.Scope}
	}
	entry, err := pkgauthorized.ParseLine(req.Line)
	if err != nil {
		return err
	}
	if len(req.Options) > 0 {
		entry.Options = req.Options
	}
	if req.Comment != "" {
		entry.Comment = req.Comment
	}
	return c.store.Add(ctx, sc, req.Owner, req.Name, entry)
}

// Get implements AuthorizedKeysClient.Get.
func (c *embeddedAuthorizedKeysClient) Get(ctx context.Context, scope, owner, name string) (*AuthorizedEntry, error) {
	sc, err := pkgscope.Parse(scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: scope}
	}
	rec, err := c.store.Get(ctx, sc, owner, name)
	if err != nil {
		return nil, err
	}
	return recordToDTO(rec), nil
}

// List implements AuthorizedKeysClient.List.
func (c *embeddedAuthorizedKeysClient) List(ctx context.Context, req ListAuthorizedKeysRequest) ([]*AuthorizedEntry, error) {
	var sc pkgscope.Scope
	if req.Scope != "" {
		parsed, err := pkgscope.Parse(req.Scope)
		if err != nil {
			return nil, &InvalidScopeError{Value: req.Scope}
		}
		sc = parsed
	}
	list, err := c.store.List(ctx, sc, req.Owner)
	if err != nil {
		return nil, err
	}
	out := make([]*AuthorizedEntry, 0, len(list))
	for _, rec := range list {
		out = append(out, recordToDTO(rec))
	}
	return out, nil
}

// Remove implements AuthorizedKeysClient.Remove.
func (c *embeddedAuthorizedKeysClient) Remove(ctx context.Context, scope, owner, name string) error {
	sc, err := pkgscope.Parse(scope)
	if err != nil {
		return &InvalidScopeError{Value: scope}
	}
	return c.store.Remove(ctx, sc, owner, name)
}

// Emit implements AuthorizedKeysClient.Emit. Parses the supplied
// public-key line, applies the requested options / comment, and
// re-emits — a normalization round-trip that also validates the input.
func (c *embeddedAuthorizedKeysClient) Emit(_ context.Context, req EmitRequest) (string, error) {
	entry, err := pkgauthorized.ParseLine(req.PublicKey)
	if err != nil {
		return "", err
	}
	entry.Options = req.Options
	entry.Comment = req.Comment
	return pkgauthorized.Emit(entry)
}

// Verify implements AuthorizedKeysClient.Verify.
func (c *embeddedAuthorizedKeysClient) Verify(ctx context.Context, scope, owner string, received gossh.PublicKey) (*AuthorizedEntry, error) {
	sc, err := pkgscope.Parse(scope)
	if err != nil {
		return nil, &InvalidScopeError{Value: scope}
	}
	rec, err := pkgauthorized.Verify(ctx, c.store, sc, owner, received)
	if err != nil {
		return nil, err
	}
	return recordToDTO(rec), nil
}

// embeddedSessionClient implements SessionClient.
type embeddedSessionClient struct {
	keys  pkgkeys.Store
	hosts pkgknownhosts.Store
}

// Dial implements SessionClient.Dial. Loads the key from the key store
// (creating a fresh enclave-backed copy), constructs a DialRequest, and
// hands ownership of the key to the returned Session. On any failure
// the enclave is destroyed before returning.
func (c *embeddedSessionClient) Dial(ctx context.Context, req SessionDialRequest) (Session, error) {
	sc, err := pkgscope.Parse(req.KeyScope)
	if err != nil {
		return nil, &InvalidScopeError{Value: req.KeyScope}
	}
	hostScope := sc
	hostOwner := req.KeyOwner
	if req.HostKeyScope != "" {
		parsed, perr := pkgscope.Parse(req.HostKeyScope)
		if perr != nil {
			return nil, &InvalidScopeError{Value: req.HostKeyScope}
		}
		hostScope = parsed
	}
	if req.HostKeyOwner != "" {
		hostOwner = req.HostKeyOwner
	}
	k, err := c.keys.Get(ctx, sc, req.KeyOwner, req.KeyName)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	sess, err := pkgsession.Dial(ctx, pkgsession.DialRequest{
		Host:            req.Host,
		Port:            req.Port,
		User:            req.User,
		Key:             k,
		HostKeyScope:    hostScope,
		HostKeyOwner:    hostOwner,
		KnownHostsStore: c.hosts,
		Timeout:         timeout,
	})
	if err != nil {
		k.Destroy()
		return nil, err
	}
	return &embeddedSession{inner: sess}, nil
}

// embeddedSession adapts pkgsession.Session to the SDK Session
// interface. They are equivalent — the thin adapter exists so the SDK
// contract stays stable if the internal interface ever diverges.
type embeddedSession struct {
	inner pkgsession.Session
}

// Run implements Session.Run.
func (s *embeddedSession) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	return s.inner.Run(ctx, cmd)
}

// Close implements Session.Close.
func (s *embeddedSession) Close() error { return s.inner.Close() }

// parseAlgorithm maps a canonical string to the internal Algorithm
// constant. Returns *InvalidAlgorithmError on unknown input.
func parseAlgorithm(v string) (pkgkeys.Algorithm, error) {
	switch v {
	case string(pkgkeys.AlgorithmEd25519):
		return pkgkeys.AlgorithmEd25519, nil
	case string(pkgkeys.AlgorithmRSA):
		return pkgkeys.AlgorithmRSA, nil
	case string(pkgkeys.AlgorithmECDSAP256):
		return pkgkeys.AlgorithmECDSAP256, nil
	case string(pkgkeys.AlgorithmECDSAP384):
		return pkgkeys.AlgorithmECDSAP384, nil
	case string(pkgkeys.AlgorithmECDSAP521):
		return pkgkeys.AlgorithmECDSAP521, nil
	}
	return "", &InvalidAlgorithmError{Value: v}
}

// toDTO converts a *pkgkeys.Key into the transport-safe Key DTO. Never
// opens the underlying Material enclave.
func toDTO(k *pkgkeys.Key) *Key {
	pubLine := ""
	if k.PublicKey != nil {
		pubLine = strings.TrimRight(string(gossh.MarshalAuthorizedKey(k.PublicKey)), "\n")
	}
	return &Key{
		Scope:        string(k.Scope),
		Owner:        k.Owner,
		Name:         k.Name,
		Algorithm:    string(k.Algorithm),
		PublicKey:    pubLine,
		Fingerprint:  k.Fingerprint,
		CreatedAt:    k.CreatedAt,
		Comment:      k.Comment,
		Backend:      k.BackendID,
		BackendKeyID: k.BackendKeyID,
	}
}

// recordToDTO maps a *pkgauthorized.Record to the transport
// AuthorizedEntry. The scope/owner/name reported are the ones the store
// read back, not an echo of the request, so a listed entry carries the
// name a caller needs for a follow-up Get or Remove.
//
// A nil Record maps to nil; the stores in this repository never produce
// one, but the DTO conversion must not panic on a third-party Store.
func recordToDTO(rec *pkgauthorized.Record) *AuthorizedEntry {
	if rec == nil {
		return nil
	}
	dto := &AuthorizedEntry{
		Scope: string(rec.Scope),
		Owner: rec.Owner,
		Name:  rec.Name,
	}
	if rec.Entry == nil {
		return dto
	}
	if line, err := pkgauthorized.Emit(rec.Entry); err == nil {
		dto.Line = line
	}
	dto.Options = rec.Entry.Options
	dto.Comment = rec.Entry.Comment
	return dto
}
