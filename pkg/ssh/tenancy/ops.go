// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tenancy

import (
	"context"
	"net"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ------------------------------------------------------------------
// Keys.
// ------------------------------------------------------------------

// keysClient binds every key operation to the caller.
type keysClient struct {
	c *client
}

// Generate implements sdkssh.KeysClient. A key may be created only under an
// owner the caller owns; otherwise nothing is generated -- not even on a
// hardware backend -- and the refusal is the not-found answer for the key.
func (k *keysClient) Generate(ctx context.Context, req sdkssh.GenerateRequest) (*sdkssh.Key, error) {
	p, err := k.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	if !p.allowed {
		return nil, k.refuse(ctx, "keys.generate", req.Scope, req.Owner, req.Name)
	}
	return p.client.Keys().Generate(ctx, req)
}

// Import implements sdkssh.KeysClient, bound as Generate is.
func (k *keysClient) Import(ctx context.Context, req sdkssh.ImportRequest, provider secure.PassphraseProvider) (*sdkssh.Key, error) {
	p, err := k.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	if !p.allowed {
		return nil, k.refuse(ctx, "keys.import", req.Scope, req.Owner, req.Name)
	}
	return p.client.Keys().Import(ctx, req, provider)
}

// Get implements sdkssh.KeysClient.
func (k *keysClient) Get(ctx context.Context, req sdkssh.GetKeyRequest) (*sdkssh.Key, error) {
	p, err := k.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	key, err := p.client.Keys().Get(ctx, req)
	if err != nil {
		return nil, k.c.wrapRefusal(ctx, p, "keys.get", req.Scope, req.Owner, err)
	}
	return key, nil
}

// List implements sdkssh.KeysClient. The listing holds only keys the caller
// owns, whatever the filters name.
func (k *keysClient) List(ctx context.Context, req sdkssh.ListKeysRequest) ([]*sdkssh.Key, error) {
	p, who, err := k.c.listPartition(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	all, err := p.Keys().List(ctx, req)
	if err != nil {
		return nil, err
	}
	owned := make([]*sdkssh.Key, 0, len(all))
	for _, key := range all {
		if who.visible(key.Scope, key.Owner) {
			owned = append(owned, key)
		}
	}
	return owned, nil
}

// Delete implements sdkssh.KeysClient.
func (k *keysClient) Delete(ctx context.Context, req sdkssh.DeleteKeyRequest) error {
	p, err := k.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return err
	}
	if err := p.client.Keys().Delete(ctx, req); err != nil {
		return k.c.wrapRefusal(ctx, p, "keys.delete", req.Scope, req.Owner, err)
	}
	return nil
}

// ExportPublic implements sdkssh.KeysClient.
func (k *keysClient) ExportPublic(ctx context.Context, req sdkssh.ExportRequest) (*sdkssh.PublicKey, error) {
	p, err := k.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	pub, err := p.client.Keys().ExportPublic(ctx, req)
	if err != nil {
		return nil, k.c.wrapRefusal(ctx, p, "keys.export", req.Scope, req.Owner, err)
	}
	return pub, nil
}

// Signer implements sdkssh.KeysClient. The signer resolves a backend-backed
// key in the partition tenant's backend namespace.
func (k *keysClient) Signer(ctx context.Context, req sdkssh.GetKeyRequest) (gossh.Signer, error) {
	p, err := k.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	signer, err := p.client.Keys().Signer(ctx, req)
	if err != nil {
		return nil, k.c.wrapRefusal(ctx, p, "keys.signer", req.Scope, req.Owner, err)
	}
	return signer, nil
}

// refuse answers a refused key write with the not-found answer for the key
// it names.
func (k *keysClient) refuse(ctx context.Context, op, scope, owner, name string) error {
	_, miss := k.c.empty.Keys().Get(ctx, sdkssh.GetKeyRequest{Scope: scope, Owner: owner, Name: name})
	return newOwnerBindingError(ctx, op, scope, owner, miss)
}

// ------------------------------------------------------------------
// Known hosts.
// ------------------------------------------------------------------

// knownHostsClient binds every host-key pin operation to the caller.
type knownHostsClient struct {
	c *client
}

// Add implements sdkssh.KnownHostsClient. A pin may be added only under an
// owner the caller owns; otherwise the refusal is the not-found answer for
// the pin.
func (h *knownHostsClient) Add(ctx context.Context, req sdkssh.AddKnownHostRequest) error {
	p, err := h.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return err
	}
	if !p.allowed {
		miss := h.c.empty.KnownHosts().Remove(ctx, sdkssh.RemoveKnownHostRequest{Scope: req.Scope, Owner: req.Owner, Host: req.Host})
		return newOwnerBindingError(ctx, "knownHosts.add", req.Scope, req.Owner, miss)
	}
	return p.client.KnownHosts().Add(ctx, req)
}

// List implements sdkssh.KnownHostsClient. The listing holds only pins the
// caller owns, whatever the filters name.
func (h *knownHostsClient) List(ctx context.Context, req sdkssh.ListKnownHostsRequest) ([]*sdkssh.Pin, error) {
	p, who, err := h.c.listPartition(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	all, err := p.KnownHosts().List(ctx, req)
	if err != nil {
		return nil, err
	}
	owned := make([]*sdkssh.Pin, 0, len(all))
	for _, pin := range all {
		if who.visible(pin.Scope, pin.Owner) {
			owned = append(owned, pin)
		}
	}
	return owned, nil
}

// Remove implements sdkssh.KnownHostsClient.
func (h *knownHostsClient) Remove(ctx context.Context, req sdkssh.RemoveKnownHostRequest) error {
	p, err := h.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return err
	}
	if err := p.client.KnownHosts().Remove(ctx, req); err != nil {
		return h.c.wrapRefusal(ctx, p, "knownHosts.remove", req.Scope, req.Owner, err)
	}
	return nil
}

// Verify implements sdkssh.KnownHostsClient.
func (h *knownHostsClient) Verify(ctx context.Context, scope, owner, host string, received gossh.PublicKey) error {
	p, err := h.c.serve(ctx, scope, owner)
	if err != nil {
		return err
	}
	if err := p.client.KnownHosts().Verify(ctx, scope, owner, host, received); err != nil {
		return h.c.wrapRefusal(ctx, p, "knownHosts.verify", scope, owner, err)
	}
	return nil
}

// Callback implements sdkssh.KnownHostsClient. A callback over pins the
// caller does not own rejects every host as unpinned.
func (h *knownHostsClient) Callback(ctx context.Context, scope, owner string) gossh.HostKeyCallback {
	p, err := h.c.serve(ctx, scope, owner)
	if err != nil {
		return func(string, net.Addr, gossh.PublicKey) error { return err }
	}
	verify := p.client.KnownHosts().Callback(ctx, scope, owner)
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if err := verify(hostname, remote, key); err != nil {
			return h.c.wrapRefusal(ctx, p, "knownHosts.callback", scope, owner, err)
		}
		return nil
	}
}

// ------------------------------------------------------------------
// Authorized keys.
// ------------------------------------------------------------------

// authorizedKeysClient binds every authorized_keys operation to the caller.
type authorizedKeysClient struct {
	c *client
}

// Add implements sdkssh.AuthorizedKeysClient. An entry may be added only
// under an owner the caller owns -- anything else would let the caller grant
// its own key login to another tenant's or user's account -- and the refusal
// is the not-found answer for the entry.
func (a *authorizedKeysClient) Add(ctx context.Context, req sdkssh.AddAuthorizedKeyRequest) error {
	p, err := a.c.serve(ctx, req.Scope, req.Owner)
	if err != nil {
		return err
	}
	if !p.allowed {
		_, miss := a.c.empty.AuthorizedKeys().Get(ctx, req.Scope, req.Owner, req.Name)
		return newOwnerBindingError(ctx, "authorizedKeys.add", req.Scope, req.Owner, miss)
	}
	return p.client.AuthorizedKeys().Add(ctx, req)
}

// Get implements sdkssh.AuthorizedKeysClient.
func (a *authorizedKeysClient) Get(ctx context.Context, scope, owner, name string) (*sdkssh.AuthorizedEntry, error) {
	p, err := a.c.serve(ctx, scope, owner)
	if err != nil {
		return nil, err
	}
	entry, err := p.client.AuthorizedKeys().Get(ctx, scope, owner, name)
	if err != nil {
		return nil, a.c.wrapRefusal(ctx, p, "authorizedKeys.get", scope, owner, err)
	}
	return entry, nil
}

// List implements sdkssh.AuthorizedKeysClient. The listing holds only
// entries the caller owns, whatever the filters name.
func (a *authorizedKeysClient) List(ctx context.Context, req sdkssh.ListAuthorizedKeysRequest) ([]*sdkssh.AuthorizedEntry, error) {
	p, who, err := a.c.listPartition(ctx, req.Scope, req.Owner)
	if err != nil {
		return nil, err
	}
	all, err := p.AuthorizedKeys().List(ctx, req)
	if err != nil {
		return nil, err
	}
	owned := make([]*sdkssh.AuthorizedEntry, 0, len(all))
	for _, entry := range all {
		if who.visible(entry.Scope, entry.Owner) {
			owned = append(owned, entry)
		}
	}
	return owned, nil
}

// Remove implements sdkssh.AuthorizedKeysClient.
func (a *authorizedKeysClient) Remove(ctx context.Context, scope, owner, name string) error {
	p, err := a.c.serve(ctx, scope, owner)
	if err != nil {
		return err
	}
	if err := p.client.AuthorizedKeys().Remove(ctx, scope, owner, name); err != nil {
		return a.c.wrapRefusal(ctx, p, "authorizedKeys.remove", scope, owner, err)
	}
	return nil
}

// Emit implements sdkssh.AuthorizedKeysClient. Emit formats the supplied
// line and addresses no stored asset, so it needs no binding and every
// partition answers it identically.
func (a *authorizedKeysClient) Emit(ctx context.Context, req sdkssh.EmitRequest) (string, error) {
	return a.c.empty.AuthorizedKeys().Emit(ctx, req)
}

// Verify implements sdkssh.AuthorizedKeysClient.
func (a *authorizedKeysClient) Verify(ctx context.Context, scope, owner string, received gossh.PublicKey) (*sdkssh.AuthorizedEntry, error) {
	p, err := a.c.serve(ctx, scope, owner)
	if err != nil {
		return nil, err
	}
	entry, err := p.client.AuthorizedKeys().Verify(ctx, scope, owner, received)
	if err != nil {
		return nil, a.c.wrapRefusal(ctx, p, "authorizedKeys.verify", scope, owner, err)
	}
	return entry, nil
}

// ------------------------------------------------------------------
// Sessions.
// ------------------------------------------------------------------

// sessionClient binds a session's authentication key and its host-key pins
// to the caller.
type sessionClient struct {
	c *client
}

// Dial implements sdkssh.SessionClient. The key and the pins must both be
// the caller's, and must live in one partition: a session never combines one
// tenant's key with another tenant's pins.
func (s *sessionClient) Dial(ctx context.Context, req sdkssh.SessionDialRequest) (sdkssh.Session, error) {
	key, err := s.c.serve(ctx, req.KeyScope, req.KeyOwner)
	if err != nil {
		return nil, err
	}
	hostScope, hostOwner := req.KeyScope, req.KeyOwner
	if req.HostKeyScope != "" {
		hostScope = req.HostKeyScope
	}
	if req.HostKeyOwner != "" {
		hostOwner = req.HostKeyOwner
	}
	pins, err := s.c.serve(ctx, hostScope, hostOwner)
	if err != nil {
		return nil, err
	}
	p := key
	if !pins.allowed || pins.tenantID != key.tenantID {
		p = partition{client: s.c.empty}
	}
	session, err := p.client.Session().Dial(ctx, req)
	if err != nil {
		return nil, s.c.wrapRefusal(ctx, p, "session.dial", req.KeyScope, req.KeyOwner, err)
	}
	return session, nil
}
