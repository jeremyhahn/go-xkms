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

package cmd

// The CLI's OIDC RP token store (go-xkms#4, gap 1): the access, refresh, and
// ID tokens "xkey oidc login" and its auto-refresh loop obtain from an
// external OIDC provider and persist between invocations. It moves behind
// the same barrier-first, warn-and-proceed decision `xkey oath` and `xkey
// fido2` already make (resolveSecretStoreBackend, barrier_store.go) instead
// of inventing a second one, and it holds the token strings in mlocked
// protected memory (sdk/go/secure) while resident in the process, the same
// way xkey/pkg/oath's Credential holds its shared secret.
//
// There is no migration from the pre-#4 ad hoc ~/.xkey/tokens.json format:
// a file in that shape is simply not read by this store, and the operator
// runs `xkey oidc login` again.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ErrOIDCProtectedMemory reports that the mlocked allocation for a token
// field failed. The token is never kept as a plain Go string as a fallback.
var ErrOIDCProtectedMemory = errors.New("oidc: protected memory allocation failed")

// OIDCStoredToken represents an OIDC RP session persisted by "xkey oidc
// login" and its subsidiary commands. AccessToken, RefreshToken, and IDToken
// live in mlocked, guard-paged protected memory rather than as ordinary Go
// string fields -- reached through the accessor and setter methods below,
// never as struct fields -- mirroring how xkey/pkg/oath's Credential holds
// its shared secret. The zero value has no secrets set and is safe to
// Destroy. Callers that obtain one (newOIDCStoredToken, oidcCLITokenStore.
// Load) must call Destroy when done with it so its buffers are wiped
// promptly rather than only at process exit.
type OIDCStoredToken struct {
	// Provider is the display name for the token's issuer. Every path in
	// this package sets it to the same value as Issuer.
	Provider string
	// Issuer is the OIDC provider's issuer URL (the JWT iss claim).
	Issuer string
	// ClientID is the OAuth2 client ID the token was issued to.
	ClientID string
	// ExpiresAt is the access token's calculated expiry time.
	ExpiresAt time.Time
	// Scopes lists the OAuth2 scopes granted to the token.
	Scopes []string

	accessToken  *secure.Buffer
	refreshToken *secure.Buffer
	idToken      *secure.Buffer
}

// newOIDCStoredToken builds an OIDCStoredToken from a freshly exchanged or
// refreshed OIDCTokenResponse, moving its AccessToken/RefreshToken/IDToken
// into protected memory. The response keeps its own copies, which its owner
// wipes with OIDCTokenResponse.Wipe. The caller owns the result and must call
// Destroy on it when done, on every path.
func newOIDCStoredToken(provider, issuer, clientID string, tokens *OIDCTokenResponse, expiresAt time.Time, scopes []string) (*OIDCStoredToken, error) {
	t := &OIDCStoredToken{
		Provider:  provider,
		Issuer:    issuer,
		ClientID:  clientID,
		ExpiresAt: expiresAt,
		Scopes:    scopes,
	}
	if err := t.SetAccessToken(tokens.AccessToken); err != nil {
		return nil, err
	}
	if err := t.SetRefreshToken(tokens.RefreshToken); err != nil {
		t.Destroy()
		return nil, err
	}
	if err := t.SetIDToken(tokens.IDToken); err != nil {
		t.Destroy()
		return nil, err
	}
	return t, nil
}

// SetAccessToken copies b into protected memory as the access token,
// destroying any previous value first. An empty b clears the field. b stays
// the caller's, who wipes it.
func (t *OIDCStoredToken) SetAccessToken(b []byte) error {
	return setOIDCProtectedField(&t.accessToken, b)
}

// AccessToken returns a caller-owned copy of the access token, or nil when
// none is set. The caller must wipe the copy as soon as it has been used
// (secure.Wipe), and must not hold it across time.
func (t *OIDCStoredToken) AccessToken() []byte {
	return oidcProtectedFieldCopy(t.accessToken)
}

// SetRefreshToken copies b into protected memory as the refresh token,
// destroying any previous value first. An empty b clears the field. b stays
// the caller's, who wipes it.
func (t *OIDCStoredToken) SetRefreshToken(b []byte) error {
	return setOIDCProtectedField(&t.refreshToken, b)
}

// RefreshToken returns a caller-owned copy of the refresh token, or nil when
// none is set. See AccessToken for the wipe contract.
func (t *OIDCStoredToken) RefreshToken() []byte {
	return oidcProtectedFieldCopy(t.refreshToken)
}

// HasRefreshToken reports whether the token carries a refresh token.
func (t *OIDCStoredToken) HasRefreshToken() bool {
	return t != nil && t.refreshToken != nil
}

// SetIDToken copies b into protected memory as the ID token, destroying any
// previous value first. An empty b clears the field. b stays the caller's,
// who wipes it.
func (t *OIDCStoredToken) SetIDToken(b []byte) error {
	return setOIDCProtectedField(&t.idToken, b)
}

// IDToken returns a caller-owned copy of the ID token, or nil when none is
// set. See AccessToken for the wipe contract.
func (t *OIDCStoredToken) IDToken() []byte {
	return oidcProtectedFieldCopy(t.idToken)
}

// Destroy wipes and releases every protected buffer the token holds. Safe to
// call more than once, and on a nil receiver.
func (t *OIDCStoredToken) Destroy() {
	if t == nil {
		return
	}
	t.accessToken.Destroy()
	t.refreshToken.Destroy()
	t.idToken.Destroy()
}

// setOIDCProtectedField copies b into protected memory at *dst, destroying
// whatever *dst held before. b stays the caller's: NewBufferFromBytes
// consumes the clone made here, not b.
func setOIDCProtectedField(dst **secure.Buffer, b []byte) error {
	if len(b) == 0 {
		(*dst).Destroy()
		*dst = nil
		return nil
	}
	buf, err := secure.NewBufferFromBytes(bytes.Clone(b))
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCProtectedMemory, Cause: err}
	}
	(*dst).Destroy()
	*dst = buf
	return nil
}

// oidcProtectedFieldCopy returns a caller-owned copy of buf's contents, or
// nil for a nil buf. The caller wipes it.
func oidcProtectedFieldCopy(buf *secure.Buffer) []byte {
	if buf == nil {
		return nil
	}
	out, err := secure.CopyOut(buf)
	if err != nil {
		// CopyOut only fails when buf is already destroyed, so this means a
		// caller used the token after Destroy: a lifecycle bug worth
		// surfacing even though this function has no error to return it
		// through.
		slog.Warn("oidc: read from a destroyed protected buffer", "error", err)
		return nil
	}
	return out
}

// oidcStoredTokenJSON is the at-rest wire form of OIDCStoredToken: the
// persistence boundary where the protected fields necessarily materialize
// immediately before Put/Get on a xkms.StorageBackend (barrier-encrypted, or,
// with no barrier, the plain file resolveSecretStoreBackend falls back to).
// The tokens are SecretBytes so they never become Go strings and encode as
// the same JSON strings the fields held before.
type oidcStoredTokenJSON struct {
	Provider     string           `json:"provider"`
	Issuer       string           `json:"issuer"`
	ClientID     string           `json:"client_id"`
	AccessToken  xkms.SecretBytes `json:"access_token"`
	RefreshToken xkms.SecretBytes `json:"refresh_token,omitempty"`
	IDToken      xkms.SecretBytes `json:"id_token,omitempty"`
	ExpiresAt    time.Time        `json:"expires_at"`
	Scopes       []string         `json:"scopes,omitempty"`
}

// wipe zeroes every token the wire form carries.
func (j *oidcStoredTokenJSON) wipe() {
	j.AccessToken.Wipe()
	j.RefreshToken.Wipe()
	j.IDToken.Wipe()
}

// MarshalJSON implements json.Marshaler, materializing the protected fields
// at this serialization boundary.
func (t *OIDCStoredToken) MarshalJSON() ([]byte, error) {
	accessToken := t.AccessToken()
	defer secure.Wipe(accessToken)
	refreshToken := t.RefreshToken()
	defer secure.Wipe(refreshToken)
	idToken := t.IDToken()
	defer secure.Wipe(idToken)
	return json.Marshal(oidcStoredTokenJSON{
		Provider:     t.Provider,
		Issuer:       t.Issuer,
		ClientID:     t.ClientID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ExpiresAt:    t.ExpiresAt,
		Scopes:       t.Scopes,
	})
}

// UnmarshalJSON implements json.Unmarshaler, adopting the access/refresh/ID
// token strings into protected memory.
func (t *OIDCStoredToken) UnmarshalJSON(data []byte) error {
	var aux oidcStoredTokenJSON
	defer aux.wipe()
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	t.Provider = aux.Provider
	t.Issuer = aux.Issuer
	t.ClientID = aux.ClientID
	t.ExpiresAt = aux.ExpiresAt
	t.Scopes = aux.Scopes
	if err := t.SetAccessToken(aux.AccessToken); err != nil {
		return err
	}
	if err := t.SetRefreshToken(aux.RefreshToken); err != nil {
		return err
	}
	return t.SetIDToken(aux.IDToken)
}

// oidcCLITokenStoreKey is the storage key holding the CLI's single active
// OIDC session, prefixed distinctly from every other store sharing the same
// barrier-backed namespace (xkey oath uses "oath/"; see barrier_store.go).
const oidcCLITokenStoreKey = "oidc/tokens.json"

// oidcCLITokenStore persists the CLI's single active OIDC session through a
// xkms.StorageBackend: barrier-encrypted when a barrier is initialized
// (openOIDCTokenStore), or the historical unencrypted file otherwise. It
// reduces to Put/Get/Delete on a xkms.StorageBackend, exactly like
// xkey/pkg/oath's BackendStore and FileStore -- there is one storage
// primitive in this CLI, not a second one invented for OIDC tokens.
type oidcCLITokenStore struct {
	backend xkms.StorageBackend
	key     string
}

// Save persists token, overwriting whatever was stored before.
func (s *oidcCLITokenStore) Save(token *OIDCStoredToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return s.backend.Put(context.Background(), s.key, data)
}

// Load retrieves the stored token. Returns ErrOIDCNoTokensFound both when
// nothing is stored and when what is stored does not parse as the current
// format: go-xkms#4 removes the pre-barrier plaintext format outright, with
// no migration, so a leftover file in that old shape is "nothing to read,"
// not a hard failure -- the operator logs in again.
func (s *oidcCLITokenStore) Load() (*OIDCStoredToken, error) {
	data, err := s.backend.Get(context.Background(), s.key)
	if err != nil {
		if errors.Is(err, xkms.ErrStorageNotFound) {
			return nil, ErrOIDCNoTokensFound
		}
		return nil, err
	}

	var token OIDCStoredToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, ErrOIDCNoTokensFound
	}
	if token.Issuer == "" {
		return nil, ErrOIDCNoTokensFound
	}
	return &token, nil
}

// Clear removes the stored token, if any. existed reports whether there was
// something to remove.
func (s *oidcCLITokenStore) Clear() (existed bool, err error) {
	if err := s.backend.Delete(context.Background(), s.key); err != nil {
		if errors.Is(err, xkms.ErrStorageNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// openOIDCTokenStore opens the CLI's OIDC token store: barrier-backed when a
// barrier is initialized in the xkey data directory
// (resolveSecretStoreBackend, barrier_store.go -- the same decision `xkey
// oath` and `xkey fido2` make), or a plain xkms.StorageBackend file
// otherwise, with the one standard "unencrypted at rest" warning
// resolveSecretStoreBackend already logs.
//
// An explicit --token-store value (cmd.Flags().Changed("token-store"))
// always resolves to a plain file at that exact path, matching how `xkey
// oath`'s --store override bypasses barrier auto-detection: the operator
// asked for a specific file, so the barrier decision does not apply.
func openOIDCTokenStore(cmd *cobra.Command, storeFlagPath string) (*oidcCLITokenStore, error) {
	if cmd.Flags().Changed("token-store") {
		path := expandPath(storeFlagPath)
		backend, err := xkms.NewFileStorageBackend(filepath.Dir(path))
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
		}
		return &oidcCLITokenStore{backend: backend, key: filepath.Base(path)}, nil
	}

	dataDir, err := resolveDataDir("")
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}

	backend, opened, err := resolveSecretStoreBackend(cmd, dataDir, "OIDC", slog.Default())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}
	if !opened {
		backend, err = xkms.NewFileStorageBackend(dataDir)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
		}
	}

	return &oidcCLITokenStore{backend: backend, key: oidcCLITokenStoreKey}, nil
}

// storeToken is a convenience wrapper around openOIDCTokenStore + Save.
func storeToken(cmd *cobra.Command, storePath string, token *OIDCStoredToken) error {
	store, err := openOIDCTokenStore(cmd, storePath)
	if err != nil {
		return err
	}
	return store.Save(token)
}

// loadToken is a convenience wrapper around openOIDCTokenStore + Load.
func loadToken(cmd *cobra.Command, storePath string) (*OIDCStoredToken, error) {
	store, err := openOIDCTokenStore(cmd, storePath)
	if err != nil {
		return nil, err
	}
	return store.Load()
}
