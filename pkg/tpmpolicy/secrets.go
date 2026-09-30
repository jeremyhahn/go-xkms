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

package tpmpolicy

import (
	"context"
	"crypto/rand"
	"encoding/json"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// secretSize is the size of every scope secret: a random 32-byte value.
const secretSize = 32

// secretsCNPrefix names the sealed object holding a scope's secrets.
const secretsCNPrefix = "tpm-scope-secrets-"

// scopeSecrets are the random auth values of a scope's TPM resources. They
// are never stored in the clear: the scope record holds them sealed by the
// physical TPM under the platform policy.
//
// They are sealed as their concatenation (authority, NV write, then the
// storage key's when present) rather than as JSON: a TPM sealed data object
// holds at most 128 bytes (MAX_SYM_DATA), and three encoded 32-byte values
// exceed it.
type scopeSecrets struct {
	// AuthorityAuth is the policy authority's auth value.
	AuthorityAuth []byte

	// NVWriteAuth authorizes writes to the scope's counter and policy
	// indices.
	NVWriteAuth []byte

	// StorageKeyAuth is the tenant storage key's auth value (shared mode
	// tenants only).
	StorageKeyAuth []byte
}

// encode returns the sealed form of secrets.
func (secrets *scopeSecrets) encode() []byte {
	out := make([]byte, 0, 3*secretSize)
	out = append(out, secrets.AuthorityAuth...)
	out = append(out, secrets.NVWriteAuth...)
	return append(out, secrets.StorageKeyAuth...)
}

// decodeScopeSecrets parses the sealed form of a scope's secrets.
func decodeScopeSecrets(plain []byte) (*scopeSecrets, error) {
	if len(plain) != 2*secretSize && len(plain) != 3*secretSize {
		return nil, ErrMalformedSecrets
	}
	secrets := &scopeSecrets{
		AuthorityAuth: plain[:secretSize],
		NVWriteAuth:   plain[secretSize : 2*secretSize],
	}
	if len(plain) == 3*secretSize {
		secrets.StorageKeyAuth = plain[2*secretSize:]
	}
	return secrets, nil
}

// randomSecret returns a fresh random secret with no zero byte. Excluding
// one value of 256 per byte leaves 255.8 bits of entropy.
//
// This works around a go-tpm v0.9.8 defect, deliberately kept rather than
// fixed upstream (owner ruling). An HMAC session's key is sessionKey ||
// authValue with trailing zero octets removed (TPM 2.0 Part 1, section
// 19.6.8), and go-tpm computes it in tpm2.hmacKeyFromAuthValue
// (tpm2/sessions.go). Its loop scans the auth value from the end for a
// non-zero octet but has no break, so it trims at ANY zero octet it passes --
// an interior one included -- instead of only the trailing run. The TPM
// trims only the trailing zeros, so for an auth value holding a zero octet
// the two HMAC keys differ and every command authorized with it fails with
// TPM_RC_BAD_AUTH. Generated auth values therefore contain no zero octet.
// Remove this restriction only once the go-tpm in go.mod trims correctly.
func randomSecret() ([]byte, error) {
	out := make([]byte, 0, secretSize)
	buf := make([]byte, secretSize)
	for len(out) < secretSize {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		for _, b := range buf {
			if b != 0 && len(out) < secretSize {
				out = append(out, b)
			}
		}
	}
	return out, nil
}

// newScopeSecrets returns fresh secrets for a scope; withStorageKey adds the
// auth value of a tenant storage key.
func newScopeSecrets(scope string, withStorageKey bool) (*scopeSecrets, error) {
	var secrets scopeSecrets
	targets := []*[]byte{&secrets.AuthorityAuth, &secrets.NVWriteAuth}
	if withStorageKey {
		targets = append(targets, &secrets.StorageKeyAuth)
	}
	for _, target := range targets {
		secret, err := randomSecret()
		if err != nil {
			return nil, &SecretsError{Scope: scope, Op: "generate", Err: err}
		}
		*target = secret
	}
	return &secrets, nil
}

// secretsKeyAttrs returns the attributes of the sealed object that holds
// scope's secrets: a child of the Platform SRK bound to the platform policy.
func (s *Service) secretsKeyAttrs(scope string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            secretsCNPrefix + scope,
		KeyType:       types.KeyTypeHMAC,
		Parent:        s.platformSRK,
		StoreType:     types.StoreTPM2,
		TPMPolicy:     types.TPMPolicyPlatform,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
}

// sealSecrets seals secrets with the physical TPM and returns the encoded
// sealed data the scope record keeps.
func (s *Service) sealSecrets(ctx context.Context, scope string, secrets *scopeSecrets) ([]byte, error) {
	sealed, err := s.sealer.Seal(ctx, secrets.encode(), &types.SealOptions{KeyAttributes: s.secretsKeyAttrs(scope)})
	if err != nil {
		return nil, &SecretsError{Scope: scope, Op: "seal", Err: err}
	}
	encoded, err := json.Marshal(sealed)
	if err != nil {
		return nil, &SecretsError{Scope: scope, Op: "encode", Err: err}
	}
	return encoded, nil
}

// unsealSecrets recovers a scope's secrets from the sealed data its record
// keeps.
func (s *Service) unsealSecrets(ctx context.Context, scope string, encoded []byte) (*scopeSecrets, error) {
	var sealed types.SealedData
	if err := json.Unmarshal(encoded, &sealed); err != nil {
		return nil, &SecretsError{Scope: scope, Op: "decode", Err: err}
	}
	plain, err := s.sealer.Unseal(ctx, &sealed, &types.UnsealOptions{KeyAttributes: s.secretsKeyAttrs(scope)})
	if err != nil {
		return nil, &SecretsError{Scope: scope, Op: "unseal", Err: err}
	}
	secrets, err := decodeScopeSecrets(plain)
	if err != nil {
		return nil, &SecretsError{Scope: scope, Op: "decode", Err: err}
	}
	return secrets, nil
}

// deleteSealedSecrets removes the sealed-object blobs the sealer stored for
// scope's secrets. The scope record's copy is what unsealing uses, so this
// only tidies the key store.
func (s *Service) deleteSealedSecrets(scope string) error {
	if err := s.keys.Delete(s.secretsKeyAttrs(scope)); err != nil {
		return &SecretsError{Scope: scope, Op: "delete", Err: err}
	}
	return nil
}

// password wraps an auth value as a types.Password.
func password(scope string, auth []byte) (types.Password, error) {
	pw, err := types.NewPassword(auth)
	if err != nil {
		return nil, &SecretsError{Scope: scope, Op: "password", Err: err}
	}
	return pw, nil
}
