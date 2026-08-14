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

package quic

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// callerTenantID returns the tenant the authenticated caller belongs to, or
// the empty string when the request carries no identity. Every crypto handler
// forwards it to the service layer so a tenant-scoped key resolves against
// that tenant's backend, exactly as the REST transport does. Dropping it
// silently resolved every operation against the untenanted backend.
func callerTenantID(ctx context.Context) string {
	if identity := auth.GetIdentity(ctx); identity != nil {
		return identity.TenantID
	}
	return ""
}

// decodeSignature converts the loosely typed signature field carried on this
// transport's VerifyRequest into raw bytes.
//
// The field is an interface{} because clients have historically sent three
// encodings: a base64 string (what encoding/json produces for a []byte), a raw
// string, and a JSON array of byte values. Accepting all three keeps those
// clients working; anything else is rejected rather than silently decoded to
// an empty signature, which would report a valid signature as invalid.
func decodeSignature(signature interface{}) ([]byte, error) {
	switch sig := signature.(type) {
	case nil:
		return nil, &errs.Message{Msg: "signature is required"}
	case []byte:
		return sig, nil
	case string:
		if decoded, err := base64.StdEncoding.DecodeString(sig); err == nil {
			return decoded, nil
		}
		return []byte(sig), nil
	case []interface{}:
		out := make([]byte, len(sig))
		for i, v := range sig {
			b, ok := v.(float64)
			if !ok {
				return nil, &errs.Message{Msg: "signature array must contain only byte values"}
			}
			out[i] = byte(b)
		}
		return out, nil
	default:
		sigJSON, err := json.Marshal(signature)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "unsupported signature encoding", Err: err}
		}
		var out []byte
		if err := json.Unmarshal(sigJSON, &out); err != nil {
			return nil, &errs.Wrapped{Msg: "unsupported signature encoding", Err: err}
		}
		return out, nil
	}
}

// extractPublicKey extracts the public key from a private key
func extractPublicKey(privKey interface{}) (crypto.PublicKey, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	case crypto.Signer:
		return key.Public(), nil
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %T", privKey)}
	}
}

// parseHashAlgorithm resolves a caller-supplied hash algorithm name for this
// transport. It delegates to xkms.ResolveHash so every transport shares one
// hash vocabulary, one default, and one refusal.
//
// It used to carry its own table, which admitted SHA-1 and SHA-224 whatever the
// process-wide weak-hash policy said. A caller could therefore obtain a SHA-1
// signature here that REST and gRPC refuse, which is both a policy bypass and a
// cross-transport divergence in what "sign this" means.
func parseHashAlgorithm(hashStr string) (crypto.Hash, error) {
	return xkms.ResolveHash(hashStr)
}

// verifySignature verifies a signature using the public key
func verifySignature(pubKey crypto.PublicKey, digest, signature []byte, hash crypto.Hash) (bool, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(key, hash, digest, signature)
		return err == nil, nil

	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest, signature), nil

	case ed25519.PublicKey:
		return ed25519.Verify(key, digest, signature), nil

	default:
		return false, &errs.Message{Msg: fmt.Sprintf("unsupported public key type: %T", pubKey)}
	}
}
