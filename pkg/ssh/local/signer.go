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

package local

import (
	"context"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ResolveSigner produces an ssh.Signer for identity, preferring the
// system ssh-agent and falling back to the identity's own private-key
// file:
//
//  1. If authSockPath is non-empty and identity.PublicKey is known (i.e.
//     a paired .pub was parsed by DiscoverIdentities), ResolveSigner
//     asks the agent for a matching signer first. This path is REQUIRED
//     for hardware-backed identities (ssh(1)'s "sk-" key types) whose
//     private half never leaves the security key — there is no PEM file
//     to fall back to for those.
//  2. Otherwise (no agent, no known public key, or the agent doesn't have
//     it), ResolveSigner reads identity.Path into a secure.Buffer and
//     parses it via keys.ParsePEM. An encrypted key with no passphrase
//     provider surfaces keys.ParsePEM's *keys.PassphraseRequiredError
//     UNCHANGED — callers distinguish it with errors.As and re-invoke
//     with a passphrase-aware flow of their own choosing; ResolveSigner
//     itself never prompts.
//
// Memory discipline: the raw file bytes and the intermediate
// *secure.Buffer are destroyed before returning (via defer) — the
// buffer's contents are copied into the *keys.Key's own sealed
// secure.Secret by keys.ParsePEM before that defer runs. The *keys.Key
// itself is deliberately NOT destroyed here: the ssh.Signer this function
// returns is a keys.Key.Signer(), which re-opens the Key's sealed Secret
// on every Sign call (see (*keys.Key).Signer's doc comment) — destroying
// the Key immediately would make every subsequent Sign call on the
// returned signer fail. Because ResolveSigner's signature has no room for
// a closer, the sealed Secret is intentionally left alive for the
// process's lifetime and reclaimed by secure.Purge() / CatchInterrupt at
// shutdown, the same lifetime tradeoff DialAgent documents for its own
// connection.
//
// Returns *NilInputError if identity is nil, *IdentityReadError if the
// private-key file cannot be read, or the error keys.ParsePEM produced
// (typically *keys.PassphraseRequiredError or *keys.PEMParseError).
func ResolveSigner(ctx context.Context, identity *Identity, authSockPath string) (ssh.Signer, error) {
	if identity == nil {
		return nil, &NilInputError{Field: "identity"}
	}

	if authSockPath != "" && identity.PublicKey != nil {
		if signer, err := SignerForPublicKey(authSockPath, identity.PublicKey); err == nil {
			return signer, nil
		}
		// Agent didn't have it (or wasn't reachable) — fall back to the
		// private-key file below.
	}

	raw, err := os.ReadFile(identity.Path)
	if err != nil {
		return nil, &IdentityReadError{Path: identity.Path, Err: err}
	}

	buf, err := secure.NewBufferFromBytes(raw)
	if err != nil {
		return nil, &IdentityReadError{Path: identity.Path, Err: err}
	}
	defer buf.Destroy()

	key, err := keys.ParsePEM(ctx, buf, nil)
	if err != nil {
		return nil, err
	}

	return key.Signer()
}
