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
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
)

// DefaultIdentityFiles are the conventional private-key file names ssh(1)
// tries, in order, for a host with no explicit IdentityFile directive.
// Names only — DiscoverIdentities joins each against homeDir/.ssh.
var DefaultIdentityFiles = []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"}

// Identity describes one candidate private key discovered on disk for a
// host. Only the public half is ever read into memory by this package —
// PublicKey, Comment, and Fingerprint come from opportunistically parsing
// the paired ".pub" file, never from the private key itself.
type Identity struct {
	// Path is the private key file's path (not necessarily existing as a
	// parseable key — DiscoverIdentities only returns paths that exist,
	// but does not attempt to parse the private key).
	Path string

	// PublicKey is the parsed public half, read from Path+".pub". nil
	// when the .pub file is missing or unparsable.
	PublicKey ssh.PublicKey

	// Comment is the comment from the paired .pub file, if any.
	Comment string

	// Fingerprint is the OpenSSH SHA256 fingerprint of PublicKey, or "" if
	// PublicKey is nil.
	Fingerprint string
}

// DiscoverIdentities returns the candidate identities for host: host's own
// IdentityFiles first (already resolved by Lookup), followed by
// DefaultIdentityFiles under homeDir/.ssh — in that order, deduplicated by
// absolute path. Only candidates whose private-key file exists on disk are
// returned; a missing candidate is silently skipped (that is the normal
// case for most of DefaultIdentityFiles).
//
// A candidate's paired ".pub" file is read and parsed opportunistically:
// failure to read or parse it is NOT an error — it simply leaves
// PublicKey, Comment, and Fingerprint at their zero values, since an
// operator's private key without a ".pub" alongside it is still a usable
// identity (ssh(1) itself will derive the public half at connect time).
// DiscoverIdentities only returns an error for an unexpected failure
// (e.g. an I/O error stating a candidate path that is not "not exists").
func DiscoverIdentities(host *HostConfig, homeDir string) ([]*Identity, error) {
	var candidates []string
	if host != nil {
		candidates = append(candidates, host.IdentityFiles...)
	}
	for _, name := range DefaultIdentityFiles {
		candidates = append(candidates, filepath.Join(homeDir, ".ssh", name))
	}

	seen := make(map[string]bool)
	var identities []*Identity

	for _, path := range candidates {
		key := path
		if abs, err := filepath.Abs(path); err == nil {
			key = abs
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, &IdentityReadError{Path: path, Err: err}
		}
		if info.IsDir() {
			continue
		}

		identities = append(identities, buildIdentity(path))
	}

	return identities, nil
}

// IdentityFromPath constructs an Identity for a private-key path,
// opportunistically parsing the paired .pub file (see buildIdentity). The
// path is not required to exist — resolution reports a read error later if
// it does not.
func IdentityFromPath(path string) *Identity {
	return buildIdentity(path)
}

// buildIdentity constructs an Identity for an existing private-key path,
// opportunistically parsing the paired .pub file. Any failure to read or
// parse the .pub leaves PublicKey/Comment/Fingerprint at zero values.
func buildIdentity(path string) *Identity {
	id := &Identity{Path: path}

	pubBytes, err := os.ReadFile(path + ".pub")
	if err != nil {
		return id
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return id
	}

	id.PublicKey = pub
	id.Comment = comment
	id.Fingerprint = keys.Fingerprint(pub)
	return id
}
