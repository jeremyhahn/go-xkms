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

package sshlocal

import (
	"os"

	gossh "golang.org/x/crypto/ssh"

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Source labels for LocalKeyInfo.Source.
const (
	// SourceAgent marks a key currently held by the local ssh-agent.
	SourceAgent = "agent"

	// SourceFile marks a key discovered only as a private-key file under
	// ~/.ssh (not currently held by the agent).
	SourceFile = "file"
)

// LocalKeyInfo describes one key discovered from the local ssh-agent or
// ~/.ssh directory. It is read-only presentation data — xkey never imports
// or manages the private-key material these describe.
type LocalKeyInfo struct {
	// Source is SourceAgent or SourceFile. A key held by the agent is always
	// reported as SourceAgent even when a matching identity file also exists
	// on disk (see ListLocalKeys).
	Source string

	// Path is the private-key file path, when known (empty for an
	// agent-only key with no matching identity file on disk).
	Path string

	// KeyType is the OpenSSH public-key algorithm name (e.g. "ssh-ed25519").
	KeyType string

	// Fingerprint is the OpenSSH SHA256 fingerprint, or "" when the public
	// half could not be determined.
	Fingerprint string

	// Comment is the comment from the paired ".pub" file, when known.
	Comment string
}

// ListLocalKeys returns every key visible to the operator's local SSH
// tooling: keys currently held by the ssh-agent at $SSH_AUTH_SOCK, plus
// identity files discovered under ~/.ssh that are not already represented by
// an agent entry (matched by fingerprint). A key present in both is reported
// once, with Source == SourceAgent (its Path/Comment are filled in from the
// matching identity file when one is found).
//
// A missing/unreachable agent, a missing ssh_config, or a missing ~/.ssh
// directory are NOT errors — each simply contributes no entries from that
// source.
func ListLocalKeys() ([]LocalKeyInfo, error) {
	identities, err := discoverIdentities()
	if err != nil {
		return nil, err
	}

	identityByFingerprint := make(map[string]*sshclient.LocalIdentity, len(identities))
	for _, id := range identities {
		if id.Fingerprint != "" {
			identityByFingerprint[id.Fingerprint] = id
		}
	}

	// DialLocalAgent's error covers "no agent configured" and "agent
	// unreachable" alike — both mean zero agent-sourced entries, not a
	// failure of ListLocalKeys as a whole.
	agentSigners, _ := sshclient.DialLocalAgent(os.Getenv("SSH_AUTH_SOCK"))

	seen := make(map[string]bool, len(agentSigners))
	out := make([]LocalKeyInfo, 0, len(agentSigners)+len(identities))
	for _, signer := range agentSigners {
		pub := signer.PublicKey()
		fp := gossh.FingerprintSHA256(pub)
		seen[fp] = true
		entry := LocalKeyInfo{Source: SourceAgent, KeyType: pub.Type(), Fingerprint: fp}
		if id, ok := identityByFingerprint[fp]; ok {
			entry.Path = id.Path
			entry.Comment = id.Comment
		}
		out = append(out, entry)
	}

	for _, id := range identities {
		if id.Fingerprint != "" && seen[id.Fingerprint] {
			continue // already reported as an agent entry above
		}
		keyType := ""
		if id.PublicKey != nil {
			keyType = id.PublicKey.Type()
		}
		out = append(out, LocalKeyInfo{
			Source:      SourceFile,
			Path:        id.Path,
			KeyType:     keyType,
			Fingerprint: id.Fingerprint,
			Comment:     id.Comment,
		})
	}
	return out, nil
}

// discoverIdentities returns the candidate identity files under ~/.ssh (an
// unresolvable home directory yields an empty list, not an error).
func discoverIdentities() ([]*sshclient.LocalIdentity, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return nil, nil
	}

	cfg, err := sshclient.LoadLocalSSHConfig(sshclient.DefaultLocalSSHConfigPaths()...)
	if err != nil {
		return nil, &ConfigLoadError{Err: err}
	}

	host := cfg.Lookup("")
	identities, err := sshclient.DiscoverLocalIdentities(host, homeDir)
	if err != nil {
		return nil, &IdentityDiscoveryError{Err: err}
	}
	return identities, nil
}
