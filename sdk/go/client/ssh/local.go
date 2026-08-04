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
	"errors"
	"fmt"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkglocal "github.com/jeremyhahn/go-xkms/pkg/ssh/local"
)

// LocalSSHConfig is the parsed, read-only view of the machine's OpenSSH
// client configuration (~/.ssh/config plus /etc/ssh/ssh_config).
type LocalSSHConfig = pkglocal.Config

// LocalHostConfig is the resolved per-host configuration for one ssh_config
// Host alias (HostName, User, Port, IdentityFiles, IdentityAgent).
type LocalHostConfig = pkglocal.HostConfig

// LocalIdentity describes one local identity file discovered under ~/.ssh
// (or named by an ssh_config IdentityFile directive), with its public half
// parsed opportunistically from the paired ".pub" file.
type LocalIdentity = pkglocal.Identity

// PassphraseRequiredError is returned when a local identity file is
// encrypted and no agent can sign for it; the caller must supply a
// passphrase or load the key into the system agent.
type PassphraseRequiredError = pkgkeys.PassphraseRequiredError

// LocalConfigParseError reports a present-but-unparseable ssh_config file.
type LocalConfigParseError = pkglocal.ConfigParseError

// LocalAgentUnavailableError reports that no system SSH agent could be
// reached at the given socket path.
type LocalAgentUnavailableError = pkglocal.AgentUnavailableError

// LocalAgentKeyNotFoundError reports that the system agent is running but
// does not hold the requested identity (for sk- keys this usually means the
// security key is not present).
type LocalAgentKeyNotFoundError = pkglocal.AgentKeyNotFoundError

// LocalIdentityReadError reports a failure reading a local identity file.
type LocalIdentityReadError = pkglocal.IdentityReadError

// LocalHostNotConfiguredError reports that an alias has no Host block in
// any parsed ssh_config file.
type LocalHostNotConfiguredError = pkglocal.HostNotConfiguredError

// DefaultLocalIdentityFiles is OpenSSH's built-in default identity list,
// consulted when ssh_config sets no IdentityFile for a host.
var DefaultLocalIdentityFiles = pkglocal.DefaultIdentityFiles

// LoadLocalSSHConfig parses the given ssh_config-format files in priority
// order. Missing files are skipped (an absent config is an empty config);
// malformed files return *LocalConfigParseError.
func LoadLocalSSHConfig(paths ...string) (*LocalSSHConfig, error) {
	return pkglocal.LoadConfig(paths...)
}

// DefaultLocalSSHConfigPaths returns the standard OpenSSH client config
// paths in priority order: ~/.ssh/config, then /etc/ssh/ssh_config.
func DefaultLocalSSHConfigPaths() []string {
	return pkglocal.DefaultConfigPaths()
}

// DiscoverLocalIdentities returns every candidate identity file that exists
// on disk for host: ssh_config IdentityFile entries first, then the
// DefaultLocalIdentityFiles under homeDir/.ssh, deduplicated by absolute
// path.
func DiscoverLocalIdentities(host *LocalHostConfig, homeDir string) ([]*LocalIdentity, error) {
	return pkglocal.DiscoverIdentities(host, homeDir)
}

// ResolveLocalSigner returns a signing gossh.Signer for identity, preferring
// the system agent at authSockPath (required for hardware-backed sk- keys)
// and falling back to parsing the identity file directly when it is not
// encrypted. Encrypted files with no agent match return
// *PassphraseRequiredError.
func ResolveLocalSigner(ctx context.Context, identity *LocalIdentity, authSockPath string) (gossh.Signer, error) {
	return pkglocal.ResolveSigner(ctx, identity, authSockPath)
}

// DialLocalAgent connects to the system SSH agent at sockPath (typically
// $SSH_AUTH_SOCK) and returns its advertised signers.
func DialLocalAgent(sockPath string) ([]gossh.Signer, error) {
	return pkglocal.DialAgent(sockPath)
}

// LocalIdentityFromPath constructs a LocalIdentity for a private-key path,
// opportunistically parsing the paired ".pub" file for the public half.
func LocalIdentityFromPath(path string) *LocalIdentity {
	return pkglocal.IdentityFromPath(path)
}

// LocalAgentSignerForFingerprint returns the system-agent signer whose public
// key has the given OpenSSH SHA256 fingerprint (`ssh-add -l` form). It
// resolves agent-held keys referenced by fingerprint alone — keys with no
// on-disk identity file.
func LocalAgentSignerForFingerprint(sockPath, fingerprint string) (gossh.Signer, error) {
	return pkglocal.SignerForFingerprint(sockPath, fingerprint)
}

// LocalIdentityAgentPrefix marks a local-identity reference that names a
// system ssh-agent key by fingerprint ("agent:<SHA256-fp>") instead of an
// identity file path.
const LocalIdentityAgentPrefix = "agent:"

// LocalIdentityAttemptError wraps a single local-identity resolution failure
// with the offending file path, so a *PassphraseRequiredError (or any other
// resolution error) surfaces which identity produced it even after being
// joined with other identities' failures (see NoUsableLocalIdentityError).
type LocalIdentityAttemptError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *LocalIdentityAttemptError) Error() string {
	return e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *LocalIdentityAttemptError) Unwrap() error { return e.Err }

// NoUsableLocalIdentityError indicates no candidate local key resolved to a
// working signer. Err joins one *LocalIdentityAttemptError per attempted
// identity (via errors.Join), so errors.As can still find a specific failure
// (e.g. a *PassphraseRequiredError) among them.
type NoUsableLocalIdentityError struct {
	// Alias labels the connection the resolution was for: the ssh_config
	// alias or the target host.
	Alias string
	Err   error
}

// Error implements the error interface.
func (e *NoUsableLocalIdentityError) Error() string {
	return fmt.Sprintf("ssh: no usable local identity for host %q: %v", e.Alias, e.Err)
}

// Unwrap returns the joined per-identity errors.
func (e *NoUsableLocalIdentityError) Unwrap() error { return e.Err }

// LocalKeySelector chooses which of the operator's local keys authenticate a
// connection (see ResolveLocalSigners).
type LocalKeySelector struct {
	// Identity pins one specific key: "agent:<SHA256-fingerprint>" for a
	// key held by the system agent, or an identity file path. When set,
	// Alias/Host are not consulted.
	Identity string

	// Alias names an ssh_config(5) Host block whose IdentityFile entries
	// (plus the OpenSSH defaults) become the candidate list. Used when
	// Identity is empty.
	Alias string

	// Host is the connection target, matched against ssh_config Host
	// patterns when Alias is empty.
	Host string
}

// ResolveLocalSigners resolves the ordered signer candidates for a
// connection authenticated with the operator's own local keys, the way the
// OpenSSH client would: a pinned Identity resolves to exactly that key;
// otherwise every key the system agent (authSock, typically $SSH_AUTH_SOCK)
// holds is offered first, followed by each discovered identity file,
// deduplicated by fingerprint. An unreachable agent contributes no signers
// (not an error). If nothing is usable it returns
// *NoUsableLocalIdentityError.
func ResolveLocalSigners(ctx context.Context, sel LocalKeySelector, authSock string) ([]gossh.Signer, error) {
	if strings.HasPrefix(sel.Identity, LocalIdentityAgentPrefix) {
		signer, err := LocalAgentSignerForFingerprint(authSock, strings.TrimPrefix(sel.Identity, LocalIdentityAgentPrefix))
		if err != nil {
			return nil, err
		}
		return []gossh.Signer{signer}, nil
	}

	label := sel.Alias
	if label == "" {
		label = sel.Host
	}

	var identities []*LocalIdentity
	includeAgent := true
	if sel.Identity != "" {
		identities = []*LocalIdentity{LocalIdentityFromPath(sel.Identity)}
		includeAgent = false
		label = sel.Identity
	} else {
		cfg, err := LoadLocalSSHConfig(DefaultLocalSSHConfigPaths()...)
		if err != nil {
			return nil, err
		}
		lookup := sel.Alias
		if lookup == "" {
			lookup = sel.Host
		}
		hc := cfg.Lookup(lookup)
		homeDir, _ := os.UserHomeDir()
		identities, err = DiscoverLocalIdentities(hc, homeDir)
		if err != nil {
			return nil, err
		}
	}

	var signers []gossh.Signer
	seen := make(map[string]bool)
	if includeAgent {
		if agentSigners, err := DialLocalAgent(authSock); err == nil {
			for _, as := range agentSigners {
				signers = append(signers, as)
				seen[gossh.FingerprintSHA256(as.PublicKey())] = true
			}
		}
	}

	var attempts []error
	for _, id := range identities {
		if id.Fingerprint != "" && seen[id.Fingerprint] {
			continue // already offered via the agent
		}
		signer, err := ResolveLocalSigner(ctx, id, authSock)
		if err != nil {
			attempts = append(attempts, &LocalIdentityAttemptError{Path: id.Path, Err: err})
			continue
		}
		signers = append(signers, signer)
		if id.Fingerprint != "" {
			seen[id.Fingerprint] = true
		}
	}

	if len(signers) == 0 {
		return nil, &NoUsableLocalIdentityError{Alias: label, Err: errors.Join(attempts...)}
	}
	return signers, nil
}
