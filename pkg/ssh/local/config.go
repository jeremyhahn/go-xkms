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
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
)

// defaultPort is substituted whenever no ssh_config file, at any priority
// level, supplies a Port for the alias.
const defaultPort = 22

// HostConfig is the resolved, ssh_config(5)-aware view of a single Host
// alias: every field already reflects file-priority resolution, token
// expansion, and "~" expansion — callers never need to re-consult the raw
// config.
type HostConfig struct {
	// Alias is the Host pattern used for the lookup that produced this
	// HostConfig (the exact string the caller passed to Lookup).
	Alias string

	// HostName is the resolved target host. Defaults to Alias when no
	// HostName directive matches.
	HostName string

	// User is the resolved remote user. Empty when no User directive
	// matches.
	User string

	// Port is the resolved TCP port. Defaults to 22 when no (valid) Port
	// directive matches at any priority level.
	Port int

	// IdentityFiles is the resolved, ordered, token-expanded list of
	// IdentityFile paths. It is cumulative across every loaded config file
	// (user file entries first, per ssh_config(5)), not first-match-wins.
	IdentityFiles []string

	// IdentityAgent is the resolved IdentityAgent value: "", "none",
	// "SSH_AUTH_SOCK", or an explicit (token-expanded) socket path.
	IdentityAgent string
}

// Config is an ordered, in-memory view of one or more parsed ssh_config(5)
// files. Files are consulted in the order LoadConfig received them — the
// first file with a matching, non-empty value for a given key wins for
// single-valued directives (HostName, User, Port, IdentityAgent);
// IdentityFile is cumulative across every file instead.
type Config struct {
	files   []*ssh_config.Config
	homeDir string
}

// LoadConfig parses each path in order and returns a *Config that resolves
// lookups against them with paths[0] at the highest priority — callers
// should pass the user's config before the system config, matching
// ssh_config(5)'s own precedence rules.
//
// A path that does not exist is not an error (an absent config file is
// equivalent to an empty one, exactly as OpenSSH treats it) — it is simply
// skipped. A path that exists but cannot be opened or parsed returns a
// *ConfigParseError identifying the offending path.
func LoadConfig(paths ...string) (*Config, error) {
	cfg := &Config{}
	if home, err := os.UserHomeDir(); err == nil {
		cfg.homeDir = home
	}

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, &ConfigParseError{Path: path, Err: err}
		}

		parsed, decodeErr := ssh_config.Decode(f)
		closeErr := f.Close()
		if decodeErr != nil {
			return nil, &ConfigParseError{Path: path, Err: decodeErr}
		}
		if closeErr != nil {
			return nil, &ConfigParseError{Path: path, Err: closeErr}
		}

		cfg.files = append(cfg.files, parsed)
	}

	return cfg, nil
}

// DefaultConfigPaths returns the two ssh_config(5) locations OpenSSH
// consults by default, in priority order: the per-user config followed by
// the system-wide config. Callers pass this directly to LoadConfig for the
// common case; tests and callers with a custom layout construct their own
// path list instead.
func DefaultConfigPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return []string{
		filepath.Join(home, ".ssh", "config"),
		"/etc/ssh/ssh_config",
	}
}

// Lookup resolves alias against every loaded file and returns a fully
// populated HostConfig. Lookup never fails: an alias that matches nothing
// in any file yields a HostConfig equal to
// &HostConfig{Alias: alias, HostName: alias, Port: 22} — the same
// defaults ssh(1) itself would apply.
func (c *Config) Lookup(alias string) *HostConfig {
	hc := &HostConfig{Alias: alias, HostName: alias, Port: defaultPort}

	if hostName := c.getFirst(alias, "HostName"); hostName != "" {
		hc.HostName = hostName
	}
	hc.User = c.getFirst(alias, "User")

	if portStr := c.getFirst(alias, "Port"); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
			hc.Port = port
		}
		// An unparsable or non-positive Port value is treated as unset
		// rather than failing the whole lookup.
	}

	hc.IdentityAgent = c.getFirst(alias, "IdentityAgent")

	hc.IdentityFiles = c.getAllCumulative(alias, "IdentityFile")
	for i, f := range hc.IdentityFiles {
		hc.IdentityFiles[i] = expandTokens(f, c.homeDir, hc.HostName, hc.User, hc.Port)
	}

	// "none" is a sentinel ssh(1) recognizes to disable agent forwarding
	// for the host — preserve it verbatim rather than token-expanding it.
	if hc.IdentityAgent != "" && hc.IdentityAgent != "none" {
		hc.IdentityAgent = expandTokens(hc.IdentityAgent, c.homeDir, hc.HostName, hc.User, hc.Port)
	}

	return hc
}

// LookupStrict behaves like Lookup but returns a *HostNotConfiguredError
// instead of a synthesized default HostConfig when alias does not match
// any literal Host pattern in the loaded configuration. It exists for
// callers (e.g. a host picker in the xkey GUI) that need to distinguish an
// operator-configured host from an arbitrary hostname typed by the user.
func (c *Config) LookupStrict(alias string) (*HostConfig, error) {
	configured := false
	for _, a := range c.Aliases() {
		if a == alias {
			configured = true
			break
		}
	}
	if !configured {
		return nil, &HostNotConfiguredError{Alias: alias}
	}
	return c.Lookup(alias), nil
}

// Aliases returns every literal (non-wildcard) Host pattern known across
// all loaded files, in file-then-declaration order, deduplicated. Patterns
// containing ssh_config(5) wildcards ('*' or '?'), negated patterns
// ("!pattern"), and Match blocks are excluded — Match blocks are modeled
// by the underlying parser as Host-shaped blocks, so they are detected by
// inspecting the block's own rendering (which begins with the literal
// text "Match" for a Match block, never for a Host block) rather than by
// pattern shape.
func (c *Config) Aliases() []string {
	seen := make(map[string]bool)
	var aliases []string

	for _, f := range c.files {
		for _, host := range f.Hosts {
			if isMatchBlock(host) {
				continue
			}
			for _, pat := range host.Patterns {
				name := pat.String()
				if name == "" || strings.HasPrefix(name, "!") {
					continue
				}
				if strings.ContainsAny(name, "*?") {
					continue
				}
				if seen[name] {
					continue
				}
				seen[name] = true
				aliases = append(aliases, name)
			}
		}
	}

	return aliases
}

// getFirst returns the first non-empty value for key across the loaded
// files, walking them in priority order. Returns "" if no file has a
// matching, non-empty value.
func (c *Config) getFirst(alias, key string) string {
	for _, f := range c.files {
		v, err := f.Get(alias, key)
		if err != nil {
			continue
		}
		if v != "" {
			return v
		}
	}
	return ""
}

// getAllCumulative concatenates every value for key across the loaded
// files, in priority order — used for IdentityFile, which ssh_config(5)
// treats as cumulative rather than first-match-wins.
func (c *Config) getAllCumulative(alias, key string) []string {
	var all []string
	for _, f := range c.files {
		vals, err := f.GetAll(alias, key)
		if err != nil {
			continue
		}
		all = append(all, vals...)
	}
	return all
}

// isMatchBlock reports whether host was produced by a "Match" directive
// rather than a "Host" directive. The underlying parser does not export
// this distinction directly, but a Match block's own String() rendering
// always begins with the literal text "Match" (a Host block's begins with
// "Host", and the implicit leading "Host *" block renders no header line
// at all) — so the rendering itself is a reliable, if indirect, signal.
func isMatchBlock(host *ssh_config.Host) bool {
	return strings.HasPrefix(strings.TrimSpace(host.String()), "Match")
}
