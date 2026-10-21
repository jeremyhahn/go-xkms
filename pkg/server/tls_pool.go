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

package server

import (
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// loadClientCAsUnion builds the union of CA PEM files referenced by
// every supplied path slice into a single x509.CertPool. Paths are
// deduplicated by their canonical (absolute, symlink-evaluated)
// filename so the same CA referenced across slices is loaded only
// once. When every input slice is empty the function returns a nil
// pool with no error so callers can distinguish "no client trust" from
// a hard failure. Each PEM file must contain at least one CERTIFICATE
// block; missing files and malformed PEM data return *ErrFileRead /
// *ErrCertParse respectively.
func loadClientCAsUnion(pathSlices ...[]string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	seen := make(map[string]struct{})
	added := false

	for _, paths := range pathSlices {
		for _, raw := range paths {
			if raw == "" {
				continue
			}
			canonical, err := canonicalizeCAPath(raw)
			if err != nil {
				return nil, &ErrFileRead{Path: raw, Err: err}
			}
			if _, dup := seen[canonical]; dup {
				continue
			}
			seen[canonical] = struct{}{}

			// #nosec G304 - CA path comes from validated configuration.
			data, err := os.ReadFile(canonical)
			if err != nil {
				return nil, &ErrFileRead{Path: canonical, Err: err}
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, &ErrCertParse{Path: canonical}
			}
			added = true
		}
	}

	if !added {
		return nil, nil
	}
	return pool, nil
}

// ceremonyRootBundleName is the file `xkmsd init` writes the ceremony CA's
// root to in the node's data directory (cmd/xkmsd/init_ceremony.go
// persistCABundle). Init issues the admin client certificate from that root.
const ceremonyRootBundleName = "ca-bundle.pem"

// configuredClientCAs builds the client-CA pool the server advertises from
// configuration: the primary TLS.CAFile, every TLS.ClientCAs entry, and the
// init ceremony root when `xkmsd init` wrote one into Datastore.Path. It
// returns a nil pool with no error when none of them is present.
//
// Advertising the ceremony root grants nothing: client identity binds by
// go-qrdb's SPKI thumbprint (pkg/auth/mtls.go userIdentity), never by chain.
// The pool only decides which certificate a crypto/tls client with a static
// Certificates list offers, since such a client withholds any certificate
// whose issuer the server does not list (#794).
func (s *Server) configuredClientCAs() (*x509.CertPool, error) {
	primary := []string{}
	if s.config.TLS.CAFile != "" {
		primary = append(primary, s.config.TLS.CAFile)
	}
	ceremony, err := s.ceremonyRootBundle()
	if err != nil {
		return nil, err
	}
	return loadClientCAsUnion(primary, s.config.TLS.ClientCAs, ceremony)
}

// ceremonyRootBundle returns the path of the init ceremony root bundle when
// it exists. A node `xkmsd init` did not initialise has none, which is not an
// error, and neither is a Datastore.Path that is not a directory (an
// ephemeral node); any other failure to inspect the path is a *ErrFileRead.
func (s *Server) ceremonyRootBundle() ([]string, error) {
	if s.config.Datastore.Path == "" {
		return nil, nil
	}
	path := filepath.Join(s.config.Datastore.Path, ceremonyRootBundleName)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, nil
		}
		return nil, &ErrFileRead{Path: path, Err: err}
	}
	return []string{path}, nil
}

// canonicalizeCAPath produces a stable identifier for a CA file path
// suitable for filename-based deduplication. It evaluates symlinks
// when the file exists and falls back to filepath.Abs for missing
// files so deduplication still works before the read attempt fails.
func canonicalizeCAPath(path string) (string, error) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, nil
		}
		return "", err
	}
	return resolved, nil
}
