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
	"os"
	"path/filepath"
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
