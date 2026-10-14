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

package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTrustImportFile writes data to a file in a fresh temp dir and returns
// its path.
func writeTrustImportFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestTrustService_ImportCertificatePath_PEMAndDER(t *testing.T) {
	tests := []struct {
		name string
		file string
		data func(t *testing.T) []byte
	}{
		{"PEM file", "ca.pem", func(t *testing.T) []byte { return []byte(certToPEM(generateTestCert(t))) }},
		{"DER file", "ca.der", func(t *testing.T) []byte { return generateTestCert(t).Raw }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestFileStore(t)
			defer store.Close()
			svc := NewTrustService(store)
			mutated := 0
			svc.SetOnMutate(func() { mutated++ })

			n, err := svc.importCertificatePath(writeTrustImportFile(t, tt.file, tt.data(t)))
			require.NoError(t, err)
			assert.Equal(t, 1, n)
			assert.Equal(t, 1, mutated, "a successful import must notify listeners once")

			total, err := svc.CertificateCount()
			require.NoError(t, err)
			assert.Equal(t, 1, total)
		})
	}
}

func TestTrustService_ImportCertificatePath_Errors(t *testing.T) {
	tests := []struct {
		name    string
		path    func(t *testing.T) string
		wantMsg string
	}{
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") }, "read "},
		{"neither PEM nor DER", func(t *testing.T) string {
			return writeTrustImportFile(t, "junk.crt", []byte("not a certificate"))
		}, "parse DER from "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestFileStore(t)
			defer store.Close()
			svc := NewTrustService(store)
			mutated := false
			svc.SetOnMutate(func() { mutated = true })

			n, err := svc.importCertificatePath(tt.path(t))
			require.Error(t, err)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.Zero(t, n)
			assert.False(t, mutated, "a failed import must not notify listeners")

			total, err := svc.CertificateCount()
			require.NoError(t, err)
			assert.Zero(t, total)
		})
	}
}
