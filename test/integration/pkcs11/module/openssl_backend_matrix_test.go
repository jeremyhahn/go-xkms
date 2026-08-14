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

//go:build integration && pkcs11 && pkcs11_tool
// +build integration,pkcs11,pkcs11_tool

// Package module runs the same OpenSSL-driven operations against every backend
// the module was compiled with.
//
// The module delegates all key material to a backend chosen by
// XKMS_PKCS11_DEFAULT_BACKEND, and each backend reaches different code: the
// software backend signs in process, tpm2 and pkcs11 talk to hardware or
// SoftHSM, and the cloud backends marshal to a remote KMS. A defect in any one
// of them is invisible if the suite only ever exercises the software default —
// which is exactly what happened with the Azure ECDSA signature-format bug.
//
// The matrix is driven by XKMS_PKCS11_BACKENDS (comma-separated). A backend
// named there that is not compiled into the binary is a hard failure, not a
// skip: naming it asserts it should be testable, and silently passing would
// hide a build that dropped it.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// backendsUnderTest returns the backends the matrix should cover.
//
// It defaults to "software" so a developer running the suite locally gets
// meaningful coverage without extra setup, while CI sets the full list.
func backendsUnderTest(t *testing.T) []string {
	t.Helper()

	raw := os.Getenv("XKMS_PKCS11_BACKENDS")
	if strings.TrimSpace(raw) == "" {
		return []string{"software"}
	}

	var backends []string
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			backends = append(backends, name)
		}
	}
	require.NotEmpty(t, backends,
		"XKMS_PKCS11_BACKENDS was set but named no backends")
	return backends
}

// withBackend runs fn with XKMS_PKCS11_DEFAULT_BACKEND set, restoring the
// previous value afterwards.
//
// The module reads its backend from the environment at C_Initialize, so each
// case must set it before the module under test is initialized.
func withBackend(t *testing.T, backend string, fn func()) {
	t.Helper()

	const key = "XKMS_PKCS11_DEFAULT_BACKEND"
	previous, had := os.LookupEnv(key)
	require.NoError(t, os.Setenv(key, backend))
	defer func() {
		if had {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	}()

	fn()
}

// TestOpenSSLBackendMatrix_SignVerify runs an OpenSSL sign-and-verify against
// each backend under test.
//
// Verification runs outside the module against the exported public key, so a
// backend that produces a structurally wrong signature — the wrong ECDSA
// encoding, say — fails here even though the module itself reported success.
func TestOpenSSLBackendMatrix_SignVerify(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	for _, backend := range backendsUnderTest(t) {
		t.Run(backend, func(t *testing.T) {
			withBackend(t, backend, func() {
				cfg := NewOpenSSLTestConfig(t)
				requireModule(t, cfg.ModulePath)
				p11 := NewPKCS11ToolTestConfig(t)

				SetupInitializedModule(t)

				for _, kt := range []struct {
					name    string
					keyType string
					digest  string
				}{
					{"rsa2048", "rsa:2048", "-sha256"},
					{"ecdsa_p256", "EC:prime256v1", "-sha256"},
					{"ecdsa_p384", "EC:secp384r1", "-sha384"},
				} {
					t.Run(kt.name, func(t *testing.T) {
						label := backend + "-" + kt.name
						generateTestKey(t, p11, kt.keyType, label, "70")

						dataFile := filepath.Join(cfg.TempDir, label+".dat")
						sigFile := filepath.Join(cfg.TempDir, label+".sig")
						pubPEM := filepath.Join(cfg.TempDir, label+".pub.pem")

						require.NoError(t, os.WriteFile(dataFile,
							[]byte("matrix payload for "+label), 0o600))

						// The public key is exported through pkcs11-provider rather
						// than pkcs11-tool. OpenSC's --read-object cannot build an
						// EVP_PKEY for a P-384 key even when the token's
						// CKA_EC_PARAMS and CKA_EC_POINT are correct (verified by
						// reconstructing the SubjectPublicKeyInfo by hand and
						// parsing it with OpenSSL, which succeeds); using it here
						// would report a tool bug as a module defect.
						provCfg := providerConfig(t, cfg.ModulePath, cfg.PIN)
						_, stderr, err := runOpenSSLWithProvider(t, provCfg, cfg.PIN,
							"pkey", "-in", "pkcs11:object="+label+";type=public",
							"-pubin", "-pubout", "-out", pubPEM,
						)
						require.NoErrorf(t, err,
							"exporting the public key for %q failed: %s", label, stderr)

						_, stderr, err = runOpenSSLCommand(t, cfg,
							"dgst", kt.digest, "-engine", "pkcs11", "-keyform", "engine",
							"-sign", pkcs11URI(label, cfg.PIN),
							"-out", sigFile, dataFile,
						)
						require.NoErrorf(t, err,
							"signing with backend %q failed: %s", backend, stderr)

						// The signature must verify outside the module. This is
						// what catches a backend returning the wrong signature
						// encoding, which the module would otherwise pass through.
						_, stderr, err = runOpenSSLCommand(t, cfg,
							"dgst", kt.digest, "-verify", pubPEM,
							"-signature", sigFile, dataFile,
						)
						require.NoErrorf(t, err,
							"a signature from backend %q did not verify against its own "+
								"public key, which points at a signature-encoding defect "+
								"in that backend: %s", backend, stderr)
					})
				}
			})
		})
	}
}

// TestOpenSSLBackendMatrix_CertificateIssuance issues a self-signed certificate
// against each backend, exercising the sign path OpenSSL uses for X.509 rather
// than the raw digest path.
func TestOpenSSLBackendMatrix_CertificateIssuance(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Engine(t)
	requireTool(t)

	for _, backend := range backendsUnderTest(t) {
		t.Run(backend, func(t *testing.T) {
			withBackend(t, backend, func() {
				cfg := NewOpenSSLTestConfig(t)
				requireModule(t, cfg.ModulePath)
				p11 := NewPKCS11ToolTestConfig(t)

				SetupInitializedModule(t)

				label := backend + "-cert-key"
				generateTestKey(t, p11, "rsa:2048", label, "71")

				certFile := filepath.Join(cfg.TempDir, label+".crt")

				_, stderr, err := runOpenSSLCommand(t, cfg,
					"req", "-new", "-x509", "-days", "1", "-sha256",
					"-engine", "pkcs11", "-keyform", "engine",
					"-key", pkcs11URI(label, cfg.PIN),
					"-out", certFile,
					"-subj", "/CN=xkms-"+backend,
				)
				require.NoErrorf(t, err,
					"issuing a certificate on backend %q failed: %s", backend, stderr)

				// The certificate must be self-consistent: OpenSSL verifies the
				// signature against the embedded public key, so a backend that
				// signed with the wrong key or encoding fails here.
				_, stderr, err = runOpenSSLCommand(t, cfg,
					"verify", "-CAfile", certFile, certFile,
				)
				require.NoErrorf(t, err,
					"the certificate issued on backend %q does not verify against "+
						"itself: %s", backend, stderr)

				pemBytes, err := os.ReadFile(certFile)
				require.NoError(t, err)
				assert.Contains(t, string(pemBytes), "BEGIN CERTIFICATE",
					"the issued file must be a PEM certificate")
			})
		})
	}
}
