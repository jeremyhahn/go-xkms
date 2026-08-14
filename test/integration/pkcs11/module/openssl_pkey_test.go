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

// Package module covers the OpenSSL public-key operations a real caller performs
// against a token key that openssl_provider_test.go does not reach.
//
// Three things are missing there, and each is a distinct code path rather than a
// restatement of one already covered:
//
//   - `openssl dgst -sign`. Every signing test in openssl_provider_test.go drives
//     `pkeyutl -sign -rawin`, which builds an EVP_PKEY_CTX and calls
//     EVP_PKEY_sign. dgst instead loads the key from its URI through OSSL_STORE
//     and signs via EVP_DigestSign. Scripts and build systems overwhelmingly use
//     dgst, so a module that works only under pkeyutl is not usable.
//   - RSA PKCS#1 v1.5 decryption. The OAEP round trip covers CKM_RSA_PKCS_OAEP;
//     v1.5 is CKM_RSA_PKCS, a different mechanism through a different branch of
//     the provider, and still what a great deal of deployed software sends.
//   - OAEP with a non-default hash AND a label. The existing OAEP test uses
//     SHA-256 with no label, which is the default on both sides, so a module
//     that discarded CK_RSA_PKCS_OAEP_PARAMS and substituted its own defaults
//     would pass it unchanged.
//
// Every signature and every plaintext here is checked outside the module, with
// the pkcs11 provider not loaded: a round trip through the same token proves
// nothing about correctness.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenSSLProvider_DgstSignVerify signs through `openssl dgst -sign` with a
// PKCS#11 URI as the key, then verifies outside the module.
func TestOpenSSLProvider_DgstSignVerify(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	for _, tc := range []struct {
		name    string
		keyType string
		id      string
		digest  string
	}{
		{"rsa2048_sha256", "rsa:2048", "73", "-sha256"},
		{"rsa2048_sha512", "rsa:2048", "74", "-sha512"},
		{"ecdsa_p256_sha256", "EC:prime256v1", "75", "-sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			label := "prov-dgst-" + tc.name
			generateTestKey(t, p11, tc.keyType, label, tc.id)

			cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
			dataFile := filepath.Join(cfg.TempDir, label+".dat")
			sigFile := filepath.Join(cfg.TempDir, label+".sig")

			require.NoError(t, os.WriteFile(dataFile,
				[]byte("dgst payload for "+label), 0o600))

			pubPEM := exportProviderPublicKeyPEM(t, cfg, label)

			_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
				"dgst", tc.digest, "-sign", providerKeyURI(label),
				"-out", sigFile, dataFile,
			)
			require.NoErrorf(t, err, "dgst -sign through the provider failed: %s", stderr)

			sig, err := os.ReadFile(sigFile)
			require.NoError(t, err, "dgst -sign wrote no signature")
			require.NotEmpty(t, sig, "dgst -sign wrote an empty signature")

			// Verified outside the module against the exported public key, so
			// the token cannot simply hand its own output back.
			_, stderr, err = runOpenSSLDefault(t,
				"dgst", tc.digest, "-verify", pubPEM, "-signature", sigFile, dataFile,
			)
			require.NoErrorf(t, err,
				"the signature `dgst -sign` produced did not verify against the "+
					"module's own exported public key: %s", stderr)

			// A signature must be bound to the data it was made over. Without
			// this the test would still pass against a module that signed a
			// constant and returned it for every input.
			tamperedFile := filepath.Join(cfg.TempDir, label+".tampered")
			require.NoError(t, os.WriteFile(tamperedFile,
				[]byte("dgst payload for "+label+"!"), 0o600))

			_, _, err = runOpenSSLDefault(t,
				"dgst", tc.digest, "-verify", pubPEM, "-signature", sigFile, tamperedFile,
			)
			require.Error(t, err,
				"the signature verified over data that was never signed, so it is "+
					"not bound to its message")
		})
	}
}

// TestOpenSSLProvider_RSAPKCS1Decrypt encrypts with PKCS#1 v1.5 outside the
// module and decrypts inside it.
func TestOpenSSLProvider_RSAPKCS1Decrypt(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-pkcs1-dec"
	generateTestKey(t, p11, "rsa:2048", label, "76")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	plainFile := filepath.Join(cfg.TempDir, "pkcs1.plain")
	cipherFile := filepath.Join(cfg.TempDir, "pkcs1.enc")
	outFile := filepath.Join(cfg.TempDir, "pkcs1.out")

	plaintext := []byte("pkcs1 v1.5 round trip")
	require.NoError(t, os.WriteFile(plainFile, plaintext, 0o600))

	pubPEM := exportProviderPublicKeyPEM(t, cfg, label)

	// Encryption runs outside the module, so the ciphertext is provably not
	// something the module produced and could merely recognise.
	_, stderr, err := runOpenSSLDefault(t,
		"pkeyutl", "-encrypt", "-pubin", "-inkey", pubPEM,
		"-pkeyopt", "rsa_padding_mode:pkcs1",
		"-in", plainFile, "-out", cipherFile,
	)
	require.NoErrorf(t, err, "PKCS#1 v1.5 encrypt failed: %s", stderr)

	_, stderr, err = runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkeyutl", "-decrypt", "-inkey", providerKeyURI(label),
		"-pkeyopt", "rsa_padding_mode:pkcs1",
		"-in", cipherFile, "-out", outFile,
	)
	require.NoErrorf(t, err, "PKCS#1 v1.5 decrypt inside the module failed: %s", stderr)

	got, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got,
		"the PKCS#1 v1.5 round trip must recover the plaintext exactly")
}

// TestOpenSSLProvider_RSAOAEP_LabelAndNonDefaultHash decrypts an OAEP ciphertext
// built with SHA-384 and a non-empty label.
//
// Both negatives are load-bearing. OAEP decoding checks lHash, so decrypting
// with the wrong label or the wrong hash must fail; if either succeeds, the
// module discarded the CK_RSA_PKCS_OAEP_PARAMS it was handed and substituted its
// own defaults, which the positive case alone cannot detect.
func TestOpenSSLProvider_RSAOAEP_LabelAndNonDefaultHash(t *testing.T) {
	requireFilePersistence(t)
	requireOpenSSL(t)
	requireOpenSSLPKCS11Provider(t)
	requireTool(t)

	cfg := NewOpenSSLTestConfig(t)
	requireModule(t, cfg.ModulePath)
	p11 := NewPKCS11ToolTestConfig(t)

	SetupInitializedModule(t)

	const label = "prov-oaep-label"
	generateTestKey(t, p11, "rsa:2048", label, "77")

	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)
	plainFile := filepath.Join(cfg.TempDir, "oaep-label.plain")
	cipherFile := filepath.Join(cfg.TempDir, "oaep-label.enc")

	plaintext := []byte("oaep with a label and a non-default hash")
	require.NoError(t, os.WriteFile(plainFile, plaintext, 0o600))

	pubPEM := exportProviderPublicKeyPEM(t, cfg, label)

	// A label the module cannot have guessed, and a hash that is not the
	// mechanism's default on either side.
	const oaepLabel = "0102030405"

	_, stderr, err := runOpenSSLDefault(t,
		"pkeyutl", "-encrypt", "-pubin", "-inkey", pubPEM,
		"-pkeyopt", "rsa_padding_mode:oaep",
		"-pkeyopt", "rsa_oaep_md:sha384",
		"-pkeyopt", "rsa_mgf1_md:sha384",
		"-pkeyopt", "rsa_oaep_label:"+oaepLabel,
		"-in", plainFile, "-out", cipherFile,
	)
	require.NoErrorf(t, err, "OAEP(SHA-384, labelled) encrypt failed: %s", stderr)

	// decryptOAEP asks the module to decrypt under the given parameters and
	// returns the output file it wrote, or the error and stderr if it refused.
	decryptOAEP := func(t *testing.T, mdName, oaepLbl, outName string) (string, string, error) {
		t.Helper()

		outFile := filepath.Join(cfg.TempDir, outName)
		_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
			"pkeyutl", "-decrypt", "-inkey", providerKeyURI(label),
			"-pkeyopt", "rsa_padding_mode:oaep",
			"-pkeyopt", "rsa_oaep_md:"+mdName,
			"-pkeyopt", "rsa_mgf1_md:"+mdName,
			"-pkeyopt", "rsa_oaep_label:"+oaepLbl,
			"-in", cipherFile, "-out", outFile,
		)
		return outFile, stderr, err
	}

	t.Run("matching_hash_and_label_recovers_the_plaintext", func(t *testing.T) {
		outFile, stderr, err := decryptOAEP(t, "sha384", oaepLabel, "oaep-label.out")
		require.NoErrorf(t, err, "OAEP(SHA-384, labelled) decrypt failed: %s", stderr)

		got, err := os.ReadFile(outFile)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got,
			"the OAEP round trip must recover the plaintext exactly")
	})

	t.Run("wrong_label_is_rejected", func(t *testing.T) {
		_, stderr, err := decryptOAEP(t, "sha384", "aabbccddee", "oaep-badlabel.out")
		require.Errorf(t, err,
			"decryption succeeded under a label the ciphertext was not built "+
				"with, so the module discarded the OAEP source data and no lHash "+
				"check is happening. stderr: %s", stderr)
	})

	t.Run("wrong_hash_is_rejected", func(t *testing.T) {
		_, stderr, err := decryptOAEP(t, "sha256", oaepLabel, "oaep-badhash.out")
		require.Errorf(t, err,
			"decryption succeeded under SHA-256 for a SHA-384 ciphertext, so the "+
				"module ignored the requested OAEP hash. stderr: %s", stderr)
	})
}

// exportProviderPublicKeyPEM reads a public key out of the module through
// pkcs11-provider and writes it as PEM, returning the path.
//
// The provider is used rather than pkcs11-tool because OpenSC cannot build an
// EVP_PKEY for every curve this suite covers (see the P-384 note in
// openssl_ssh_test.go), and because it exercises the same object-loading path
// the signing tests use. The file it produces is only ever consumed with the
// pkcs11 provider unloaded, which is what keeps the verifications independent.
func exportProviderPublicKeyPEM(t *testing.T, cfg *OpenSSLTestConfig, label string) string {
	t.Helper()

	pemPath := filepath.Join(cfg.TempDir, label+".pub.pem")
	cfgPath := providerConfig(t, cfg.ModulePath, cfg.PIN)

	_, stderr, err := runOpenSSLWithProvider(t, cfgPath, cfg.PIN,
		"pkey", "-in", "pkcs11:object="+label+";type=public",
		"-pubin", "-pubout", "-out", pemPath,
	)
	require.NoErrorf(t, err, "exporting the public key for %q failed: %s", label, stderr)

	return pemPath
}
