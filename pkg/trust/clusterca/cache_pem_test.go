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

package clusterca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseChainPEM_LeafFirstThenIntermediates verifies the chain is split into
// the leaf (first certificate) and the intermediates that follow. Order matters:
// TLS requires the leaf first, and the provisioner feeds the tail straight into
// chain verification, so a mis-split silently breaks peer validation.
func TestParseChainPEM_LeafFirstThenIntermediates(t *testing.T) {
	rootPEM, intermediate, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")
	_ = rootPEM

	leafGot, intermediatesGot, err := parseChainPEM(certsToPEM(leaf, intermediate))
	require.NoError(t, err)

	assert.Equal(t, leaf.SerialNumber, leafGot.SerialNumber, "the first certificate is the leaf")
	require.Len(t, intermediatesGot, 1)
	assert.Equal(t, intermediate.SerialNumber, intermediatesGot[0].SerialNumber)
}

// TestParseChainPEM_SingleCertificateHasNoIntermediates verifies a bare leaf
// parses with an empty intermediate list rather than erroring, which is the
// shape a directly-root-issued node certificate takes.
func TestParseChainPEM_SingleCertificateHasNoIntermediates(t *testing.T) {
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	leafGot, intermediates, err := parseChainPEM(certsToPEM(leaf))
	require.NoError(t, err)

	assert.Equal(t, leaf.SerialNumber, leafGot.SerialNumber)
	assert.Empty(t, intermediates)
}

// TestParseChainPEM_RejectsUnusableInput verifies every malformed shape is
// rejected. A cached chain is attacker-reachable on disk, so parsing must fail
// loudly instead of yielding a partially-populated chain.
func TestParseChainPEM_RejectsUnusableInput(t *testing.T) {
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty input",
			input: nil,
		},
		{
			name:  "not PEM at all",
			input: []byte("this is not a certificate"),
		},
		{
			name: "PEM blocks but none are certificates",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: []byte("key material, not a certificate"),
			}),
		},
		{
			name:  "truncated certificate DER",
			input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw[:len(leaf.Raw)/2]}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLeaf, gotIntermediates, err := parseChainPEM(tt.input)
			require.Error(t, err)
			assert.Nil(t, gotLeaf)
			assert.Nil(t, gotIntermediates)
		})
	}
}

// TestParseChainPEM_EmptyChainIsTheTypedSentinel verifies that input with no
// CERTIFICATE blocks at all (not merely a decode failure) fails with the
// typed ErrEmptyPEMChain sentinel, reachable with errors.Is (#700).
func TestParseChainPEM_EmptyChainIsTheTypedSentinel(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input []byte
	}{
		{name: "nil input", input: nil},
		{name: "not PEM at all", input: []byte("this is not a certificate")},
		{
			name: "PEM blocks but none are certificates",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: []byte("key material, not a certificate"),
			}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseChainPEM(tt.input)
			require.ErrorIs(t, err, ErrEmptyPEMChain)
		})
	}
}

// TestParseChainPEM_SkipsNonCertificateBlocks verifies non-CERTIFICATE PEM
// blocks interleaved with the chain are ignored rather than aborting the parse.
// Operator-assembled bundles routinely carry comments or key blocks.
func TestParseChainPEM_SkipsNonCertificateBlocks(t *testing.T) {
	_, intermediate, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	var bundle []byte
	bundle = append(bundle, certsToPEM(leaf)...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PARAMETERS",
		Bytes: []byte("ignored"),
	})...)
	bundle = append(bundle, certsToPEM(intermediate)...)

	leafGot, intermediates, err := parseChainPEM(bundle)
	require.NoError(t, err)

	assert.Equal(t, leaf.SerialNumber, leafGot.SerialNumber)
	require.Len(t, intermediates, 1)
	assert.Equal(t, intermediate.SerialNumber, intermediates[0].SerialNumber)
}

// TestCertsToPEM_RoundTripsAndSkipsNil verifies the encoder emits one block per
// certificate, preserves order, and tolerates nil entries. Callers build the
// slice with append from optional values, so a nil must not produce a corrupt
// bundle that breaks every downstream parse.
func TestCertsToPEM_RoundTripsAndSkipsNil(t *testing.T) {
	_, intermediate, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	out := certsToPEM(leaf, nil, intermediate)

	parsedLeaf, intermediates, err := parseChainPEM(out)
	require.NoError(t, err)
	assert.Equal(t, leaf.SerialNumber, parsedLeaf.SerialNumber)
	require.Len(t, intermediates, 1, "the nil entry must be skipped, not encoded")
	assert.Equal(t, intermediate.SerialNumber, intermediates[0].SerialNumber)
}

// TestCertsToPEM_EmptyInputs verifies the degenerate inputs produce no output
// rather than a PEM block with an empty body.
func TestCertsToPEM_EmptyInputs(t *testing.T) {
	assert.Empty(t, certsToPEM())
	assert.Empty(t, certsToPEM(nil))
	assert.Empty(t, certsToPEM(nil, nil))
}

// TestAnchorIntermediates_ExcludesSelfSignedRoot verifies the helper returns
// only the issuing intermediates from an anchor bundle. The root must be
// excluded: it belongs in the peer's trust store, and shipping it inside the
// presented chain is what makes a handshake appear to succeed against a chain
// the peer never actually anchored.
func TestAnchorIntermediates_ExcludesSelfSignedRoot(t *testing.T) {
	rootPEM, intermediate, _ := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	bundle := append(append([]byte{}, rootPEM...), certsToPEM(intermediate)...)

	got := anchorIntermediates(bundle)

	require.Len(t, got, 1, "only the intermediate is an intermediate")
	assert.Equal(t, intermediate.SerialNumber, got[0].SerialNumber)
}

// TestAnchorIntermediates_ToleratesGarbage verifies unparseable or
// non-certificate blocks are skipped instead of aborting, and that an anchor
// with only a root yields nothing.
func TestAnchorIntermediates_ToleratesGarbage(t *testing.T) {
	rootPEM, _, _ := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	t.Run("root only yields no intermediates", func(t *testing.T) {
		assert.Empty(t, anchorIntermediates(rootPEM))
	})

	t.Run("non-PEM input yields nothing", func(t *testing.T) {
		assert.Empty(t, anchorIntermediates([]byte("not pem at all")))
	})

	t.Run("undecodable certificate block is skipped", func(t *testing.T) {
		garbage := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not valid DER"),
		})
		assert.Empty(t, anchorIntermediates(garbage))
	})

	t.Run("non-certificate block is skipped", func(t *testing.T) {
		other := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")})
		assert.Empty(t, anchorIntermediates(other))
	})
}

// TestCacheIdentity_RoundTrip verifies cached material is written under DataDir
// and read back byte-for-byte, which is what makes a node reuse its identity
// across restarts instead of re-enrolling.
func TestCacheIdentity_RoundTrip(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "nested", "cluster-ca")
	p, err := New(&Options{
		RaftAddress: "10.0.0.1:8300",
		TrustDomain: "test.cluster",
		DataDir:     dataDir,
	}, testLogger())
	require.NoError(t, err)

	leafChain := []byte("leaf-chain-pem")
	anchor := []byte("anchor-pem")

	require.NoError(t, p.cacheIdentity(leafChain, anchor),
		"cacheIdentity must create DataDir when it does not exist")

	gotChain, gotAnchor, ok := p.loadCachedIdentity()
	require.True(t, ok)
	assert.Equal(t, leafChain, gotChain)
	assert.Equal(t, anchor, gotAnchor)
}

// TestCacheIdentity_WritesPrivateFilePermissions verifies the cache directory
// and files are not world-readable. They hold only public certificates today,
// but the directory is also where sealed key blobs land.
func TestCacheIdentity_WritesPrivateFilePermissions(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "cluster-ca")
	p, err := New(&Options{
		RaftAddress: "10.0.0.1:8300", TrustDomain: "test.cluster", DataDir: dataDir,
	}, testLogger())
	require.NoError(t, err)

	require.NoError(t, p.cacheIdentity([]byte("chain"), []byte("anchor")))

	for _, name := range []string{nodeCertFile, anchorCertFile} {
		info, statErr := os.Stat(filepath.Join(dataDir, name))
		require.NoError(t, statErr, name)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s must be owner-only", name)
	}
}

// TestCacheIdentity_FailsWhenDataDirUnusable verifies a write failure is
// surfaced rather than silently swallowed. A node that believes it cached its
// identity but did not would re-enroll on every restart.
func TestCacheIdentity_FailsWhenDataDirUnusable(t *testing.T) {
	// A regular file where the data directory should be makes MkdirAll fail.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	p, err := New(&Options{
		RaftAddress: "10.0.0.1:8300", TrustDomain: "test.cluster", DataDir: blocker,
	}, testLogger())
	require.NoError(t, err)

	require.Error(t, p.cacheIdentity([]byte("chain"), []byte("anchor")))
}

// TestLoadCachedIdentity_MissingFiles verifies a partial cache is reported as
// absent. Treating a half-written cache as usable would hand the node a
// certificate with no anchor to validate its peers against.
func TestLoadCachedIdentity_MissingFiles(t *testing.T) {
	dataDir := t.TempDir()
	p, err := New(&Options{
		RaftAddress: "10.0.0.1:8300", TrustDomain: "test.cluster", DataDir: dataDir,
	}, testLogger())
	require.NoError(t, err)

	t.Run("nothing cached", func(t *testing.T) {
		_, _, ok := p.loadCachedIdentity()
		assert.False(t, ok)
	})

	t.Run("node cert without anchor", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dataDir, nodeCertFile), []byte("chain"), 0o600))
		_, _, ok := p.loadCachedIdentity()
		assert.False(t, ok, "a node certificate without its anchor is not a usable identity")
	})

	t.Run("anchor without node cert", func(t *testing.T) {
		require.NoError(t, os.Remove(filepath.Join(dataDir, nodeCertFile)))
		require.NoError(t, os.WriteFile(filepath.Join(dataDir, anchorCertFile), []byte("anchor"), 0o600))
		_, _, ok := p.loadCachedIdentity()
		assert.False(t, ok)
	})
}

// TestPublicKeysEqual verifies the comparison used to confirm a cached
// certificate still matches the backend-held key. It must fail closed for key
// types that do not implement Equal, otherwise a mismatched key would be
// accepted and the node would present a certificate it cannot sign for.
func TestPublicKeysEqual(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	assert.True(t, publicKeysEqual(keyA.Public(), keyA.Public()))
	assert.False(t, publicKeysEqual(keyA.Public(), keyB.Public()))

	t.Run("different curve is not equal", func(t *testing.T) {
		p384, genErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, genErr)
		assert.False(t, publicKeysEqual(keyA.Public(), p384.Public()))
	})

	t.Run("type without Equal fails closed", func(t *testing.T) {
		type opaqueKey struct{ b []byte }
		assert.False(t, publicKeysEqual(opaqueKey{b: []byte{1}}, opaqueKey{b: []byte{1}}),
			"a key type that cannot prove equality must never compare equal")
	})

	t.Run("nil operands fail closed", func(t *testing.T) {
		assert.False(t, publicKeysEqual(nil, keyA.Public()))
		assert.False(t, publicKeysEqual(nil, nil))
	})
}

// TestSignerCertificate_AssemblesChain verifies the TLS certificate carries the
// leaf DER first, then each intermediate, and uses the supplied signer as the
// private key. The signer indirection is what keeps a hardware-resident key
// inside its device during a handshake, so it must be wired through verbatim.
func TestSignerCertificate_AssemblesChain(t *testing.T) {
	_, intermediate, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	got, err := signerCertificate(certsToPEM(leaf), []*x509.Certificate{intermediate}, signer)
	require.NoError(t, err)

	require.Len(t, got.Certificate, 2)
	assert.Equal(t, leaf.Raw, got.Certificate[0], "the leaf must come first")
	assert.Equal(t, intermediate.Raw, got.Certificate[1])
	assert.Same(t, signer, got.PrivateKey, "the signer must drive handshake signatures")
	require.NotNil(t, got.Leaf)
	assert.Equal(t, leaf.SerialNumber, got.Leaf.SerialNumber)
}

// TestSignerCertificate_NoIntermediates verifies the chain-free case yields a
// single-entry certificate rather than a nil slice.
func TestSignerCertificate_NoIntermediates(t *testing.T) {
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	got, err := signerCertificate(certsToPEM(leaf), nil, signer)
	require.NoError(t, err)
	require.Len(t, got.Certificate, 1)
}

// TestSignerCertificate_RejectsBadLeaf verifies malformed leaf material is
// rejected instead of producing a tls.Certificate with a nil Leaf that would
// panic or silently misbehave during the handshake.
func TestSignerCertificate_RejectsBadLeaf(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.1:8300")

	t.Run("not PEM", func(t *testing.T) {
		got, err := signerCertificate([]byte("not pem"), nil, signer)
		var decodeErr *ErrLeafDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Nil(t, got)
	})

	t.Run("empty input", func(t *testing.T) {
		got, err := signerCertificate(nil, nil, signer)
		var decodeErr *ErrLeafDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Nil(t, got)
	})

	t.Run("PEM block with non-certificate DER", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw[:20]})
		got, err := signerCertificate(bad, nil, signer)
		require.Error(t, err)
		assert.Nil(t, got)
	})
}
