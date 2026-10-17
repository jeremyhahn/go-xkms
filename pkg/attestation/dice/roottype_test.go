// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package dice

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustRootTypeVendorInfo(t *testing.T, root RootType) []byte {
	t.Helper()
	value, err := RootTypeVendorInfo(root)
	require.NoError(t, err)
	return value
}

// rootTypeTcbInfo is a DiceTcbInfo declaring root, with notSecure as given.
func rootTypeTcbInfo(t *testing.T, root RootType, notSecure bool) *TcbInfo {
	t.Helper()
	return &TcbInfo{
		Vendor:     "Automate The Things",
		FWIDs:      []FWID{{HashAlg: oidSHA256, Digest: make([]byte, 32)}},
		Flags:      &OperationalFlags{NotSecure: notSecure},
		VendorInfo: mustRootTypeVendorInfo(t, root),
	}
}

func mustMarshalTcbInfo(t *testing.T, info *TcbInfo) []byte {
	t.Helper()
	value, err := MarshalTcbInfo(info)
	require.NoError(t, err)
	return value
}

func TestRootTypeString(t *testing.T) {
	assert.Equal(t, "unreported", RootTypeUnreported.String())
	assert.Equal(t, "hardware", RootTypeHardware.String())
	assert.Equal(t, "software", RootTypeSoftware.String())
	assert.Equal(t, "unknown", RootType(200).String())
}

func TestRootTypeVendorInfo(t *testing.T) {
	t.Run("each root type encodes as its DER OID and reads back", func(t *testing.T) {
		for root, oid := range map[RootType]asn1.ObjectIdentifier{
			RootTypeHardware: OIDRootOfTrustHardware,
			RootTypeSoftware: OIDRootOfTrustSoftware,
		} {
			value := mustRootTypeVendorInfo(t, root)
			expected, err := asn1.Marshal(oid)
			require.NoError(t, err)
			assert.Equal(t, expected, value)
			assert.Equal(t, root, rootTypeFromVendorInfo(value))
		}
	})

	t.Run("both values sit under the root-of-trust arc", func(t *testing.T) {
		assert.Equal(t, "1.3.6.1.4.1.29377.101.24", OIDRootOfTrust.String())
		assert.Equal(t, OIDRootOfTrust, OIDRootOfTrustHardware[:len(OIDRootOfTrust)])
		assert.Equal(t, OIDRootOfTrust, OIDRootOfTrustSoftware[:len(OIDRootOfTrust)])
	})

	t.Run("unreported and undefined root types have no value", func(t *testing.T) {
		for _, root := range []RootType{RootTypeUnreported, RootType(9)} {
			value, err := RootTypeVendorInfo(root)
			assert.ErrorIs(t, err, ErrUnknownRootType)
			assert.Nil(t, value)
		}
	})
}

func TestRootTypeFromVendorInfoIgnoresOtherVendorsData(t *testing.T) {
	arc, err := asn1.Marshal(OIDRootOfTrust)
	require.NoError(t, err)
	unknownChild, err := asn1.Marshal(append(asn1.ObjectIdentifier{}, 1, 3, 6, 1, 4, 1, 29377, 101, 24, 3))
	require.NoError(t, err)
	trailing := append(mustRootTypeVendorInfo(t, RootTypeHardware), 0x00)

	for name, value := range map[string][]byte{
		"absent":                     nil,
		"opaque bytes":               []byte("avr-tier-hardware"),
		"the arc itself":             arc,
		"an undefined child":         unknownChild,
		"a value with trailing data": trailing,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, RootTypeUnreported, rootTypeFromVendorInfo(value))
		})
	}
}

func TestVerifyReportsTheRootType(t *testing.T) {
	tests := []struct {
		name     string
		options  []chainOption
		expected RootType
	}{
		{
			name:     "a hardware chain",
			options:  []chainOption{withTcbInfo(rootTypeTcbInfo(t, RootTypeHardware, false))},
			expected: RootTypeHardware,
		},
		{
			name:     "a software chain",
			options:  []chainOption{withTcbInfo(rootTypeTcbInfo(t, RootTypeSoftware, true))},
			expected: RootTypeSoftware,
		},
		{
			name:     "a chain with no DiceTcbInfo",
			options:  []chainOption{withoutTcbInfo()},
			expected: RootTypeUnreported,
		},
		{
			name:     "a DiceTcbInfo whose vendorInfo is another vendor's",
			options:  nil,
			expected: RootTypeUnreported,
		},
		{
			name: "a declaration on the embedded CA alone",
			options: []chainOption{
				withRawECATcbInfo(mustMarshalTcbInfo(t, rootTypeTcbInfo(t, RootTypeHardware, false))),
			},
			expected: RootTypeHardware,
		},
		{
			name: "the same declaration on both certificates",
			options: []chainOption{
				withTcbInfo(rootTypeTcbInfo(t, RootTypeSoftware, true)),
				withRawECATcbInfo(mustMarshalTcbInfo(t, rootTypeTcbInfo(t, RootTypeSoftware, true))),
			},
			expected: RootTypeSoftware,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := newTestChain(t, test.options...)
			options := defaultOptions(chain)
			options.PermittedFlags = OperationalFlags{NotSecure: true}

			evidence, err := Verify(chain.certs(), options)
			require.NoError(t, err)
			assert.Equal(t, test.expected, evidence.RootType)
		})
	}
}

func TestVerifyReadsAnySoftwareLayerAsSoftware(t *testing.T) {
	// CA m452: notSecure on any layer, with or without a vendorInfo
	// declaration, and a software vendorInfo on any layer, make the identity
	// software-rooted.
	tests := []struct {
		name    string
		options []chainOption
	}{
		{
			name:    "a hardware vendorInfo with notSecure set",
			options: []chainOption{withTcbInfo(rootTypeTcbInfo(t, RootTypeHardware, true))},
		},
		{
			name:    "a software vendorInfo with notSecure clear",
			options: []chainOption{withTcbInfo(rootTypeTcbInfo(t, RootTypeSoftware, false))},
		},
		{
			name: "a software vendorInfo with the flags field omitted",
			options: []chainOption{withTcbInfo(&TcbInfo{
				Vendor:     "Automate The Things",
				VendorInfo: mustRootTypeVendorInfo(t, RootTypeSoftware),
			})},
		},
		{
			name: "a hardware leaf under a software embedded CA",
			options: []chainOption{
				withTcbInfo(rootTypeTcbInfo(t, RootTypeHardware, false)),
				withRawECATcbInfo(mustMarshalTcbInfo(t, rootTypeTcbInfo(t, RootTypeSoftware, true))),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := newTestChain(t, test.options...)
			options := defaultOptions(chain)
			options.PermittedFlags = OperationalFlags{NotSecure: true}

			evidence, err := Verify(chain.certs(), options)
			require.NoError(t, err)
			assert.Equal(t, RootTypeSoftware, evidence.RootType)

			evidence, err = Verify(chain.certs(), defaultOptions(chain))
			assert.ErrorIs(t, err, ErrOperationalStateNotPermitted)
			assert.Nil(t, evidence)
		})
	}
}

func TestRootTypeFromPathsRejectsBadInput(t *testing.T) {
	t.Run("no verified path reports unreported", func(t *testing.T) {
		for _, paths := range [][][]*x509.Certificate{nil, {}} {
			root, err := RootTypeFromPaths(paths)
			require.NoError(t, err)
			assert.Equal(t, RootTypeUnreported, root)
		}
	})

	t.Run("a nil certificate is refused", func(t *testing.T) {
		root, err := RootTypeFromPaths([][]*x509.Certificate{{nil}})
		assert.ErrorIs(t, err, ErrNilCertificate)
		assert.Equal(t, RootTypeUnreported, root)
	})

	t.Run("an unreadable DiceTcbInfo is refused", func(t *testing.T) {
		chain := newTestChain(t, withRawECATcbInfo([]byte{0x30, 0x03, 0x01}))
		root, err := RootTypeFromPaths([][]*x509.Certificate{chain.certs()})
		assert.ErrorIs(t, err, ErrMalformedTcbInfo)
		assert.Equal(t, RootTypeUnreported, root)
	})
}

func TestRootTypeFromPathsReadsOnlyTheVerifiedPaths(t *testing.T) {
	// The embedded CA declares the root; a short path that leaves it out
	// stands for x509.Verify authenticating the leaf without it.
	newPaths := func(t *testing.T, info *TcbInfo) (full, short []*x509.Certificate) {
		chain := newTestChain(t, withoutTcbInfo(), withRawECATcbInfo(mustMarshalTcbInfo(t, info)))
		return chain.certs(), []*x509.Certificate{chain.leaf, chain.root}
	}

	t.Run("a certificate on no path is not read", func(t *testing.T) {
		_, short := newPaths(t, rootTypeTcbInfo(t, RootTypeHardware, false))
		root, err := RootTypeFromPaths([][]*x509.Certificate{short})
		require.NoError(t, err)
		assert.Equal(t, RootTypeUnreported, root)
	})

	t.Run("hardware only when every path declares it", func(t *testing.T) {
		full, short := newPaths(t, rootTypeTcbInfo(t, RootTypeHardware, false))
		root, err := RootTypeFromPaths([][]*x509.Certificate{full})
		require.NoError(t, err)
		assert.Equal(t, RootTypeHardware, root)

		root, err = RootTypeFromPaths([][]*x509.Certificate{full, short})
		require.NoError(t, err)
		assert.Equal(t, RootTypeUnreported, root)
	})

	t.Run("software when any path declares it", func(t *testing.T) {
		full, short := newPaths(t, &TcbInfo{Flags: &OperationalFlags{NotSecure: true}})
		root, err := RootTypeFromPaths([][]*x509.Certificate{short, full})
		require.NoError(t, err)
		assert.Equal(t, RootTypeSoftware, root)
	})
}

// strayHardwareRoot is a self-signed certificate from no one the verifier
// trusts, declaring a hardware root of trust.
func strayHardwareRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	extension, err := CreateTcbInfoExtension(rootTypeTcbInfo(t, RootTypeHardware, false))
	require.NoError(t, err)
	key := mustP256(t)
	return signCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Stray Hardware Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       []pkix.Extension{extension},
	}, nil, key, key.Public())
}

func TestVerifyReadsTheRootTypeOnlyFromTheVerifiedPath(t *testing.T) {
	t.Run("an unverified chain that declares hardware reports unreported", func(t *testing.T) {
		chain := newTestChain(t, withTcbInfo(rootTypeTcbInfo(t, RootTypeHardware, false)))

		evidence, err := Verify(chain.certs(), &VerifyOptions{ExpectedNonce: testNonce})
		require.NoError(t, err)
		assert.Equal(t, RootTypeUnreported, evidence.RootType)
	})

	t.Run("an off-path certificate that declares hardware is ignored", func(t *testing.T) {
		chain := newTestChain(t, withoutTcbInfo())
		certs := append(chain.certs(), strayHardwareRoot(t))

		evidence, err := Verify(certs, defaultOptions(chain))
		require.NoError(t, err)
		assert.Equal(t, RootTypeUnreported, evidence.RootType)
	})
}

func TestVerifyHoldsAnAncestorsSoftwareRootToTheNotSecurePolicy(t *testing.T) {
	// The leaf reports no flags at all: the software root is on the embedded
	// CA alone.
	for name, info := range map[string]func(t *testing.T) *TcbInfo{
		"a software vendorInfo": func(t *testing.T) *TcbInfo {
			return rootTypeTcbInfo(t, RootTypeSoftware, true)
		},
		"notSecure with no vendorInfo": func(*testing.T) *TcbInfo {
			return &TcbInfo{Flags: &OperationalFlags{NotSecure: true}}
		},
	} {
		newChain := func(t *testing.T) *testChain {
			return newTestChain(t, withoutTcbInfo(), withRawECATcbInfo(mustMarshalTcbInfo(t, info(t))))
		}

		t.Run(name+" is refused when notSecure is not permitted", func(t *testing.T) {
			chain := newChain(t)

			evidence, err := Verify(chain.certs(), defaultOptions(chain))
			require.ErrorIs(t, err, ErrOperationalStateNotPermitted)
			assert.Nil(t, evidence)
		})

		t.Run(name+" is software when it is", func(t *testing.T) {
			chain := newChain(t)
			options := defaultOptions(chain)
			options.PermittedFlags = OperationalFlags{NotSecure: true}

			evidence, err := Verify(chain.certs(), options)
			require.NoError(t, err)
			assert.Equal(t, RootTypeSoftware, evidence.RootType)
		})
	}
}
