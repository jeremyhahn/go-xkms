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

package android

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// googleExampleList is the example CRL of §Certificate revocation status
// list, verbatim.
const googleExampleList = `{
  "entries": {
    "2c8cdddfd5e03bfc": {
      "status": "REVOKED",
      "expires": "2020-11-13",
      "reason": "KEY_COMPROMISE",
      "comment": "Key stored on unsecure system"
    },
    "c8966fcb2fbb0d7a": {
      "status": "SUSPENDED",
      "reason": "SOFTWARE_FLAW",
      "comment": "Bug in keystore causes this key malfunction b/555555"
    }
  }
}`

// testChain is a three-certificate chain: leaf, intermediate, root.
type testChain struct {
	leaf, intermediate, root *x509.Certificate
	roots                    *x509.CertPool
}

func (c testChain) certs() []*x509.Certificate {
	return []*x509.Certificate{c.leaf, c.intermediate, c.root}
}

// newTestChain issues a leaf through an intermediate from a self-signed
// root, with the serial numbers given.
func newTestChain(t *testing.T, leafSerial, intermediateSerial, rootSerial *big.Int) testChain {
	t.Helper()
	issue := func(serial *big.Int, name string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, key
	}

	root, rootKey := issue(rootSerial, "Test Root", true, nil, nil)
	intermediate, intermediateKey := issue(intermediateSerial, "Test Intermediate", true, root, rootKey)
	leaf, _ := issue(leafSerial, "Test Leaf", false, intermediate, intermediateKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return testChain{leaf: leaf, intermediate: intermediate, root: root, roots: roots}
}

func serial(t *testing.T, hex string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(hex, 16)
	require.True(t, ok)
	return n
}

func TestParseStatusList_GoogleExample(t *testing.T) {
	list, err := ParseStatusList([]byte(googleExampleList))
	require.NoError(t, err)
	assert.Equal(t, 2, list.Len())

	entry, ok := list.Lookup(serial(t, "2c8cdddfd5e03bfc"))
	require.True(t, ok)
	assert.Equal(t, StatusEntry{
		Status: CertificateStatusRevoked, Expires: "2020-11-13",
		Reason: RevocationReasonKeyCompromise, Comment: "Key stored on unsecure system",
	}, entry)

	entry, ok = list.Lookup(serial(t, "c8966fcb2fbb0d7a"))
	require.True(t, ok)
	assert.Equal(t, CertificateStatusSuspended, entry.Status)

	_, ok = list.Lookup(serial(t, "1"))
	assert.False(t, ok)
}

func TestParseStatusList_Malformed(t *testing.T) {
	cases := map[string]string{
		"not json":                 `{"entries":`,
		"entries missing":          `{}`,
		"entries null":             `{"entries":null}`,
		"unknown top-level field":  `{"entries":{},"extra":1}`,
		"unknown entry field":      `{"entries":{"ab":{"status":"REVOKED","note":"x"}}}`,
		"status missing":           `{"entries":{"ab":{"reason":"UNSPECIFIED"}}}`,
		"unknown status":           `{"entries":{"ab":{"status":"VALID"}}}`,
		"unknown reason":           `{"entries":{"ab":{"status":"REVOKED","reason":"LOST"}}}`,
		"expires not a date":       `{"entries":{"ab":{"status":"REVOKED","expires":"13/11/2020"}}}`,
		"comment too long":         `{"entries":{"ab":{"status":"REVOKED","comment":"` + strings.Repeat("x", 141) + `"}}}`,
		"uppercase serial":         `{"entries":{"AB":{"status":"REVOKED"}}}`,
		"leading-zero serial":      `{"entries":{"0ab":{"status":"REVOKED"}}}`,
		"non-hex serial":           `{"entries":{"xyz":{"status":"REVOKED"}}}`,
		"trailing data":            `{"entries":{}} {}`,
		"entries not an object":    `{"entries":[]}`,
		"status of the wrong type": `{"entries":{"ab":{"status":1}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			list, err := ParseStatusList([]byte(doc))
			require.ErrorIs(t, err, ErrStatusListMalformed)
			assert.Nil(t, list)
		})
	}
}

func TestParseStatusList_CommentOfMultibyteCharactersAtTheLimit(t *testing.T) {
	// maxLength counts characters, not bytes.
	doc := `{"entries":{"ab":{"status":"REVOKED","comment":"` + strings.Repeat("é", 140) + `"}}}`
	_, err := ParseStatusList([]byte(doc))
	require.NoError(t, err)
}

func TestStatusListSerial(t *testing.T) {
	cases := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"lowercase hex", serial(t, "C8966FCB2FBB0D7A"), "c8966fcb2fbb0d7a"},
		// DER prefixes a 0x00 octet to a serial whose high bit is set; the
		// list key carries no leading zero.
		{"high bit set", serial(t, "ff01"), "ff01"},
		{"leading zero nibble", serial(t, "0abc"), "abc"},
		{"one", big.NewInt(1), "1"},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StatusListSerial(tc.serial))
		})
	}
}

func TestStatusListSerial_MatchesDERWithLeadingZeroOctet(t *testing.T) {
	// 0x80... needs a leading 0x00 in DER; the parsed serial still keys as
	// "80..." and so finds its list entry.
	chain := newTestChain(t, serial(t, "80aa"), serial(t, "2"), serial(t, "3"))
	list, err := ParseStatusList([]byte(`{"entries":{"80aa":{"status":"REVOKED"}}}`))
	require.NoError(t, err)

	err = CheckRevocation(list, chain.certs())

	var revoked *RevokedCertificateError
	require.ErrorAs(t, err, &revoked)
	assert.Equal(t, "80aa", revoked.Serial)
}

func TestCheckRevocation(t *testing.T) {
	chain := newTestChain(t, serial(t, "a1"), serial(t, "b2"), serial(t, "c3"))

	t.Run("unlisted chain passes", func(t *testing.T) {
		list, err := ParseStatusList([]byte(googleExampleList))
		require.NoError(t, err)
		require.NoError(t, CheckRevocation(list, chain.certs()))
	})

	for _, tc := range []struct {
		name, serial string
		status       CertificateStatus
	}{
		{"revoked leaf", "a1", CertificateStatusRevoked},
		{"revoked intermediate", "b2", CertificateStatusRevoked},
		{"revoked root", "c3", CertificateStatusRevoked},
		{"suspended leaf", "a1", CertificateStatusSuspended},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list, err := ParseStatusList([]byte(`{"entries":{"` + tc.serial + `":{"status":"` + string(tc.status) + `","reason":"SOFTWARE_FLAW"}}}`))
			require.NoError(t, err)

			err = CheckRevocation(list, chain.certs())

			require.ErrorIs(t, err, ErrCertificateRevoked)
			var revoked *RevokedCertificateError
			require.ErrorAs(t, err, &revoked)
			assert.Equal(t, RevokedCertificateError{Serial: tc.serial, Status: tc.status, Reason: RevocationReasonSoftwareFlaw}, *revoked)
			assert.Contains(t, err.Error(), tc.serial)
			assert.Contains(t, err.Error(), string(tc.status))
		})
	}

	t.Run("nil source", func(t *testing.T) {
		require.ErrorIs(t, CheckRevocation(nil, chain.certs()), ErrNilStatusListSource)
	})

	t.Run("nil list", func(t *testing.T) {
		var list *StatusList
		require.ErrorIs(t, CheckRevocation(list, chain.certs()), ErrNilStatusListSource)
	})

	t.Run("nil certificate", func(t *testing.T) {
		list, err := ParseStatusList([]byte(`{"entries":{}}`))
		require.NoError(t, err)
		require.ErrorIs(t, CheckRevocation(list, []*x509.Certificate{nil}), ErrNilCertificate)
	})
}

func TestRevokedCertificateError_WithoutReason(t *testing.T) {
	err := &RevokedCertificateError{Serial: "ab", Status: CertificateStatusSuspended}
	assert.Equal(t, ErrCertificateRevoked.Error()+": serial ab is SUSPENDED", err.Error())
}

func TestVerifyKeyAttestation_ChecksRevocation(t *testing.T) {
	chain := newTestChain(t, serial(t, "a1"), serial(t, "b2"), serial(t, "c3"))
	// The presented chain omits the root: the check still reaches it
	// through the chain it verified to.
	presented := []*x509.Certificate{chain.leaf, chain.intermediate}
	list, err := ParseStatusList([]byte(`{"entries":{"c3":{"status":"REVOKED"}}}`))
	require.NoError(t, err)

	_, err = VerifyKeyAttestation(presented, &VerifyOptions{TrustedRoots: chain.roots, Revocation: list})

	var revoked *RevokedCertificateError
	require.ErrorAs(t, err, &revoked)
	assert.Equal(t, "c3", revoked.Serial)
}

func TestVerifyKeyAttestation_UnavailableListFailsClosed(t *testing.T) {
	chain := newTestChain(t, serial(t, "a1"), serial(t, "b2"), serial(t, "c3"))
	source := statusListFunc(func() (*StatusList, error) {
		return nil, &StatusListUnavailableError{Source: "test", Cause: os.ErrNotExist}
	})

	_, err := VerifyKeyAttestation(chain.certs(), &VerifyOptions{TrustedRoots: chain.roots, Revocation: source})

	require.ErrorIs(t, err, ErrStatusListUnavailable)
}

// statusListFunc adapts a function to StatusListSource.
type statusListFunc func() (*StatusList, error)

func (f statusListFunc) Current() (*StatusList, error) { return f() }

func TestLoadStatusListFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("loads the list", func(t *testing.T) {
		path := filepath.Join(dir, "status.json")
		require.NoError(t, os.WriteFile(path, []byte(googleExampleList), 0o600))

		list, err := LoadStatusListFile(path)
		require.NoError(t, err)
		current, err := list.Current()
		require.NoError(t, err)
		assert.Same(t, list, current, "a loaded list is its own source")
		assert.Equal(t, 2, list.Len())
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadStatusListFile(filepath.Join(dir, "absent.json"))
		require.ErrorIs(t, err, ErrStatusListUnavailable)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("malformed file", func(t *testing.T) {
		path := filepath.Join(dir, "bad.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"entries":{"AB":{"status":"REVOKED"}}}`), 0o600))
		_, err := LoadStatusListFile(path)
		require.ErrorIs(t, err, ErrStatusListMalformed)
	})

	t.Run("over-size file", func(t *testing.T) {
		path := filepath.Join(dir, "big.json")
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(DefaultMaxStatusListBytes+1))
		require.NoError(t, f.Close())

		_, err = LoadStatusListFile(path)
		require.ErrorIs(t, err, ErrStatusListTooLarge)
		require.ErrorIs(t, err, ErrStatusListUnavailable)
	})
}

func TestStatusListUnavailableError(t *testing.T) {
	cause := errors.New("cause")
	err := &StatusListUnavailableError{Source: "https://example.test/status", Cause: cause}
	assert.ErrorIs(t, err, ErrStatusListUnavailable)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "https://example.test/status")
}
