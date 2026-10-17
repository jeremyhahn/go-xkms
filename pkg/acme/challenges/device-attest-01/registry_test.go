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

package deviceattest01

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// errRegistryUnavailable is the lookup failure the failing registry reports.
var errRegistryUnavailable = errors.New("test registry: unavailable")

// testRegistry is a device registry: provisioning records keyed by the
// lowercase hex UEID, the way the injected resolver keys them.
type testRegistry map[string]*ProvisionedDevice

func (r testRegistry) ResolveDevice(_ context.Context, ueid string) (*ProvisionedDevice, error) {
	record, ok := r[ueid]
	if !ok {
		return nil, ErrDeviceNotProvisioned
	}
	return record, nil
}

// resolverFunc is a DeviceResolver answering with a fixed function, for the
// answers a well-behaved registry never gives.
type resolverFunc func(ctx context.Context, ueid string) (*ProvisionedDevice, error)

func (f resolverFunc) ResolveDevice(ctx context.Context, ueid string) (*ProvisionedDevice, error) {
	return f(ctx, ueid)
}

func registryVerifier(t *testing.T, anchors TrustAnchors) *TrustAnchorVerifier {
	t.Helper()
	verifier, err := NewTrustAnchorVerifier(anchors)
	require.NoError(t, err)
	return verifier
}

// provisionedFor is a verifier whose registry provisions key as the DeviceID
// key of the device named diceUeid: the raw-key path.
func provisionedFor(t *testing.T, key *ecdsa.PrivateKey) *TrustAnchorVerifier {
	t.Helper()
	return registryVerifier(t, TrustAnchors{Devices: testRegistry{
		hex.EncodeToString(diceUeid): {DeviceIDKey: spkiOf(t, key)},
	}})
}

func spkiOf(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return spki
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// mintAlias is an alias certificate for subject, signed by signer under
// algorithm, naming diceUeid, echoing this challenge's nonce, and claiming the
// firmware measurement digest. It is what a host that holds no DeviceID key
// would have to forge.
func mintAlias(t *testing.T, subject *ecdsa.PublicKey, signer *ecdsa.PrivateKey, algorithm x509.SignatureAlgorithm, digest []byte) *x509.Certificate {
	t.Helper()
	return mintAliasWithTcbInfo(t, subject, nil, signer, algorithm, &dice.TcbInfo{
		Vendor: "Automate The Things",
		FWIDs:  []dice.FWID{{HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Digest: digest}},
	})
}

// mintAliasWithTcbInfo is mintAlias with info as the alias's DiceTcbInfo,
// issued by parent; a nil parent makes it self-signed.
func mintAliasWithTcbInfo(t *testing.T, subject *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey, algorithm x509.SignatureAlgorithm, info *dice.TcbInfo) *x509.Certificate {
	t.Helper()
	tcbInfo, err := dice.CreateTcbInfoExtension(info)
	require.NoError(t, err)
	uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: DICENonce(diceKeyAuth)})
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(9),
		Subject:            pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: algorithm,
		ExtraExtensions:    []pkix.Extension{tcbInfo, uccs, ueidExtension(t)},
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, subject, signer)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

func TestVerifyRegisteredDeviceRawKey(t *testing.T) {
	ctx := context.Background()
	deviceKey := newP256Key(t)
	verifier := provisionedFor(t, deviceKey)
	genuineDigest := make([]byte, 32)

	t.Run("an alias carrying and signed by the provisioned key is accepted", func(t *testing.T) {
		leaf := mintAlias(t, &deviceKey.PublicKey, deviceKey, x509.ECDSAWithSHA256, genuineDigest)
		attested, err := verifier.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		require.NoError(t, err)
		assert.Equal(t, spkiOf(t, deviceKey), attested.AttestedSPKI)
		assert.Same(t, leaf, attested.Leaf)
		assert.Equal(t, dice.RootTypeUnreported, attested.RootType)
	})

	t.Run("an alias for another key is refused", func(t *testing.T) {
		other := newP256Key(t)
		leaf := mintAlias(t, &other.PublicKey, other, x509.ECDSAWithSHA256, genuineDigest)
		_, err := verifier.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrAttestedKeyMismatch)
	})

	t.Run("the provisioned key with forged measurements, signed by another key, is refused", func(t *testing.T) {
		// The SPKI is public, so a host can copy it into an alias it signs
		// itself and claim any firmware. dice.Verify with no roots would not
		// look at the signature; the registry check does.
		forged := bytes.Repeat([]byte{0xff}, 32)
		leaf := mintAlias(t, &deviceKey.PublicKey, newP256Key(t), x509.ECDSAWithSHA256, forged)
		require.Equal(t, spkiOf(t, deviceKey), leaf.RawSubjectPublicKeyInfo, "the fixture must copy the provisioned SPKI")

		_, err := verifier.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrAliasSignatureInvalid)
	})

	t.Run("an alias signed with anything but ECDSA with SHA-256 is refused", func(t *testing.T) {
		leaf := mintAlias(t, &deviceKey.PublicKey, deviceKey, x509.ECDSAWithSHA384, genuineDigest)
		_, err := verifier.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrAliasSignatureInvalid)
	})

	t.Run("a vouched-for alias answering another challenge is refused as evidence, not as the device", func(t *testing.T) {
		leaf := mintAlias(t, &deviceKey.PublicKey, deviceKey, x509.ECDSAWithSHA256, genuineDigest)
		_, err := verifier.VerifyRegisteredDevice(ctx, leaf, "another.keyauthorization")
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
		assert.ErrorIs(t, err, dice.ErrNonceMismatch)
		assert.NotErrorIs(t, err, ErrDeviceNotAuthorized)
	})

	t.Run("a provisioned key the device cannot hold is an invalid record", func(t *testing.T) {
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		leaf := mintAlias(t, &deviceKey.PublicKey, deviceKey, x509.ECDSAWithSHA256, genuineDigest)
		for name, key := range map[string][]byte{
			"not P-256":  spkiOf(t, p384),
			"not a SPKI": []byte("not a key"),
		} {
			v := registryVerifier(t, TrustAnchors{Devices: testRegistry{hex.EncodeToString(diceUeid): {DeviceIDKey: key}}})
			_, err := v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
			assert.ErrorIs(t, err, ErrDeviceNotAuthorized, name)
			assert.ErrorIs(t, err, ErrProvisioningRecordInvalid, name)
		}
	})
}

func TestVerifyRegisteredDeviceEndorsed(t *testing.T) {
	ctx := context.Background()
	fixture := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)
	leaf, err := x509.ParseCertificate(fixture.leafDER)
	require.NoError(t, err)

	t.Run("an alias endorsed by the provisioned DeviceID certificate is accepted", func(t *testing.T) {
		attested, err := fixture.verifier(t, DICEPolicy{}).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		require.NoError(t, err)
		assert.Equal(t, fixture.deviceID.RawSubjectPublicKeyInfo, attested.AttestedSPKI)
		assert.Same(t, leaf, attested.Leaf)
	})

	t.Run("a DeviceID certificate for another UEID is refused", func(t *testing.T) {
		otherUeid := append([]byte{0x01}, bytes.Repeat([]byte{0x42}, 16)...)
		record := testRegistry{hex.EncodeToString(diceUeid): {DeviceIDCertificate: fixture.issueDeviceID(t, otherUeid).Raw}}
		v := registryVerifier(t, TrustAnchors{DICERoots: []*x509.Certificate{fixture.root}, Devices: record})

		_, err := v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrDeviceEndorsementInvalid)
	})

	t.Run("no DICE root refuses the device rather than falling back", func(t *testing.T) {
		for name, roots := range map[string][]*x509.Certificate{"nil": nil, "empty": {}} {
			v := registryVerifier(t, TrustAnchors{DICERoots: roots, Devices: fixture.registry()})
			_, err := v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
			assert.ErrorIs(t, err, ErrDeviceNotAuthorized, name)
			assert.ErrorIs(t, err, ErrNoTrustAnchors, name)
		}
	})

	t.Run("a DeviceID certificate under a root nobody configured is refused", func(t *testing.T) {
		stranger := newDICEFixture(t, nil, true, true, true)
		v := registryVerifier(t, TrustAnchors{DICERoots: []*x509.Certificate{stranger.root}, Devices: fixture.registry()})

		_, err := v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrDeviceEndorsementInvalid)
		assert.ErrorIs(t, err, dice.ErrChainVerificationFailed)
	})

	t.Run("a DeviceID certificate that does not parse is an invalid record", func(t *testing.T) {
		record := testRegistry{hex.EncodeToString(diceUeid): {DeviceIDCertificate: []byte{0x30, 0x00}}}
		v := registryVerifier(t, TrustAnchors{DICERoots: []*x509.Certificate{fixture.root}, Devices: record})

		_, err := v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrProvisioningRecordInvalid)
	})
}

func TestVerifyRegisteredDeviceRegistryFailures(t *testing.T) {
	ctx := context.Background()
	deviceKey := newP256Key(t)
	leaf := mintAlias(t, &deviceKey.PublicKey, deviceKey, x509.ECDSAWithSHA256, make([]byte, 32))
	spki := spkiOf(t, deviceKey)

	resolving := func(record *ProvisionedDevice, err error) *TrustAnchorVerifier {
		return registryVerifier(t, TrustAnchors{Devices: resolverFunc(func(context.Context, string) (*ProvisionedDevice, error) {
			return record, err
		})})
	}

	for name, tc := range map[string]struct {
		verifier *TrustAnchorVerifier
		reason   error
	}{
		"no record":                          {registryVerifier(t, TrustAnchors{Devices: testRegistry{}}), ErrDeviceNotProvisioned},
		"the registry fails":                 {resolving(nil, errRegistryUnavailable), errRegistryUnavailable},
		"no device registry":                 {registryVerifier(t, TrustAnchors{TPMRoots: []*x509.Certificate{newAIKIssuer(t, "AIK CA").cert}}), ErrNoDeviceResolver},
		"neither a record nor an error":      {resolving(nil, nil), ErrProvisioningRecordInvalid},
		"a record with neither key nor cert": {resolving(&ProvisionedDevice{}, nil), ErrProvisioningRecordInvalid},
		"a record with both key and cert":    {resolving(&ProvisionedDevice{DeviceIDKey: spki, DeviceIDCertificate: leaf.Raw}, nil), ErrProvisioningRecordInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			attested, err := tc.verifier.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
			assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
			assert.ErrorIs(t, err, tc.reason)
			assert.Nil(t, attested)
		})
	}

	t.Run("the resolver is asked for the leaf's UEID in lowercase hex", func(t *testing.T) {
		var asked string
		v := registryVerifier(t, TrustAnchors{Devices: resolverFunc(func(_ context.Context, ueid string) (*ProvisionedDevice, error) {
			asked = ueid
			return &ProvisionedDevice{DeviceIDKey: spki}, nil
		})})
		_, err := v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		require.NoError(t, err)
		assert.Equal(t, "0100112233445566778899aabbccddeeff", asked)
	})

	t.Run("malformed input never reaches the registry", func(t *testing.T) {
		v := provisionedFor(t, deviceKey)
		_, err := v.VerifyRegisteredDevice(ctx, nil, diceKeyAuth)
		assert.ErrorIs(t, err, ErrInvalidAttestationObject)
		_, err = v.VerifyRegisteredDevice(ctx, leaf, "")
		assert.ErrorIs(t, err, ErrInvalidAttestationObject)
	})

	t.Run("a verifier that cannot consult a registry refuses every dice attestation", func(t *testing.T) {
		_, err := VerifyAttestation(ctx, &mockCA{}, attestationPayload(t, diceLeafObject(leaf.Raw)), diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrNoDeviceResolver)
	})
}

func TestConfirmRegisteredDevice(t *testing.T) {
	ctx := context.Background()
	deviceKey := newP256Key(t)
	ueid := hex.EncodeToString(diceUeid)
	spki := spkiOf(t, deviceKey)

	t.Run("an unchanged record confirms", func(t *testing.T) {
		require.NoError(t, provisionedFor(t, deviceKey).ConfirmRegisteredDevice(ctx, ueid, spki))
	})

	t.Run("an unchanged DeviceID certificate confirms", func(t *testing.T) {
		fixture := newDICEFixture(t, nil, true, true, true)
		v := fixture.verifier(t, DICEPolicy{})
		require.NoError(t, v.ConfirmRegisteredDevice(ctx, ueid, fixture.deviceID.RawSubjectPublicKeyInfo))
	})

	t.Run("a withdrawn device is refused", func(t *testing.T) {
		v := registryVerifier(t, TrustAnchors{Devices: testRegistry{}})
		err := v.ConfirmRegisteredDevice(ctx, ueid, spki)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrDeviceNotProvisioned)
	})

	t.Run("a re-keyed device is refused", func(t *testing.T) {
		err := provisionedFor(t, newP256Key(t)).ConfirmRegisteredDevice(ctx, ueid, spki)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrAttestedKeyMismatch)
	})

	t.Run("a DeviceID certificate that no longer parses is refused", func(t *testing.T) {
		v := registryVerifier(t, TrustAnchors{Devices: testRegistry{ueid: {DeviceIDCertificate: []byte{0x30, 0x00}}}})
		err := v.ConfirmRegisteredDevice(ctx, ueid, spki)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrProvisioningRecordInvalid)
	})
}

func TestConfirmRegistration(t *testing.T) {
	ctx := context.Background()
	leafDER, deviceKey := newDICEAlias(t, DICENonce(diceKeyAuth))
	verified, err := VerifyAttestation(ctx, provisionedFor(t, deviceKey), attestationPayload(t, diceLeafObject(leafDER)), diceKeyAuth)
	require.NoError(t, err)

	t.Run("a device the registry still vouches for confirms", func(t *testing.T) {
		require.NoError(t, verified.ConfirmRegistration(ctx, provisionedFor(t, deviceKey)))
	})

	t.Run("a re-keyed device is refused", func(t *testing.T) {
		assert.ErrorIs(t, verified.ConfirmRegistration(ctx, provisionedFor(t, newP256Key(t))), ErrDeviceNotAuthorized)
	})

	t.Run("a verifier that cannot consult a registry refuses", func(t *testing.T) {
		err := verified.ConfirmRegistration(ctx, &mockCA{})
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrNoDeviceResolver)
	})

	t.Run("a leaf that names no device is refused", func(t *testing.T) {
		noUeid := newDICEFixture(t, DICENonce(diceKeyAuth), false, true, true)
		record := &VerifiedAttestation{Format: FormatDICE, KeyAuthorization: diceKeyAuth, LeafDER: noUeid.leafDER, AttestedSPKI: verified.AttestedSPKI}
		assert.ErrorIs(t, record.ConfirmRegistration(ctx, provisionedFor(t, deviceKey)), ErrDeviceNotAuthorized)
	})

	t.Run("no record is refused", func(t *testing.T) {
		var missing *VerifiedAttestation
		assert.ErrorIs(t, missing.ConfirmRegistration(ctx, provisionedFor(t, deviceKey)), ErrNoVerifiedAttestation)
	})

	t.Run("a tpm attestation has nothing to confirm", func(t *testing.T) {
		require.NoError(t, (&VerifiedAttestation{Format: FormatTPM}).ConfirmRegistration(ctx, &mockCA{}))
	})
}
