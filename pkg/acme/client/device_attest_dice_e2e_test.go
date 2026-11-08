//go:build codec_json

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

package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"
	"github.com/jeremyhahn/trusted-firmware/sdk/go/tfwsim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// These tests enroll the REAL trusted-firmware firmware, compiled for the host
// and started by tfwsim.StartElement, through go-xkms's ACME client and the real
// ACME server handlers with device-attest-01 offered:
//
//   - the device mints a DICE alias certificate over the nonce derived from the
//     challenge's key authorization (ATTEST_CERT, signed with real P-256);
//   - the client POSTs it as the attestation object and the server verifies it
//     with the production deviceattest01.TrustAnchorVerifier;
//   - the order's identifier is the device's ueid, read from the evidence;
//   - finalization binds the CSR's key to the alias certificate's key.
//
// The simulator binaries are built by `make agsim` (into $TFWSIM_DIR). A missing binary FAILS
// these tests (tfwsim reports the command); they never skip.

// testDeviceIDSeed is the published string whose SHA-256 is the private half
// of the simulator's TEST DeviceID key (trusted-firmware test/model/atecc608a.c).
// It is public on purpose: the identity is a test identity and nothing outside
// a test may trust it. The private half is needed here only to sign the CSR,
// because the firmware has no command that signs one; see diceElement.
const testDeviceIDSeed = "tfwsim-atecc608a TEST DeviceID key v1"

// diceDeviceIDKey returns the simulator's DeviceID private key and proves it is
// the key the firmware signs with by comparing it to tfwsim's public point.
func diceDeviceIDKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	scalar := sha256.Sum256([]byte(testDeviceIDSeed))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	require.NoError(t, err)
	require.True(t, key.PublicKey.Equal(tfwsim.TestDeviceIDPublicKey()),
		"the published seed no longer derives tfwsim.TestDeviceIDPublicKey: the simulator's identity changed")
	return key
}

// simulatorUeid is the lowercase hex of the simulator's UEID, type byte
// included: the key its provisioning record is filed under.
func simulatorUeid() string {
	return hex.EncodeToString(append([]byte{0x01}, tfwsim.TestSerial[:]...))
}

// diceRegistry is the device registry a provisioning step fills: the DeviceID
// key each UEID was provisioned with. Only the public key crosses over.
type diceRegistry map[string]*ecdsa.PublicKey

func (r diceRegistry) ResolveDevice(_ context.Context, ueid string) (*deviceattest01.ProvisionedDevice, error) {
	key, ok := r[ueid]
	if !ok {
		return nil, deviceattest01.ErrDeviceNotProvisioned
	}
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &deviceattest01.ProvisionedDevice{DeviceIDKey: spki}, nil
}

// diceElement is the ACME client's view of the simulated device. It implements
// the two TPMModule methods DeviceAttest calls for a device-attest-01 order,
// DeviceIdentity and CreateAttestedKey; the embedded interface is nil, so a
// call to any other method fails loudly rather than answering.
//
// The device is the real firmware. Its alias key is its DeviceID key, so the
// CSR for "the attested key" is signed by that key. The firmware has no
// command that signs a CSR (trusted-firmware has ATTEST, ATTEST_CERT, AUTH and
// PROV_* only), which is why signer holds the public test key's private half.
type diceElement struct {
	TPMModule

	device   *tfw.Device
	identity string
	signer   crypto.Signer

	// nonceFor derives the nonce the device attests over from the key
	// authorization. The draft's is deviceattest01.DICENonce.
	nonceFor func(keyAuthorization string) []byte
}

func newDiceElement(t *testing.T) *diceElement {
	t.Helper()
	element := &diceElement{
		device:   tfwsim.StartElement(t),
		signer:   diceDeviceIDKey(t),
		nonceFor: deviceattest01.DICENonce,
	}

	// The device's identity is read from its own evidence, by the rule the
	// server reads it with, so client and server cannot disagree.
	probe := element.attestCert(t, deviceattest01.DICENonce("identity-probe"))
	leaf, err := x509.ParseCertificate(probe)
	require.NoError(t, err)
	element.identity, err = deviceattest01.DeviceIdentityFromCertificate(deviceattest01.FormatDICE, leaf)
	require.NoError(t, err)
	return element
}

func (e *diceElement) attestCert(t testing.TB, nonce []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	der, err := e.device.AttestCert(ctx, nonce)
	require.NoError(t, err)
	return der
}

// DeviceIdentity implements TPMModule.
func (e *diceElement) DeviceIdentity() (string, error) { return e.identity, nil }

// CreateAttestedKey implements TPMModule: the device mints its alias
// certificate over the challenge's nonce and the client wraps it as a "dice"
// attestation object.
func (e *diceElement) CreateAttestedKey(_, keyAuthorization string) (*AttestedKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	der, err := e.device.AttestCert(ctx, e.nonceFor(keyAuthorization))
	if err != nil {
		return nil, err
	}
	statement, err := deviceattest01.EncodeAttestationRequest(&deviceattest01.AttestationObject{
		Format:       deviceattest01.FormatDICE.String(),
		AttStatement: deviceattest01.AttestationStatement{X5c: []interface{}{der}},
	})
	if err != nil {
		return nil, err
	}
	return &AttestedKey{Statement: statement, Signer: e.signer, Format: deviceattest01.FormatDICE}, nil
}

// verdictRecorder wraps the production verifier and remembers why it last
// refused. The server hides that reason from the client by design -- every
// failed attestation is the same incorrectResponse -- so a test that must tell
// "the nonce was wrong" from "the key was not provisioned" reads it here, where the
// verdict is made, instead of weakening what the client is told.
type verdictRecorder struct {
	*deviceattest01.TrustAnchorVerifier
	refusal atomic.Pointer[error]
}

func (r *verdictRecorder) VerifyRegisteredDevice(ctx context.Context, leaf *x509.Certificate, keyAuthorization string) (*deviceattest01.VerifiedAttestation, error) {
	verified, err := r.TrustAnchorVerifier.VerifyRegisteredDevice(ctx, leaf, keyAuthorization)
	return verified, r.record(err)
}

func (r *verdictRecorder) ConfirmRegisteredDevice(ctx context.Context, ueid string, attestedSPKI []byte) error {
	return r.record(r.TrustAnchorVerifier.ConfirmRegisteredDevice(ctx, ueid, attestedSPKI))
}

func (r *verdictRecorder) record(err error) error {
	if err != nil {
		r.refusal.Store(&err)
	}
	return err
}

// Refusal returns the last error the verifier refused with, or nil.
func (r *verdictRecorder) Refusal() error {
	if refusal := r.refusal.Load(); refusal != nil {
		return *refusal
	}
	return nil
}

// diceEnrollment is a device-attest-01 ACME server anchored the way a
// deployment anchors it, and a client for it.
type diceEnrollment struct {
	server   *deviceAttestServer
	client   *Client
	verifier *verdictRecorder
}

// newDiceEnrollment serves device-attest-01 with the simulator's UEID
// provisioned with deviceID as its DeviceID key. RequireDeviceSignedLeaf is the
// device-resident-issuer profile: the alias certificate's issuer is the
// element's own DeviceID key.
func newDiceEnrollment(t *testing.T, deviceID *ecdsa.PublicKey) *diceEnrollment {
	t.Helper()
	verifier, err := deviceattest01.NewTrustAnchorVerifier(deviceattest01.TrustAnchors{
		Devices: diceRegistry{simulatorUeid(): deviceID},
		DICE:    deviceattest01.DICEPolicy{RequireDeviceSignedLeaf: true},
	})
	require.NoError(t, err)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	recorder := &verdictRecorder{TrustAnchorVerifier: verifier}
	server := startDeviceAttestServer(t, caCert, caKey, recorder)
	return &diceEnrollment{server: server, client: newDeviceAttestRoundTripClient(t, server), verifier: recorder}
}

func (e *diceEnrollment) enroll(element TPMModule) (*x509.Certificate, error) {
	return e.client.DeviceAttest(context.Background(), &EnrollmentConfig{
		Challenge:  string(ChallengeTypeDeviceAttest01),
		TPMModule:  element,
		CommonName: "sensor-1.example.com",
		Timeout:    10 * time.Second,
	})
}

// permanentIdentifier returns the RFC 4043 permanentIdentifier a certificate
// is bound to.
func permanentIdentifier(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	names, err := ca.ParseOtherNames(cert.Extensions)
	require.NoError(t, err)
	for _, name := range names {
		if name.TypeID.Equal(ca.OIDPermanentIdentifier) {
			parsed, err := ca.ParsePermanentIdentifierExtension(name.Value)
			require.NoError(t, err)
			return parsed.IdentifierValue
		}
	}
	t.Fatal("the certificate carries no permanentIdentifier")
	return ""
}

// A real trusted-firmware device enrolls: the order is for its ueid, its DICE
// evidence answers the challenge's nonce, and the certificate that is issued
// is for the DeviceID key it attested and bound to the ueid.
func TestDeviceAttestDICEEnrollsTheRealFirmware(t *testing.T) {
	element := newDiceElement(t)
	enrollment := newDiceEnrollment(t, tfwsim.TestDeviceIDPublicKey())

	assert.Equal(t, simulatorUeid(), element.identity,
		"the identity is the hex of the ueid, type byte included")

	cert, err := enrollment.enroll(element)
	require.NoError(t, err)
	require.NoError(t, enrollment.verifier.Refusal())

	assert.True(t, cert.PublicKey.(*ecdsa.PublicKey).Equal(tfwsim.TestDeviceIDPublicKey()),
		"the certificate must be for the key the device attested")
	assert.Equal(t, element.identity, permanentIdentifier(t, cert),
		"the certificate must be bound to the device's ueid")
	select {
	case issued := <-enrollment.server.issued:
		assert.Equal(t, issued.Raw, cert.Raw)
	default:
		t.Fatal("the server issued no certificate")
	}
}

// An order for a ueid other than the one the evidence carries is refused: the
// evidence is genuine, but it is not that device's.
func TestDeviceAttestDICERefusesAnotherUeid(t *testing.T) {
	element := newDiceElement(t)
	enrollment := newDiceEnrollment(t, tfwsim.TestDeviceIDPublicKey())
	element.identity = hex.EncodeToString(append([]byte{0x01}, []byte("another-device-1")...))

	cert, err := enrollment.enroll(element)

	require.ErrorContains(t, err, "urn:ietf:params:acme:error:unauthorized")
	assert.Nil(t, cert)
	assert.Empty(t, enrollment.server.issued)
}

// Evidence minted over a different challenge's nonce is a replay and is
// refused, whatever else about it is genuine.
func TestDeviceAttestDICERefusesTheWrongNonce(t *testing.T) {
	element := newDiceElement(t)
	enrollment := newDiceEnrollment(t, tfwsim.TestDeviceIDPublicKey())
	element.nonceFor = func(string) []byte { return deviceattest01.DICENonce("another-token.another-thumbprint") }

	cert, err := enrollment.enroll(element)

	require.ErrorContains(t, err, "urn:ietf:params:acme:error:incorrectResponse")
	assert.Nil(t, cert)
	assert.Empty(t, enrollment.server.issued)
	assert.ErrorIs(t, enrollment.verifier.Refusal(), dice.ErrNonceMismatch,
		"the verifier must have refused the evidence for its nonce, not for another reason")
}

// A CSR for any key but the attested one is refused at finalization, even
// though the device's evidence verified.
func TestDeviceAttestDICERefusesACSRForAnotherKey(t *testing.T) {
	element := newDiceElement(t)
	enrollment := newDiceEnrollment(t, tfwsim.TestDeviceIDPublicKey())
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	element.signer = other

	cert, err := enrollment.enroll(element)

	require.ErrorContains(t, err, "urn:ietf:params:acme:error:badCSR")
	assert.Nil(t, cert)
	assert.Empty(t, enrollment.server.issued)
}

// Evidence from a device whose provisioning record names another DeviceID key
// is refused as unauthorized: the evidence is self-consistent whoever made it,
// and only the registry says whose key it should be.
func TestDeviceAttestDICERefusesAnUnprovisionedKey(t *testing.T) {
	element := newDiceElement(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrollment := newDiceEnrollment(t, &stranger.PublicKey)

	cert, err := enrollment.enroll(element)

	require.ErrorContains(t, err, "urn:ietf:params:acme:error:unauthorized")
	assert.Nil(t, cert)
	assert.Empty(t, enrollment.server.issued)
	refusal := enrollment.verifier.Refusal()
	assert.ErrorIs(t, refusal, deviceattest01.ErrAttestedKeyMismatch)
	assert.NotErrorIs(t, refusal, dice.ErrNonceMismatch,
		"the nonce was right: the refusal must be about the provisioned key")
}
