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

//go:build pkcs11

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	p11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// mustPINSecret seals s into a *secure.Secret for PKCS11StorageConfig.PIN
// test fixtures that have no *testing.T in scope (e.g. pivToken.config, a
// value method). Test-only: production callers resolve the PIN from config.
func mustPINSecret(s string) *secure.Secret {
	sec, err := secure.NewSecret([]byte(s))
	if err != nil {
		panic(err)
	}
	return sec
}

// pivTokenLabel names the token the PIV tests provision for themselves.
const pivTokenLabel = "e2e-piv-test"

// pivSlotSpec describes the key and certificate a provisioned PIV slot holds.
type pivSlotSpec struct {
	slot pivcert.PIVSlot

	// commonName is the certificate subject CN.
	commonName string

	// rsa selects an RSA-2048 key pair; otherwise an EC P-256 pair is used.
	// The mix mirrors a real PIV card, where the card-authentication slot is
	// commonly elliptic while the others are RSA.
	rsa bool
}

// preloadedPIVSlots is the exact token layout every PIV test provisions for
// itself: the four primary PIV slots, mapped to CKA_IDs 0x01-0x04.
var preloadedPIVSlots = []pivSlotSpec{
	{pivcert.PIVSlotAuthentication, "PIV Authentication Test", true},
	{pivcert.PIVSlotDigitalSignature, "Digital Signature Test", true},
	{pivcert.PIVSlotKeyManagement, "Key Management Test", true},
	{pivcert.PIVSlotCardAuthentication, "Card Authentication Test", false},
}

// p256Params is the DER-encoded OID of prime256v1, as CKA_EC_PARAMS wants it.
var p256Params = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// rsaKeyBits is the modulus size of the provisioned RSA PIV keys.
const rsaKeyBits = 2048

// pivToken is a provisioned SoftHSM2 token carrying the four primary PIV
// slots, plus the configuration needed to reach it.
type pivToken struct {
	softhsmtest.Token
}

// config returns a storage configuration pointing at the provisioned token.
func (tok pivToken) config() *pivcert.PKCS11StorageConfig {
	return &pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         mustPINSecret(tok.UserPIN),
		SlotID:      -1, // resolve by label
	}
}

// provisionPIVToken creates a private SoftHSM2 token under t.TempDir() and
// populates the four primary PIV slots with an EC P-256 key pair and a
// matching self-signed certificate each.
//
// This replaces the previous dependency on a token that had to be provisioned
// on the host out of band: every test now builds the exact state it asserts
// against, so a green run proves the code works rather than proving somebody
// remembered to run a setup script.
func provisionPIVToken(t *testing.T) pivToken {
	t.Helper()

	tok := pivToken{Token: softhsmtest.Provision(t, pivTokenLabel)}

	ctx := p11.New(tok.Library)
	require.NotNil(t, ctx, "load SoftHSM library")
	require.NoError(t, ctx.Initialize())
	defer func() {
		require.NoError(t, ctx.Finalize())
		ctx.Destroy()
	}()

	slot, err := resolveSlot(ctx, tok.config())
	require.NoError(t, err, "resolve provisioned token slot")

	session, err := ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	require.NoError(t, err)
	defer func() { require.NoError(t, ctx.CloseSession(session)) }()

	require.NoError(t, ctx.Login(session, p11.CKU_USER, tok.UserPIN))
	defer func() { require.NoError(t, ctx.Logout(session)) }()

	for _, spec := range preloadedPIVSlots {
		ckaID, ok := PIVSlotToCKAID(spec.slot)
		require.True(t, ok, "PIV slot %s must map to a CKA_ID", spec.slot)

		generatePIVKeyPair(t, ctx, session, []byte{ckaID}, spec)
		storePIVCertificate(t, ctx, session, []byte{ckaID}, spec)
	}

	return tok
}

// generatePIVKeyPair creates a token-resident key pair tagged with the given
// CKA_ID, which is how the slot model recognizes an occupied PIV slot.
func generatePIVKeyPair(t *testing.T, ctx *p11.Ctx, session p11.SessionHandle, ckaID []byte, spec pivSlotSpec) {
	t.Helper()

	mechanism := p11.NewMechanism(p11.CKM_EC_KEY_PAIR_GEN, nil)
	keyType := uint(p11.CKK_EC)
	pubExtra := []*p11.Attribute{p11.NewAttribute(p11.CKA_EC_PARAMS, p256Params)}
	if spec.rsa {
		mechanism = p11.NewMechanism(p11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
		keyType = p11.CKK_RSA
		pubExtra = []*p11.Attribute{
			p11.NewAttribute(p11.CKA_MODULUS_BITS, rsaKeyBits),
			p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		}
	}

	pubTemplate := append([]*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, keyType),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_ID, ckaID),
		p11.NewAttribute(p11.CKA_LABEL, string(spec.slot)),
		p11.NewAttribute(p11.CKA_VERIFY, true),
	}, pubExtra...)

	_, _, err := ctx.GenerateKeyPair(session,
		[]*p11.Mechanism{mechanism},
		pubTemplate,
		[]*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
			p11.NewAttribute(p11.CKA_KEY_TYPE, keyType),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_ID, ckaID),
			p11.NewAttribute(p11.CKA_LABEL, string(spec.slot)),
			p11.NewAttribute(p11.CKA_PRIVATE, true),
			p11.NewAttribute(p11.CKA_SIGN, true),
		})
	require.NoError(t, err, "generate PIV key pair for slot %s", spec.slot)
}

// storePIVCertificate writes a self-signed certificate object tagged with the
// given CKA_ID, mirroring what a real PIV provisioning run leaves behind.
func storePIVCertificate(t *testing.T, ctx *p11.Ctx, session p11.SessionHandle, ckaID []byte, spec pivSlotSpec) {
	t.Helper()

	cert := newSelfSignedPIVCert(t, spec)

	serialDER, err := asn1.Marshal(cert.SerialNumber)
	require.NoError(t, err)

	_, err = ctx.CreateObject(session, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE),
		p11.NewAttribute(p11.CKA_CERTIFICATE_TYPE, p11.CKC_X_509),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_ID, ckaID),
		p11.NewAttribute(p11.CKA_LABEL, string(spec.slot)),
		p11.NewAttribute(p11.CKA_SUBJECT, cert.RawSubject),
		p11.NewAttribute(p11.CKA_ISSUER, cert.RawIssuer),
		p11.NewAttribute(p11.CKA_SERIAL_NUMBER, serialDER),
		p11.NewAttribute(p11.CKA_VALUE, cert.Raw),
	})
	require.NoError(t, err, "store PIV certificate for slot %s", spec.slot)
}

// newSelfSignedPIVCert builds a short-lived self-signed certificate matching
// the slot's declared algorithm and common name.
func newSelfSignedPIVCert(t *testing.T, spec pivSlotSpec) *x509.Certificate {
	t.Helper()

	var (
		signer crypto.Signer
		err    error
	)
	if spec.rsa {
		signer, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	} else {
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   spec.commonName,
			Organization: []string{"go-xkms Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
