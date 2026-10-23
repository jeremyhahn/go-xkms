package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignCSRUsesReservedSerial(t *testing.T) {
	testCA := setupTestCA(t)
	ctx := context.Background()

	serial, err := testCA.ReserveSerial(ctx)
	require.NoError(t, err)

	cert, err := testCA.SignCSR(ctx, presignCSR(t, "reserved.example.com"),
		&SignOptions{TenantID: testTenant, Serial: serial})
	require.NoError(t, err)
	assert.Equal(t, 0, cert.SerialNumber.Cmp(serial))
}

func TestSignCSRRefusesUnreservedSerial(t *testing.T) {
	testCA := setupTestCA(t)
	ctx := context.Background()

	_, err := testCA.SignCSR(ctx, presignCSR(t, "unreserved.example.com"),
		&SignOptions{TenantID: testTenant, Serial: big.NewInt(4242)})
	require.ErrorIs(t, err, ErrSerialNotReserved)
}

func TestSignCSRRefusesInvalidSerial(t *testing.T) {
	testCA := setupTestCA(t)
	ctx := context.Background()

	_, err := testCA.SignCSR(ctx, presignCSR(t, "invalid.example.com"),
		&SignOptions{TenantID: testTenant, Serial: big.NewInt(-1)})
	require.ErrorIs(t, err, ErrInvalidSerial)
}

func TestSignCSRPrecertificateIsPoisonedAndNotStored(t *testing.T) {
	testCA := setupTestCA(t)
	ctx := context.Background()
	const cn = "precert.example.com"
	csrPEM := presignCSR(t, cn)

	serial, err := testCA.ReserveSerial(ctx)
	require.NoError(t, err)

	precert, err := testCA.SignCSR(ctx, csrPEM,
		&SignOptions{TenantID: testTenant, Serial: serial, Precertificate: true})
	require.NoError(t, err)
	poison, ok := findExtension(precert.Extensions, ct.OIDPrecertPoison)
	require.True(t, ok, "precertificate lacks the RFC 6962 poison extension")
	assert.True(t, poison.Critical)
	_, err = testCA.certStore.GetCertificate(cn)
	require.Error(t, err, "a precertificate must not be stored")

	final, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant, Serial: serial})
	require.NoError(t, err)
	_, poisoned := findExtension(final.Extensions, ct.OIDPrecertPoison)
	assert.False(t, poisoned)
	assert.Equal(t, 0, final.SerialNumber.Cmp(precert.SerialNumber))
	stored, err := testCA.certStore.GetCertificate(cn)
	require.NoError(t, err)
	assert.Equal(t, final.Raw, stored.Raw)
}

func TestSignCSRLintsTheFinalTBSBeforeSigning(t *testing.T) {
	testCA := setupTestCA(t)
	ctx := context.Background()

	var linted []byte
	cert, err := testCA.SignCSR(ctx, presignCSR(t, "linted.example.com"), &SignOptions{
		TenantID: testTenant,
		Linter:   LintFunc(func(der []byte) error { linted = der; return nil }),
	})
	require.NoError(t, err)

	lintCert, err := x509.ParseCertificate(linted)
	require.NoError(t, err)
	assert.Equal(t, cert.RawTBSCertificate, lintCert.RawTBSCertificate)
	assert.NotEqual(t, cert.Signature, lintCert.Signature, "the lint certificate is signed by a throwaway key")
}

func TestSignCSRRefusesLintFailure(t *testing.T) {
	testCA := setupTestCA(t)
	ctx := context.Background()
	const cn = "refused.example.com"
	errLint := errors.New("e_test_lint")

	_, err := testCA.SignCSR(ctx, presignCSR(t, cn), &SignOptions{
		TenantID: testTenant,
		Linter:   LintFunc(func([]byte) error { return errLint }),
	})
	require.ErrorIs(t, err, ErrLintFailed)
	require.ErrorIs(t, err, errLint)
	_, err = testCA.certStore.GetCertificate(cn)
	require.Error(t, err, "a refused certificate must not be stored")
}

func TestLintAndSignRefusesNilIssuer(t *testing.T) {
	var iss *Issuer
	_, err := iss.lintAndSign(rand.Reader, &x509.Certificate{}, nil)
	require.ErrorIs(t, err, ErrInvalidIssuer)
}

func TestIssueLintsASelfSignedRootThatCertifiesTheIssuerKey(t *testing.T) {
	// A nil PublicKey certifies the issuer's own key; the lint certificate
	// must certify the same key, or the TBS determinism check refuses it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var linted []byte
	iss := &Issuer{Signer: key, Linter: LintFunc(func(der []byte) error { linted = der; return nil })}

	root, err := iss.Issue(rand.Reader, &CertificateSpec{
		Serial:    big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Linted Root"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		Profile:   NewCAProfile(),
	})
	require.NoError(t, err)
	assert.Equal(t, key.Public(), root.PublicKey)
	lintCert, err := x509.ParseCertificate(linted)
	require.NoError(t, err)
	assert.Equal(t, root.RawTBSCertificate, lintCert.RawTBSCertificate)
}

func TestIssueRefusesASelfSignedRootThatFailsLint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	errLint := errors.New("e_test_lint")
	iss := &Issuer{Signer: key, Linter: LintFunc(func([]byte) error { return errLint })}

	_, err = iss.Issue(rand.Reader, &CertificateSpec{
		Serial:    big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Refused Root"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		Profile:   NewCAProfile(),
	})
	require.ErrorIs(t, err, ErrLintFailed)
	require.ErrorIs(t, err, errLint)
}

func TestNewLintSignerMatchesIssuingKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name  string
		key   crypto.PublicKey
		check func(t *testing.T, lint crypto.PublicKey)
	}{
		{"rsa", &rsaKey.PublicKey, func(t *testing.T, lint crypto.PublicKey) {
			assert.Equal(t, 2048, lint.(*rsa.PublicKey).N.BitLen())
		}},
		{"ecdsa", &ecKey.PublicKey, func(t *testing.T, lint crypto.PublicKey) {
			assert.Equal(t, elliptic.P384(), lint.(*ecdsa.PublicKey).Curve)
		}},
		{"ed25519", edPub, func(t *testing.T, lint crypto.PublicKey) {
			assert.IsType(t, ed25519.PublicKey{}, lint)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := newLintSigner(tt.key)
			require.NoError(t, err)
			tt.check(t, signer.Public())
		})
	}
}

func TestNewLintSignerRefusesUnsupportedKey(t *testing.T) {
	_, err := newLintSigner("not a key")
	require.ErrorIs(t, err, ErrLintKey)
}

func TestValidateReservedSerial(t *testing.T) {
	// 159 bits encode in 20 octets; 160 bits need a leading zero octet.
	twentyOctets := new(big.Int).Lsh(big.NewInt(1), 158)
	twentyOneOctets := new(big.Int).Lsh(big.NewInt(1), 159)

	require.NoError(t, validateReservedSerial(big.NewInt(1)))
	require.NoError(t, validateReservedSerial(twentyOctets))
	for name, serial := range map[string]*big.Int{
		"nil":       nil,
		"zero":      big.NewInt(0),
		"negative":  big.NewInt(-5),
		"21 octets": twentyOneOctets,
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, validateReservedSerial(serial), ErrInvalidSerial)
		})
	}
}

// presignCSR returns a PEM CSR for an ECDSA P-256 key naming cn.
func presignCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
