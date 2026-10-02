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

package trustedca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// activatingCA is a CA whose credential the device below activates.
type activatingCA struct {
	ACMECertificateAuthority
	secret []byte
}

func (a activatingCA) VerifyTCG_CSR_IDevIDBytes([]byte, x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	return []byte("blob"), []byte("enc"), a.secret, nil
}

func (activatingCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm { return x509.ECDSAWithSHA256 }

func sdkSizeField(n int) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return b
}

// enrollDevice serves a TCG-CSR-IDEVID for ekDER and attestPub and activates
// every credential with secret, returning its host and port.
func enrollDevice(t *testing.T, ekDER, attestPub, secret []byte) (string, string) {
	t.Helper()
	csr := &xkmssdk.TCG_CSR_IDEVID{}
	csr.CsrContents.EkCert = ekDER
	csr.CsrContents.EkCertSZ = sdkSizeField(len(ekDER))
	csr.CsrContents.AttestPub = attestPub
	csr.CsrContents.AttestPubSZ = sdkSizeField(len(attestPub))
	packed, err := xkmssdk.PackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("PackIDevIDCSR: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			_, _ = fmt.Fprint(w, base64.RawURLEncoding.EncodeToString(packed))
			return
		}
		_, _ = w.Write(secret)
	}))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func newSDKEKCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The enroll-01 verifier reports the identifier the dial established and
// returns, as the evidence to persist, the TPM that activated the credential:
// the endorsement key's TCG permanent identifier and the activation key
// (go-xkms#1391). The two are different things -- the first is the address
// the server dialed, the second names the TPM -- and neither stands in for the
// other.
func TestACMEAttestingVerifiers_Enroll01RecordsTheActivatedTPM(t *testing.T) {
	ek := newSDKEKCertificate(t)
	secret := []byte("the-secret")
	host, port := enrollDevice(t, ek.Raw, []byte("iak-public-area"), secret)
	client := NewACMEChallengeClient(ACMEChallengeClientConfig{AllowPrivateTargets: true})
	verifier := ACMEAttestingVerifiers(client, true, false, nil)[ACMEChallengeTypeEnroll01]

	attested, err := verifier.VerifyAttested(nil, activatingCA{secret: secret}, ACMEAttestationChallenge{
		IdentifierType: acmecommon.AuthzTypePermanentIdentifier, IdentifierValue: "device-1",
		DialTarget: host, Port: port, Token: "token", KeyAuthorization: "token.thumbprint",
	})
	if err != nil {
		t.Fatalf("VerifyAttested: %v", err)
	}
	if attested.Identifier != "device-1" {
		t.Errorf("Identifier = %q, want the identifier the dial established", attested.Identifier)
	}

	record := attested.Attestation
	if record == nil {
		t.Fatal("no activation record to persist for finalization")
	}
	want, err := pkgca.EKCertificatePermanentIdentifier(ek)
	if err != nil {
		t.Fatal(err)
	}
	if record.Format != ACMEEnroll01Format || record.DeviceIdentityValue != want ||
		string(record.PubArea) != "iak-public-area" || string(record.LeafDER) != string(ek.Raw) {
		t.Errorf("record = %+v, want the activated EK (%s) and IAK", record, want)
	}
	if record.DeviceIdentityValue == attested.Identifier {
		t.Error("the TPM's identity must not be the address that was dialed")
	}
}

// A device that does not activate the credential is not validated, and an
// activation that cannot be read back carries no evidence.
func TestACMEAttestingVerifiers_Enroll01RefusesWhatItCannotRecord(t *testing.T) {
	client := NewACMEChallengeClient(ACMEChallengeClientConfig{AllowPrivateTargets: true})
	verifier := ACMEAttestingVerifiers(client, true, false, nil)[ACMEChallengeTypeEnroll01]
	challengeFor := func(host, port string) ACMEAttestationChallenge {
		return ACMEAttestationChallenge{
			IdentifierType: acmecommon.AuthzTypePermanentIdentifier, IdentifierValue: "device-1",
			DialTarget: host, Port: port, Token: "token", KeyAuthorization: "token.thumbprint",
		}
	}

	t.Run("a wrong secret", func(t *testing.T) {
		host, port := enrollDevice(t, newSDKEKCertificate(t).Raw, []byte("iak"), []byte("not-the-secret"))
		attested, err := verifier.VerifyAttested(nil, activatingCA{secret: []byte("the-secret")}, challengeFor(host, port))
		if err == nil || attested != nil {
			t.Fatalf("got (%v, %v), want a refusal", attested, err)
		}
	})

	t.Run("an activated TPM with no readable endorsement key", func(t *testing.T) {
		host, port := enrollDevice(t, []byte("not a certificate"), []byte("iak"), []byte("the-secret"))
		attested, err := verifier.VerifyAttested(nil, activatingCA{secret: []byte("the-secret")}, challengeFor(host, port))
		if attested != nil || err == nil {
			t.Fatalf("got (%v, %v), want ErrACMEEnroll01ActivationUnreadable", attested, err)
		}
	})
}
