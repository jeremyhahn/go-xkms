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

package enroll01

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

func sizeField(n int) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return b
}

// newEKCertificate mints an endorsement key certificate for a fresh key.
func newEKCertificate(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("ek-%d", serial)},
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

// packCSR packs a TCG-CSR-IDEVID carrying the endorsement key certificate and
// activation key a credential is made for: the two fields enroll-01's
// activation record is read from.
func packCSR(t *testing.T, ekCert, attestPub []byte) []byte {
	t.Helper()
	csr := &xkmssdk.TCG_CSR_IDEVID{}
	csr.CsrContents.EkCert = ekCert
	csr.CsrContents.EkCertSZ = sizeField(len(ekCert))
	csr.CsrContents.AttestPub = attestPub
	csr.CsrContents.AttestPubSZ = sizeField(len(attestPub))
	packed, err := xkmssdk.PackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("PackIDevIDCSR: %v", err)
	}
	return packed
}

// newPackedCSR is a TCG-CSR-IDEVID for a fresh endorsement key and activation
// key, with the certificate and key it carries.
func newPackedCSR(t *testing.T) ([]byte, *x509.Certificate, []byte) {
	t.Helper()
	ek := newEKCertificate(t, 1)
	attestPub := []byte("iak-tpmt-public")
	return packCSR(t, ek.Raw, attestPub), ek, attestPub
}

// activatingDevice is a device that activates whatever it is sent, serving
// packedCSR as its TCG-CSR-IDEVID, and the address to verify against.
func activatingDevice(t *testing.T, packedCSR, secret []byte) (string, string) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, challengePath):
			_, _ = fmt.Fprint(w, base64.RawURLEncoding.EncodeToString(packedCSR))
		case strings.HasPrefix(r.URL.Path, secretPath):
			_, _ = w.Write(secret)
		}
	}))
	t.Cleanup(ts.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// A credential activation returns the endorsement key and activation key it
// activated, read from the CSR the credential was made for (go-xkms#1391).
func TestVerifyActivation_ReturnsTheActivatedKeys(t *testing.T) {
	packedCSR, ek, attestPub := newPackedCSR(t)
	secret := []byte("the-secret")
	host, port := activatingDevice(t, packedCSR, secret)
	ca := &mockCA{credentialBlob: []byte("blob"), encryptedSecret: []byte("enc"), plainSecret: secret}

	activation, err := VerifyActivation(loopbackClient(), ca, host, port, "token", "keyauth")
	if err != nil {
		t.Fatalf("VerifyActivation: %v", err)
	}
	if !activation.EKCertificate.Equal(ek) {
		t.Error("the activation does not name the endorsement key certificate the CSR carried")
	}
	if string(activation.AttestPub) != string(attestPub) {
		t.Errorf("AttestPub = %q, want %q", activation.AttestPub, attestPub)
	}
}

// An activation that cannot be read back is not a validated challenge: the
// evidence finalization binds to would be missing.
func TestVerifyActivation_RefusesAnUnreadableCSR(t *testing.T) {
	secret := []byte("the-secret")
	ca := &mockCA{credentialBlob: []byte("blob"), encryptedSecret: []byte("enc"), plainSecret: secret}

	tests := map[string][]byte{
		"not a TCG-CSR-IDEVID":       []byte("packed-csr-data"),
		"no endorsement certificate": packCSR(t, nil, []byte("iak")),
		"EK certificate not DER":     packCSR(t, []byte("not a certificate"), []byte("iak")),
		"no activation key":          packCSR(t, newEKCertificate(t, 2).Raw, nil),
	}
	for name, packed := range tests {
		t.Run(name, func(t *testing.T) {
			host, port := activatingDevice(t, packed, secret)
			activation, err := VerifyActivation(loopbackClient(), ca, host, port, "token", "keyauth")
			if !errors.Is(err, ErrActivationUnreadable) || activation != nil {
				t.Fatalf("got (%v, %v), want (nil, ErrActivationUnreadable)", activation, err)
			}
		})
	}
}

// A wrong secret activates nothing, so there is nothing to record.
func TestVerifyActivation_RefusesAWrongSecret(t *testing.T) {
	packedCSR, _, _ := newPackedCSR(t)
	host, port := activatingDevice(t, packedCSR, []byte("not the secret"))
	ca := &mockCA{credentialBlob: []byte("blob"), encryptedSecret: []byte("enc"), plainSecret: []byte("the-secret")}

	activation, err := VerifyActivation(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil || activation != nil {
		t.Fatalf("got (%v, %v), want a refusal", activation, err)
	}
}

// The record names the TPM by the TCG permanent identifier of the activated
// endorsement key certificate -- not by the order's identifier, which for
// enroll-01 is the address that was dialed.
func TestActivation_Record(t *testing.T) {
	ek := newEKCertificate(t, 7)
	activation := &Activation{EKCertificate: ek, AttestPub: []byte("iak")}

	record, err := activation.Record("permanent-identifier", "token.thumbprint")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	digest := sha256.Sum256(ek.Raw)
	if record.DeviceIdentityValue != hex.EncodeToString(digest[:]) {
		t.Errorf("DeviceIdentityValue = %q, want the endorsement certificate's permanent identifier", record.DeviceIdentityValue)
	}
	if record.Format != Format || record.DeviceIdentityType != "permanent-identifier" ||
		record.KeyAuthorization != "token.thumbprint" || string(record.PubArea) != "iak" ||
		string(record.LeafDER) != string(ek.Raw) {
		t.Errorf("record = %+v", record)
	}
}

func TestActivation_RecordRefusesNoCertificate(t *testing.T) {
	if _, err := (&Activation{}).Record("permanent-identifier", "ka"); err == nil {
		t.Fatal("a record was made for an activation naming no endorsement key certificate")
	}
}
