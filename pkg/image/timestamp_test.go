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

package image

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidSHA1 is a digest algorithm the timestamp verifier refuses.
var (
	oidSHA1           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidKPServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

func TestNewRFC3161Client(t *testing.T) {
	client, err := NewRFC3161Client("https://tsa.example.com/tsr", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://tsa.example.com/tsr", client.url)
	assert.Equal(t, DefaultTimestampTimeout, client.http.Timeout)

	custom := &http.Client{}
	client, err = NewRFC3161Client("http://tsa.example.com", custom)
	require.NoError(t, err)
	assert.Same(t, custom, client.http)
}

func TestNewRFC3161Client_InvalidURL(t *testing.T) {
	for _, tsaURL := range []string{"", "tsa.example.com", "ftp://tsa.example.com", "https://", "http://[::1"} {
		client, err := NewRFC3161Client(tsaURL, nil)
		require.ErrorIs(t, err, ErrTimestampURLInvalid, tsaURL)
		assert.Nil(t, client)
	}
}

func TestRFC3161Client_Timestamp(t *testing.T) {
	pki := newTestPKI(t)
	tsa := newTestTSA(t, pki, tsaConfig{})
	data := []byte("signature")

	response, err := tsa.client(t).Timestamp(t.Context(), data)
	require.NoError(t, err)

	info, err := VerifyTimestamp(response, data, pki.pool)
	require.NoError(t, err)
	assert.Equal(t, tsa.certificate.Raw, info.Certificate.Raw)
	assert.WithinDuration(t, time.Now(), info.Time, time.Minute)
	assert.Equal(t, big.NewInt(1), info.SerialNumber)
}

func TestRFC3161Client_Timestamp_NoData(t *testing.T) {
	client, err := NewRFC3161Client("https://tsa.example.com", nil)
	require.NoError(t, err)

	response, err := client.Timestamp(t.Context(), nil)
	require.ErrorIs(t, err, ErrTimestampDataRequired)
	assert.Nil(t, response)
}

func TestRFC3161Client_Timestamp_Errors(t *testing.T) {
	pki := newTestPKI(t)
	tsa := func(config tsaConfig) func(t *testing.T) string {
		return func(t *testing.T) string {
			return newTestTSA(t, pki, config).server.URL
		}
	}
	answering := func(status int, body []byte) func(t *testing.T) string {
		return func(t *testing.T) string {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				if _, err := w.Write(body); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			t.Cleanup(server.Close)
			return server.URL
		}
	}
	closed := func(t *testing.T) string {
		server := httptest.NewServer(http.NotFoundHandler())
		server.Close()
		return server.URL
	}

	tests := []struct {
		name string
		url  func(t *testing.T) string
		err  error
	}{
		{name: "rejected", url: tsa(tsaConfig{status: 2}), err: ErrTimestampRejected},
		{
			name: "nonce changed",
			url:  tsa(tsaConfig{tamper: func(info *tstInfo) { info.Nonce = new(big.Int).Add(info.Nonce, big.NewInt(1)) }}),
			err:  ErrTimestampMismatch,
		},
		{name: "nonce dropped", url: tsa(tsaConfig{tamper: func(info *tstInfo) { info.Nonce = nil }}), err: ErrTimestampMismatch},
		{
			name: "imprint of other data",
			url:  tsa(tsaConfig{tamper: func(info *tstInfo) { info.MessageImprint.HashedMessage = sha256Sum([]byte("other")) }}),
			err:  ErrTimestampMismatch,
		},
		{name: "server error", url: answering(http.StatusInternalServerError, nil), err: ErrTimestampFailed},
		{name: "not a timestamp response", url: answering(http.StatusOK, []byte("garbage")), err: ErrInvalidTimestamp},
		{name: "response too large", url: answering(http.StatusOK, make([]byte, maxTimestampSize+1)), err: ErrResponseTooLarge},
		{name: "unreachable", url: closed, err: ErrTimestampFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewRFC3161Client(tt.url(t), nil)
			require.NoError(t, err)

			response, err := client.Timestamp(t.Context(), []byte("signature"))
			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, response)
		})
	}
}

func TestVerifyTimestamp(t *testing.T) {
	pki := newTestPKI(t)
	data := []byte("signature")
	genTime := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name string
		key  crypto.Signer
		opts tokenOptions
	}{
		{name: "ecdsa", key: newECDSAKey(t)},
		{name: "rsa", key: newRSAKey(t)},
		{name: "rsa encryption signature algorithm", key: newRSAKey(t), opts: tokenOptions{signatureAlgorithm: oidRSAEncryption}},
		{name: "sha512 signer digest", key: newECDSAKey(t), opts: tokenOptions{digestAlgorithm: oidSHA512, signatureAlgorithm: oidECDSAWithSHA512}},
		{name: "subject key identifier", key: newECDSAKey(t), opts: tokenOptions{keyIdentifier: true}},
		{name: "granted with modifications", key: newECDSAKey(t), opts: tokenOptions{status: pkiStatusGrantedWithMods}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certificate := pki.timestamping(t, tt.key.Public())
			response, err := timestampResponse(tt.key, certificate, newTSTInfo(data, genTime), &tt.opts)
			require.NoError(t, err)

			info, err := VerifyTimestamp(response, data, pki.pool)
			require.NoError(t, err)
			assert.True(t, genTime.Equal(info.Time), "the token's genTime")
			assert.Equal(t, big.NewInt(7), info.SerialNumber)
			assert.Equal(t, certificate.Raw, info.Certificate.Raw)
		})
	}
}

// TestCheckTimestampingUsage_CAProfile pins the seam between the CA and the
// verifier: a certificate issued under pkg/ca's timestamping profile meets
// RFC 3161 section 2.3, and the same certificate without the profile's
// critical extension does not.
func TestCheckTimestampingUsage_CAProfile(t *testing.T) {
	pki := newTestPKI(t)
	key := newECDSAKey(t)

	assert.NoError(t, checkTimestampingUsage(pki.timestamping(t, key.Public())))

	derived := pki.issue(t, key.Public(), &x509.Certificate{
		Subject:     pkix.Name{CommonName: "image tsa"},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	assert.ErrorIs(t, checkTimestampingUsage(derived), ErrTimestampExtKeyUsage)
}

func TestVerifyTimestamp_Intermediate(t *testing.T) {
	pki := newTestPKI(t)
	intermediateKey := newECDSAKey(t)
	intermediate := &testPKI{key: intermediateKey, certificate: pki.issue(t, intermediateKey.Public(), &x509.Certificate{
		Subject:               pkix.Name{CommonName: "image test intermediate"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})}
	key := newECDSAKey(t)
	certificate := intermediate.timestamping(t, key.Public())
	data := []byte("signature")

	response, err := timestampResponse(key, certificate, newTSTInfo(data, time.Now()), &tokenOptions{
		certificates: []*x509.Certificate{certificate, intermediate.certificate},
	})
	require.NoError(t, err)
	info, err := VerifyTimestamp(response, data, pki.pool)
	require.NoError(t, err)
	assert.Equal(t, certificate.Raw, info.Certificate.Raw)

	response, err = timestampResponse(key, certificate, newTSTInfo(data, time.Now()), &tokenOptions{})
	require.NoError(t, err)
	info, err = VerifyTimestamp(response, data, pki.pool)
	require.ErrorIs(t, err, ErrTimestampUntrusted, "the token must carry the intermediate")
	assert.Nil(t, info)
}

func TestVerifyTimestamp_MissingInputs(t *testing.T) {
	info, err := VerifyTimestamp([]byte("response"), []byte("signature"), nil)
	require.ErrorIs(t, err, ErrTimestampRootsRequired)
	assert.Nil(t, info)

	info, err = VerifyTimestamp([]byte("response"), nil, x509.NewCertPool())
	require.ErrorIs(t, err, ErrTimestampDataRequired)
	assert.Nil(t, info)
}

func TestVerifyTimestamp_Errors(t *testing.T) {
	pki := newTestPKI(t)
	key := newECDSAKey(t)
	certificate := pki.timestamping(t, key.Public())
	otherKey := newECDSAKey(t)
	untrusted := newTestPKI(t).timestamping(t, otherKey.Public())
	// serverAuth shares certificate's issuer but neither its serial number
	// nor its subject key identifier.
	serverAuth := pki.issue(t, key.Public(), &x509.Certificate{
		Subject:     pkix.Name{CommonName: "not a tsa"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	// tsa issues a certificate for key that chains to the trusted root but
	// whose extended key usage is not RFC 3161's.
	tsa := func(name string, extensions ...pkix.Extension) *x509.Certificate {
		return pki.issue(t, key.Public(), &x509.Certificate{
			Subject:         pkix.Name{CommonName: name},
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtraExtensions: extensions,
			SubjectKeyId:    []byte("image tsa key"),
		})
	}
	noExtKeyUsage := tsa("no eku")
	nonCritical := tsa("non-critical eku", extKeyUsageExtension(t, false, oidKPTimeStamping))
	extraUsage := tsa("two ekus", extKeyUsageExtension(t, true, oidKPTimeStamping, oidKPServerAuth))

	tests := []struct {
		name        string
		signer      crypto.Signer
		certificate *x509.Certificate
		tamper      func(info *tstInfo)
		opts        tokenOptions
		data        string
		err         error
	}{
		{name: "untrusted root", signer: otherKey, certificate: untrusted, err: ErrTimestampUntrusted},
		{name: "not a timestamping certificate", certificate: serverAuth, err: ErrTimestampExtKeyUsage},
		{name: "no extended key usage", certificate: noExtKeyUsage, err: ErrTimestampExtKeyUsage},
		{name: "non-critical extended key usage", certificate: nonCritical, err: ErrTimestampExtKeyUsage},
		{name: "extended key usage beside timestamping", certificate: extraUsage, err: ErrTimestampExtKeyUsage},
		{
			name:   "after the certificate expired",
			tamper: func(info *tstInfo) { info.GenTime = info.GenTime.Add(30 * time.Hour) },
			err:    ErrTimestampUntrusted,
		},
		{name: "other data", data: "other", err: ErrTimestampMismatch},
		{
			name:   "sha1 imprint",
			tamper: func(info *tstInfo) { info.MessageImprint.HashAlgorithm.Algorithm = oidSHA1 },
			err:    ErrUnsupportedAlgorithm,
		},
		{name: "message digest attribute", opts: tokenOptions{messageDigest: []byte("wrong")}, err: ErrTimestampSignatureInvalid},
		{name: "content type attribute", opts: tokenOptions{contentType: oidSignedData}, err: ErrInvalidTimestamp},
		{name: "no signed attributes", opts: tokenOptions{noSignedAttributes: true}, err: ErrInvalidTimestamp},
		{name: "two signers", opts: tokenOptions{signers: 2}, err: ErrInvalidTimestamp},
		{name: "sha1 signer digest", opts: tokenOptions{digestAlgorithm: oidSHA1}, err: ErrUnsupportedAlgorithm},
		{name: "signature algorithm of another key type", opts: tokenOptions{signatureAlgorithm: oidSHA256WithRSA}, err: ErrUnsupportedAlgorithm},
		{name: "signer certificate missing", opts: tokenOptions{certificates: []*x509.Certificate{serverAuth}}, err: ErrInvalidTimestamp},
		{
			name: "signer key identifier missing",
			opts: tokenOptions{keyIdentifier: true, certificates: []*x509.Certificate{serverAuth}},
			err:  ErrInvalidTimestamp,
		},
		{name: "signed by another key", signer: otherKey, err: ErrTimestampSignatureInvalid},
		{name: "rejected", opts: tokenOptions{status: 2}, err: ErrTimestampRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, signerCertificate, data := crypto.Signer(key), certificate, []byte("signature")
			if tt.signer != nil {
				signer = tt.signer
			}
			if tt.certificate != nil {
				signerCertificate = tt.certificate
			}
			info := newTSTInfo(data, time.Now())
			if tt.tamper != nil {
				tt.tamper(info)
			}
			if tt.data != "" {
				data = []byte(tt.data)
			}
			response, err := timestampResponse(signer, signerCertificate, info, &tt.opts)
			require.NoError(t, err)

			verified, err := VerifyTimestamp(response, data, pki.pool)
			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, verified)
		})
	}
}

func TestVerifyTimestamp_Malformed(t *testing.T) {
	pki := newTestPKI(t)
	key := newECDSAKey(t)
	data := []byte("signature")
	valid, err := timestampResponse(key, pki.timestamping(t, key.Public()), newTSTInfo(data, time.Now()), &tokenOptions{})
	require.NoError(t, err)

	noToken, err := asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: pkiStatusGranted}})
	require.NoError(t, err)
	notSignedData, err := asn1.Marshal(contentInfo{
		ContentType: oidTSTInfo,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x05, 0x00}},
	})
	require.NoError(t, err)
	wrongContent, err := asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: pkiStatusGranted},
		TimeStampToken: asn1.RawValue{FullBytes: notSignedData},
	})
	require.NoError(t, err)

	for name, response := range map[string][]byte{
		"garbage":         []byte("garbage"),
		"trailing data":   append(valid, 0x00),
		"no token":        noToken,
		"not signed data": wrongContent,
	} {
		t.Run(name, func(t *testing.T) {
			info, err := VerifyTimestamp(response, data, pki.pool)
			require.ErrorIs(t, err, ErrInvalidTimestamp)
			assert.Nil(t, info)
		})
	}
}
