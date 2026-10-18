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

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errFakeTransport = errors.New("fake transport failure")

// fakeCAClient answers the four certificate authority calls XKMSdCA makes.
// The embedded transport.Client is nil: any other call panics, which proves
// the adapter reaches nothing beyond its contract.
type fakeCAClient struct {
	transport.Client

	signResp    *transport.SignCSRResponse
	caResp      *transport.GetCACertificateResponse
	revokeResp  *transport.RevokeCertificateResponse
	revokedResp *transport.IsRevokedResponse
	err         error

	lastSign   *transport.SignCSRRequest
	lastRevoke *transport.RevokeCertificateRequest
	lastCheck  *transport.IsRevokedRequest
	closed     bool
}

func (f *fakeCAClient) SignCSR(_ context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	f.lastSign = req
	return f.signResp, f.err
}

func (f *fakeCAClient) GetCACertificate(context.Context, *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return f.caResp, f.err
}

func (f *fakeCAClient) RevokeCertificate(_ context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	f.lastRevoke = req
	return f.revokeResp, f.err
}

func (f *fakeCAClient) IsRevoked(_ context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	f.lastCheck = req
	return f.revokedResp, f.err
}

func (f *fakeCAClient) Close() error {
	f.closed = true
	return nil
}

func newTestXKMSdCA(t *testing.T, client *fakeCAClient, profile string, validityDays int) *XKMSdCA {
	t.Helper()
	ca, err := NewXKMSdCA(client, profile, validityDays)
	if err != nil {
		t.Fatalf("NewXKMSdCA: %v", err)
	}
	return ca
}

func TestNewXKMSdCA_DefaultsTheProfile(t *testing.T) {
	client := &fakeCAClient{signResp: &transport.SignCSRResponse{CertificatePEM: []byte("leaf")}}
	ca := newTestXKMSdCA(t, client, "", 0)

	if _, err := ca.SignCSR([]byte("csr")); err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if client.lastSign.Profile != CertProfileDefault {
		t.Errorf("profile = %q, want %q", client.lastSign.Profile, CertProfileDefault)
	}
}

func TestNewXKMSdCA_NilClient(t *testing.T) {
	if _, err := NewXKMSdCA(nil, CertProfileDefault, 0); !errors.Is(err, ErrNilClient) {
		t.Fatalf("NewXKMSdCA(nil) = %v, want ErrNilClient", err)
	}
}

func TestXKMSdCA_SignCSR_ReturnsLeafThenChain(t *testing.T) {
	client := &fakeCAClient{signResp: &transport.SignCSRResponse{
		CertificatePEM: []byte("leaf|"),
		ChainPEM:       []byte("issuer"),
	}}
	ca := newTestXKMSdCA(t, client, "server", 7)

	certPEM, err := ca.SignCSR([]byte("csr"))
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if string(certPEM) != "leaf|issuer" {
		t.Errorf("certificate = %q, want leaf then chain", certPEM)
	}
	if string(client.lastSign.CSRPEM) != "csr" || client.lastSign.Profile != "server" || client.lastSign.ValidityDays != 7 {
		t.Errorf("sign request = %+v, want the CSR, profile and validity passed through", client.lastSign)
	}
}

func TestXKMSdCA_SignCSR_Failures(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeCAClient
		want   error
	}{
		{"authority rejects", &fakeCAClient{err: errFakeTransport}, ErrCASignFailed},
		{"no certificate", &fakeCAClient{signResp: &transport.SignCSRResponse{}}, ErrCAEmptyResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newTestXKMSdCA(t, tt.client, "", 0)
			if _, err := ca.SignCSR([]byte("csr")); !errors.Is(err, tt.want) {
				t.Fatalf("SignCSR = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestXKMSdCA_GetCACertificate(t *testing.T) {
	ca := newTestXKMSdCA(t, &fakeCAClient{caResp: &transport.GetCACertificateResponse{CertificatePEM: []byte("root")}}, "", 0)

	certPEM, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("GetCACertificate: %v", err)
	}
	if string(certPEM) != "root" {
		t.Errorf("CA certificate = %q, want root", certPEM)
	}
}

func TestXKMSdCA_GetCACertificate_Failures(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeCAClient
		want   error
	}{
		{"authority fails", &fakeCAClient{err: errFakeTransport}, ErrCACertFailed},
		{"no certificate", &fakeCAClient{caResp: &transport.GetCACertificateResponse{}}, ErrCAEmptyResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newTestXKMSdCA(t, tt.client, "", 0)
			if _, err := ca.GetCACertificate(); !errors.Is(err, tt.want) {
				t.Fatalf("GetCACertificate = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestXKMSdCA_RevokeCertificate_RecordsCessationOfOperation(t *testing.T) {
	client := &fakeCAClient{revokeResp: &transport.RevokeCertificateResponse{Success: true}}
	ca := newTestXKMSdCA(t, client, "", 0)

	if err := ca.RevokeCertificate("0a0b"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if client.lastRevoke.SerialNumber != "0a0b" || client.lastRevoke.Reason != RevocationReasonCessationOfOperation {
		t.Errorf("revoke request = %+v, want serial 0a0b with reason %d", client.lastRevoke, RevocationReasonCessationOfOperation)
	}
}

func TestXKMSdCA_RevokeCertificate_Failures(t *testing.T) {
	tests := []struct {
		name    string
		client  *fakeCAClient
		message string
	}{
		{"transport fails", &fakeCAClient{err: errFakeTransport}, errFakeTransport.Error()},
		{"authority refuses with a reason", &fakeCAClient{revokeResp: &transport.RevokeCertificateResponse{Message: "unknown serial"}}, "unknown serial"},
		{"authority refuses silently", &fakeCAClient{revokeResp: &transport.RevokeCertificateResponse{}}, "reported failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newTestXKMSdCA(t, tt.client, "", 0)
			err := ca.RevokeCertificate("0a0b")
			if !errors.Is(err, ErrCARevokeFailed) {
				t.Fatalf("RevokeCertificate = %v, want ErrCARevokeFailed", err)
			}
			if !strings.Contains(err.Error(), tt.message) {
				t.Errorf("error %q does not carry %q", err, tt.message)
			}
		})
	}
}

func TestXKMSdCA_IsRevoked(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		client := &fakeCAClient{revokedResp: &transport.IsRevokedResponse{Revoked: revoked}}
		ca := newTestXKMSdCA(t, client, "", 0)

		got, err := ca.IsRevoked("0a0b")
		if err != nil {
			t.Fatalf("IsRevoked: %v", err)
		}
		if got != revoked || client.lastCheck.SerialNumber != "0a0b" {
			t.Errorf("IsRevoked = %v for serial %q, want %v for 0a0b", got, client.lastCheck.SerialNumber, revoked)
		}
	}
}

func TestXKMSdCA_IsRevoked_FailsClosed(t *testing.T) {
	ca := newTestXKMSdCA(t, &fakeCAClient{err: errFakeTransport}, "", 0)

	revoked, err := ca.IsRevoked("0a0b")
	if !errors.Is(err, ErrCARevocationCheckFailed) {
		t.Fatalf("IsRevoked = %v, want ErrCARevocationCheckFailed", err)
	}
	if revoked {
		t.Error("an indeterminate revocation check reported revoked=true alongside its error")
	}
}

func TestXKMSdCA_Close_ReleasesTheClient(t *testing.T) {
	client := &fakeCAClient{}
	ca := newTestXKMSdCA(t, client, "", 0)

	if err := ca.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !client.closed {
		t.Error("Close did not release the transport client")
	}
}
