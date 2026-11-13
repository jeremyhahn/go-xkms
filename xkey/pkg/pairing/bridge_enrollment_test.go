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

package pairing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// These tests cover what happens either side of BridgeConfig.TPM being set.
// The production defect they guard is a Bridge built without a TPM: the
// enrollment handlers then report the feature as unavailable no matter what
// the host actually has, and nothing else about the bridge may break as a
// result.

// fakeEnroller is a TPMEnroller that answers from canned material, so the
// pass-through from BridgeConfig.TPM into the handlers can be observed without
// a TPM. The simulator test in bridge_enrollment_simulator_test.go covers the
// real cryptography.
type fakeEnroller struct {
	ekCert     *x509.Certificate
	ekCertErr  error
	iak        *types.KeyAttributes
	idevid     *types.KeyAttributes
	csr        tpm2.TCG_CSR_IDEVID
	csrErr     error
	props      *tpm2.PropertiesFixed
	secret     []byte
	quote      tpm2.Quote
	activateIn [][]byte
}

func (f *fakeEnroller) EKCertificate() (*x509.Certificate, error) {
	return f.ekCert, f.ekCertErr
}

func (f *fakeEnroller) IAKAttributes() (*types.KeyAttributes, error) { return f.iak, nil }

func (f *fakeEnroller) IDevIDAttributes() (*types.KeyAttributes, error) { return f.idevid, nil }

func (f *fakeEnroller) CreateTCG_CSR_IDEVID(
	_ *x509.Certificate,
	_ *types.KeyAttributes,
	_ *types.KeyAttributes) (tpm2.TCG_CSR_IDEVID, error) {
	return f.csr, f.csrErr
}

func (f *fakeEnroller) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	f.activateIn = [][]byte{credentialBlob, encryptedSecret}
	return f.secret, nil
}

func (f *fakeEnroller) Quote(_ []uint, _ []byte) (tpm2.Quote, error) { return f.quote, nil }

func (f *fakeEnroller) FixedProperties() (*tpm2.PropertiesFixed, error) { return f.props, nil }

func (f *fakeEnroller) ProvisionIAKCert(_ *x509.Certificate) error { return nil }

func (f *fakeEnroller) ProvisionIDevIDCert(_ *x509.Certificate) error { return nil }

var _ TPMEnroller = (*fakeEnroller)(nil)

// fakeKeyAttributes returns key attributes carrying a non-empty TPM2B_PUBLIC,
// which is what the handlers read out as the IAK / IDevID public area.
func fakeKeyAttributes(t *testing.T) *types.KeyAttributes {
	t.Helper()

	unique := gotpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)}
	public := gotpm2.TPMTPublic{
		Type:    gotpm2.TPMAlgRSA,
		NameAlg: gotpm2.TPMAlgSHA256,
		ObjectAttributes: gotpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: gotpm2.NewTPMUPublicParms(gotpm2.TPMAlgRSA, &gotpm2.TPMSRSAParms{KeyBits: 2048}),
		Unique:     gotpm2.NewTPMUPublicID(gotpm2.TPMAlgRSA, &unique),
	}

	return &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public:  public,
			BPublic: gotpm2.New2B(public),
		},
	}
}

// fakeCertificate returns a throwaway self-signed certificate.
func fakeCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newFakeEnroller returns an enroller wired with everything the enrollment
// handlers read.
func newFakeEnroller(t *testing.T) *fakeEnroller {
	t.Helper()

	return &fakeEnroller{
		ekCert: fakeCertificate(t),
		iak:    fakeKeyAttributes(t),
		idevid: fakeKeyAttributes(t),
		props:  &tpm2.PropertiesFixed{Manufacturer: "ATT"},
		secret: []byte("recovered-secret"),
	}
}

// TestBridge_EnrollmentReachesTheConfiguredTPM is the regression test for the
// defect: with BridgeConfig.TPM set, the enrollment methods must reach that
// TPM rather than reporting the feature as unconfigured.
func TestBridge_EnrollmentReachesTheConfiguredTPM(t *testing.T) {
	enroller := newFakeEnroller(t)

	bridge, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger: testLogger(),
		TPM:    enroller,
	})
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		params interface{}
		verify func(t *testing.T, resp *pairingproto.Response)
	}{
		{
			name:   "getTCGCSRIDevID",
			method: pairingproto.MethodRemoteGetTCGCSRIDevID,
			params: pairingproto.RemoteGetTCGCSRIDevIDParams{Backend: "tpm2"},
			verify: func(t *testing.T, resp *pairingproto.Response) {
				res := decodeResult[pairingproto.RemoteGetTCGCSRIDevIDResult](t, resp)
				assert.Equal(t, "ATT", res.PlatformManufacturer)
				assert.NotEmpty(t, res.IAKPublicKey)
				assert.NotEmpty(t, res.IDevIDPublicKey)
				assert.Equal(t, enroller.ekCert.Raw, res.EKCert)
			},
		},
		{
			name:   "activateCredential",
			method: pairingproto.MethodRemoteActivateCredential,
			params: pairingproto.RemoteActivateCredentialParams{
				Backend:         "tpm2",
				CredentialBlob:  []byte("blob"),
				EncryptedSecret: []byte("secret"),
			},
			verify: func(t *testing.T, resp *pairingproto.Response) {
				res := decodeResult[pairingproto.RemoteActivateCredentialResult](t, resp)
				assert.Equal(t, []byte("recovered-secret"), res.DecryptedSecret)
				assert.Equal(t, [][]byte{[]byte("blob"), []byte("secret")}, enroller.activateIn,
					"the challenge must reach the TPM unchanged")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRemoteRequest(tt.method, tt.params)
			resp := bridge.HandleRequest(context.Background(), req)
			require.Nil(t, resp.Error, "a configured TPM must answer %s", tt.method)
			tt.verify(t, resp)
		})
	}
}

// TestBridge_WithoutATPMEverythingElseStillWorks proves the cost of having no
// TPM is confined to enrollment. A laptop without one must still pair and
// serve the rest of the remote.* method set.
func TestBridge_WithoutATPMEverythingElseStillWorks(t *testing.T) {
	client := &mockTransportClient{
		listBackendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{{ID: "software", Type: "software"}},
		},
	}
	bridge, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	enrollment := []string{
		pairingproto.MethodRemoteGetTCGCSRIDevID,
		pairingproto.MethodRemoteActivateCredential,
		pairingproto.MethodRemoteGetAttestationQuote,
	}
	for _, method := range enrollment {
		t.Run(method+" reports unavailable", func(t *testing.T) {
			req := newRemoteRequest(method, map[string]any{"backend": "tpm2"})
			resp := bridge.HandleRequest(context.Background(), req)
			require.NotNil(t, resp.Error)
			assert.Equal(t, pairingproto.ErrorCodeAttestUnsupported, resp.Error.Code)
		})
	}

	t.Run("listBackends still works", func(t *testing.T) {
		req := newRemoteRequest(pairingproto.MethodRemoteListBackends, nil)
		resp := bridge.HandleRequest(context.Background(), req)
		result := decodeResult[pairingproto.RemoteListBackendsResult](t, resp)
		assert.Len(t, result.Backends, 1, "an absent TPM must not disable the rest of the bridge")
	})
}

// TestMapErrorToRPC_TPMStates pins the wire distinction the phone relies on to
// tell the user whether this laptop has no TPM at all, or has one xkey cannot
// reach.
func TestMapErrorToRPC_TPMStates(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{
			name:     "no TPM is a missing capability",
			err:      pairingproto.ErrTPMNotConfigured,
			wantCode: pairingproto.ErrorCodeAttestUnsupported,
		},
		{
			name:     "an unreachable TPM is a failure the operator can fix",
			err:      pairingproto.ErrTPMUnavailable,
			wantCode: pairingproto.ErrorCodeAttestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, message := mapErrorToRPC(tt.err)
			assert.Equal(t, tt.wantCode, code)
			assert.NotEmpty(t, message)
		})
	}

	// The two must not collapse onto the same message, or the phone cannot
	// tell the user which of the two situations it is looking at.
	_, absent := mapErrorToRPC(pairingproto.ErrTPMNotConfigured)
	_, unreachable := mapErrorToRPC(pairingproto.ErrTPMUnavailable)
	assert.NotEqual(t, absent, unreachable)
	assert.False(t, errors.Is(pairingproto.ErrTPMUnavailable, pairingproto.ErrTPMNotConfigured))
}

// TestBridge_UnopenableTPM_IsReportedDistinctlyFromNoTPM proves the phone can
// tell "this laptop has no TPM" from "this laptop has one xkey cannot reach".
//
// The two are the same to the enrollment handlers — b.tpm is nil either way —
// so without the recorded open failure an operator-fixable permission problem
// on /dev/tpmrm0 is indistinguishable from hardware that does not exist. That
// distinction is the entire point of ErrTPMUnavailable.
func TestBridge_UnopenableTPM_IsReportedDistinctlyFromNoTPM(t *testing.T) {
	openErr := errors.New("open /dev/tpmrm0: permission denied")

	unreachable, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:     testLogger(),
		TPMOpenErr: openErr,
	})
	require.NoError(t, err)

	absent, err := NewBridge(&mockTransportClient{}, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	_, unreachableErr := unreachable.enroller()
	require.Error(t, unreachableErr)
	assert.ErrorIs(t, unreachableErr, pairingproto.ErrTPMUnavailable)
	assert.ErrorIs(t, unreachableErr, openErr, "the cause must survive for the operator")
	assert.NotErrorIs(t, unreachableErr, pairingproto.ErrTPMNotConfigured)

	_, absentErr := absent.enroller()
	assert.ErrorIs(t, absentErr, pairingproto.ErrTPMNotConfigured)
	assert.NotErrorIs(t, absentErr, pairingproto.ErrTPMUnavailable)

	// And they must reach the phone as different codes.
	unreachableCode, _ := mapErrorToRPC(unreachableErr)
	absentCode, _ := mapErrorToRPC(absentErr)
	assert.Equal(t, pairingproto.ErrorCodeAttestFailed, unreachableCode)
	assert.Equal(t, pairingproto.ErrorCodeAttestUnsupported, absentCode)
	assert.NotEqual(t, unreachableCode, absentCode)
}

// TestMapErrorToRPC_MatchesWrappedCauses guards the identity-comparison bug:
// the handlers wrap their causes, and a `switch err` silently dropped every
// wrapped error through to ErrorCodeInternalError. Observed on real hardware,
// where an unprovisioned IAK reported -32603 instead of an attestation code.
func TestMapErrorToRPC_MatchesWrappedCauses(t *testing.T) {
	wrapped := tpmError(errors.New("TPM_RC_HANDLE"))

	code, _ := mapErrorToRPC(wrapped)

	assert.Equal(t, pairingproto.ErrorCodeAttestFailed, code,
		"a wrapped TPM failure must keep its attestation code")
	assert.NotEqual(t, pairingproto.ErrorCodeInternalError, code)
}
