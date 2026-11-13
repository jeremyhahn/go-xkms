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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// errPIVSignTransportFailureForTest is a plain, unregistered error used to
// verify that handlePIVSign wraps arbitrary transport failures as
// ErrPIVSignFailed instead of leaking whatever the transport happened to
// return (or matching some unrelated sentinel by coincidence).
var errPIVSignTransportFailureForTest = errors.New("test: transport sign failure")

// fakePIVStorage is an in-memory xkms.PIVCertificateStorage used to exercise
// the bridge's remote.piv* handlers end to end without a real TPM/PKCS#11
// backend.
type fakePIVStorage struct {
	certs  map[xkms.PIVSlot]*x509.Certificate
	closed bool
}

func newFakePIVStorage() *fakePIVStorage {
	return &fakePIVStorage{certs: make(map[xkms.PIVSlot]*x509.Certificate)}
}

func (f *fakePIVStorage) Store(slot xkms.PIVSlot, cert *x509.Certificate) error {
	f.certs[slot] = cert
	return nil
}

func (f *fakePIVStorage) Retrieve(slot xkms.PIVSlot) (*x509.Certificate, error) {
	cert, ok := f.certs[slot]
	if !ok {
		return nil, xkms.ErrPIVCertificateNotFound
	}
	return cert, nil
}

func (f *fakePIVStorage) Delete(slot xkms.PIVSlot) error {
	delete(f.certs, slot)
	return nil
}

func (f *fakePIVStorage) List() ([]xkms.PIVSlotInfo, error) {
	infos := make([]xkms.PIVSlotInfo, 0, len(f.certs))
	for slot, cert := range f.certs {
		infos = append(infos, xkms.PIVSlotInfo{
			Slot:      slot,
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			Algorithm: "ECDSA",
		})
	}
	return infos, nil
}

func (f *fakePIVStorage) Import(slot xkms.PIVSlot, data []byte, _ xkms.PIVCertFormat) error {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return err
	}
	f.certs[slot] = cert
	return nil
}

func (f *fakePIVStorage) Export(slot xkms.PIVSlot, _ xkms.PIVCertFormat) ([]byte, error) {
	cert, ok := f.certs[slot]
	if !ok {
		return nil, xkms.ErrPIVCertificateNotFound
	}
	return cert.Raw, nil
}

func (f *fakePIVStorage) Close() error {
	f.closed = true
	return nil
}

func (f *fakePIVStorage) Type() xkms.PIVStorageType {
	return xkms.PIVStorageTypeFile
}

// newTestPIVCertificate returns a minimal self-signed certificate usable as
// fixture data for PIV storage tests.
func newTestPIVCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsPIVMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	pivMethods := []string{
		pairingproto.MethodRemotePIVListSlots,
		pairingproto.MethodRemotePIVSign,
		pairingproto.MethodRemotePIVGetCert,
	}

	for _, method := range pivMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for PIV method %s", method)
	}
}

// --- handlePIVListSlots tests ---

// TestBridge_HandlePIVListSlots_NotConfigured verifies that without a
// PIVStorageProvider wired into the Bridge, remote.pivListSlots reports the
// feature as unavailable rather than an empty-but-successful list.
func TestBridge_HandlePIVListSlots_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVListSlots, pairingproto.RemotePIVListSlotsParams{
		Backend: "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeFeatureUnavailable)
}

// TestBridge_HandlePIVListSlots_Success verifies the real round trip through
// the dispatch path: a certificate stored in the fake PIV storage is
// reported back with its metadata, and HasKey reflects Client.ListKeys.
func TestBridge_HandlePIVListSlots_Success(t *testing.T) {
	storage := newFakePIVStorage()
	cert := newTestPIVCertificate(t, "Authentication")
	require.NoError(t, storage.Store(xkms.PIVSlot(pairingproto.PIVSlotAuthentication), cert))

	client := &mockTransportClient{
		listKeysResp: &transport.ListKeysResponse{
			Keys: []transport.KeyInfo{{KeyID: pairingproto.PIVSlotAuthentication, Backend: "software"}},
		},
	}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:     testLogger(),
		PIVStorage: func(string) (xkms.PIVCertificateStorage, error) { return storage, nil },
	})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVListSlots, pairingproto.RemotePIVListSlotsParams{
		Backend: "software",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[pairingproto.RemotePIVListSlotsResult](t, resp)
	require.Len(t, result.Slots, 1)
	assert.Equal(t, pairingproto.PIVSlotAuthentication, result.Slots[0].Slot)
	assert.True(t, result.Slots[0].HasCertificate)
	assert.True(t, result.Slots[0].HasKey)
	assert.Equal(t, "Authentication", result.Slots[0].CertSubject)
	assert.True(t, storage.closed, "bridge must close storage it opened for the request")
}

// TestBridge_HandlePIVListSlots_NilParams verifies nil/empty params are
// accepted gracefully (defaulting the backend) when storage is configured.
func TestBridge_HandlePIVListSlots_NilParams(t *testing.T) {
	storage := newFakePIVStorage()
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:     testLogger(),
		PIVStorage: func(string) (xkms.PIVCertificateStorage, error) { return storage, nil },
	})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVListSlots, nil)
	resp := b.HandleRequest(context.Background(), req)

	require.Nil(t, resp.Error, "expected success but got error: %v", resp.Error)
	result := decodeResult[pairingproto.RemotePIVListSlotsResult](t, resp)
	assert.Empty(t, result.Slots)
}

func TestBridge_HandlePIVListSlots_EmptyParams(t *testing.T) {
	storage := newFakePIVStorage()
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:     testLogger(),
		PIVStorage: func(string) (xkms.PIVCertificateStorage, error) { return storage, nil },
	})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVListSlots, pairingproto.RemotePIVListSlotsParams{})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[pairingproto.RemotePIVListSlotsResult](t, resp)
	assert.Empty(t, result.Slots)
}

// --- handlePIVSign tests ---

// TestBridge_HandlePIVSign_Success verifies the real round trip through the
// dispatch path: remote.pivSign addresses the PIV slot's key as
// Backend+KeyID==slot through Client.Sign, exactly like remote.sign.
func TestBridge_HandlePIVSign_Success(t *testing.T) {
	expectedSig := []byte("piv-signature-bytes")
	client := &mockTransportClient{
		signResp: &transport.SignResponse{
			Signature: expectedSig,
			Algorithm: "SHA256withECDSA",
		},
	}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVSign, pairingproto.RemotePIVSignParams{
		Slot:      pairingproto.PIVSlotAuthentication,
		Data:      []byte("data to sign"),
		Algorithm: "SHA256withECDSA",
		Backend:   "software",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[pairingproto.RemotePIVSignResult](t, resp)
	assert.Equal(t, expectedSig, result.Signature)
	assert.Equal(t, "SHA256withECDSA", result.Algorithm)
}

// TestBridge_HandlePIVSign_TransportFailure verifies that a signing failure
// from the key backend is reported as a PIV-specific sign failure, not a
// fabricated signature.
func TestBridge_HandlePIVSign_TransportFailure(t *testing.T) {
	client := &mockTransportClient{signErr: errPIVSignTransportFailureForTest}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVSign, pairingproto.RemotePIVSignParams{
		Slot: pairingproto.PIVSlotAuthentication,
		Data: []byte("data to sign"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodePIVSignFailed)
}

func TestBridge_HandlePIVSign_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(pairingproto.MethodRemotePIVSign, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandlePIVSign_EmptySlot(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVSign, pairingproto.RemotePIVSignParams{
		Data: []byte("data to sign"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodePIVInvalidSlot)
}

func TestBridge_HandlePIVSign_EmptyData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVSign, pairingproto.RemotePIVSignParams{
		Slot: pairingproto.PIVSlotAuthentication,
		Data: []byte{},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

// --- handlePIVGetCert tests ---

// TestBridge_HandlePIVGetCert_NotConfigured verifies that without a
// PIVStorageProvider wired into the Bridge, remote.pivGetCert reports the
// feature as unavailable rather than a nil-but-successful certificate.
func TestBridge_HandlePIVGetCert_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVGetCert, pairingproto.RemotePIVGetCertParams{
		Slot:    pairingproto.PIVSlotAuthentication,
		Backend: "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeFeatureUnavailable)
}

// TestBridge_HandlePIVGetCert_Success verifies the real round trip through
// the dispatch path: a certificate stored in the fake PIV storage is
// returned with its DER bytes and metadata.
func TestBridge_HandlePIVGetCert_Success(t *testing.T) {
	storage := newFakePIVStorage()
	cert := newTestPIVCertificate(t, "Authentication")
	require.NoError(t, storage.Store(xkms.PIVSlot(pairingproto.PIVSlotAuthentication), cert))

	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:     testLogger(),
		PIVStorage: func(string) (xkms.PIVCertificateStorage, error) { return storage, nil },
	})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVGetCert, pairingproto.RemotePIVGetCertParams{
		Slot:    pairingproto.PIVSlotAuthentication,
		Backend: "software",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[pairingproto.RemotePIVGetCertResult](t, resp)
	assert.Equal(t, cert.Raw, result.CertificateDER)
	assert.Contains(t, result.Subject, "Authentication")
	assert.True(t, storage.closed)
}

// TestBridge_HandlePIVGetCert_NotFound verifies that an empty slot is
// reported as PIV-slot-not-found rather than a nil-but-successful response.
func TestBridge_HandlePIVGetCert_NotFound(t *testing.T) {
	storage := newFakePIVStorage()
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:     testLogger(),
		PIVStorage: func(string) (xkms.PIVCertificateStorage, error) { return storage, nil },
	})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVGetCert, pairingproto.RemotePIVGetCertParams{
		Slot: pairingproto.PIVSlotAuthentication,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodePIVSlotNotFound)
}

func TestBridge_HandlePIVGetCert_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(pairingproto.MethodRemotePIVGetCert, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandlePIVGetCert_EmptySlot(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemotePIVGetCert, pairingproto.RemotePIVGetCertParams{
		Backend: "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodePIVInvalidSlot)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_PIVSlotNotFound(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrPIVSlotNotFound)
	assert.Equal(t, pairingproto.ErrorCodePIVSlotNotFound, code)
	assert.Contains(t, msg, "PIV slot not found")
}

func TestMapErrorToRPC_PIVSlotOccupied(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrPIVSlotOccupied)
	assert.Equal(t, pairingproto.ErrorCodePIVSlotOccupied, code)
	assert.Contains(t, msg, "PIV slot already occupied")
}

func TestMapErrorToRPC_PIVSignFailed(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrPIVSignFailed)
	assert.Equal(t, pairingproto.ErrorCodePIVSignFailed, code)
	assert.Contains(t, msg, "PIV signing failed")
}

func TestMapErrorToRPC_PIVInvalidSlot(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrPIVInvalidSlot)
	assert.Equal(t, pairingproto.ErrorCodePIVInvalidSlot, code)
	assert.Contains(t, msg, "invalid PIV slot")
}

// --- Nil params tests for PIV handlers ---

func TestBridge_NilParams_PIVHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// pivSign and pivGetCert require params.
	methodsRequiringParams := []string{
		pairingproto.MethodRemotePIVSign,
		pairingproto.MethodRemotePIVGetCert,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
		})
	}
}
