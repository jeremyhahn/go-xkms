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

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPKCS11Handler implements both Handler and PKCS11Handler for testing.
// Every operation records the request it received and returns either err or
// a non-nil result, so a test can check both directions of the wire.
type mockPKCS11Handler struct {
	mockHandler // embed the basic handler

	got           any
	err           error
	barrierResult *BarrierStatusResult
	barrierErr    error
}

func record[Req, Resp any](h *mockPKCS11Handler, req *Req, resp *Resp) (*Resp, error) {
	h.got = req
	if h.err != nil {
		return nil, h.err
	}
	return resp, nil
}

func (h *mockPKCS11Handler) HandlePKCS11GenerateKey(_ context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return record(h, req, &transport.GenerateKeyResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11Sign(_ context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return record(h, req, &transport.SignResponse{Signature: []byte("signature")})
}

func (h *mockPKCS11Handler) HandlePKCS11Verify(_ context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return record(h, req, &transport.VerifyResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11Encrypt(_ context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return record(h, req, &transport.EncryptResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11EncryptAsym(_ context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return record(h, req, &transport.EncryptAsymResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11Decrypt(_ context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return record(h, req, &transport.DecryptResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11DeriveKey(_ context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return record(h, req, &transport.DeriveKeyResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11DeriveKeyECDH(_ context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return record(h, req, &transport.DeriveKeyECDHResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11WrapKeyByID(_ context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return record(h, req, &transport.WrapKeyByIDResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11UnwrapKeyByID(_ context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return record(h, req, &transport.UnwrapKeyByIDResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11ExportKeyMaterial(_ context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return record(h, req, &transport.ExportKeyMaterialResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11GetImportParameters(_ context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return record(h, req, &transport.GetImportParametersResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11ImportKey(_ context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return record(h, req, &transport.ImportKeyResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11ListPIVSlots(_ context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return record(h, req, &transport.ListPIVSlotsResponse{Slots: []transport.PIVSlotStatus{{Slot: "9a"}}})
}

func (h *mockPKCS11Handler) HandlePKCS11GetPIVCertificate(_ context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return record(h, req, &transport.GetPIVCertificateResponse{Slot: req.Slot})
}

func (h *mockPKCS11Handler) HandlePKCS11GeneratePIVKey(_ context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return record(h, req, &transport.GeneratePIVKeyResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11StorePIVCertificate(_ context.Context, req *transport.StorePIVCertificateRequest) error {
	_, err := record(h, req, &struct{}{})
	return err
}

func (h *mockPKCS11Handler) HandlePKCS11DeletePIVCertificate(_ context.Context, req *transport.DeletePIVCertificateRequest) error {
	_, err := record(h, req, &struct{}{})
	return err
}

func (h *mockPKCS11Handler) HandlePKCS11ImportPIVCertificate(_ context.Context, req *transport.StorePIVCertificateRequest) error {
	_, err := record(h, req, &struct{}{})
	return err
}

func (h *mockPKCS11Handler) HandlePKCS11ExportPIVCertificate(_ context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return record(h, req, &transport.GetPIVCertificateResponse{Slot: req.Slot})
}

func (h *mockPKCS11Handler) HandlePKCS11GeneratePIVCSR(_ context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return record(h, req, &transport.GeneratePIVCSRResponse{})
}

func (h *mockPKCS11Handler) HandlePKCS11BarrierStatus() (*BarrierStatusResult, error) {
	return h.barrierResult, h.barrierErr
}

// pkcs11Case is one operation carried over the socket: the payload a client
// sends, the request the handler must receive, and the result field the
// client must find in the reply (nil for operations without a result).
type pkcs11Case struct {
	payload *PKCS11Payload
	sent    any
	result  func(*PKCS11Result) any
}

// pkcs11Cases returns one valid request for every PKCS#11 operation that
// carries one.
func pkcs11Cases() map[string]pkcs11Case {
	generate := &transport.GenerateKeyRequest{KeyID: "k"}
	sign := &transport.SignRequest{KeyID: "k", Data: []byte("data"), Hash: "SHA-256"}
	verify := &transport.VerifyRequest{KeyID: "k", Data: []byte("data"), Signature: []byte("sig")}
	encrypt := &transport.EncryptRequest{KeyID: "k", Plaintext: []byte("p")}
	encryptAsym := &transport.EncryptAsymRequest{KeyID: "k", Plaintext: []byte("p")}
	decrypt := &transport.DecryptRequest{KeyID: "k", Ciphertext: []byte("c")}
	derive := &transport.DeriveKeyRequest{Algorithm: "HKDF", InputKeyMaterial: []byte("ikm"), KeyLength: 32}
	ecdh := &transport.DeriveKeyECDHRequest{KeyID: "k", PeerPublicKey: []byte("pub")}
	wrap := &transport.WrapKeyByIDRequest{WrappingKeyID: "w", TargetKeyID: "k"}
	unwrap := &transport.UnwrapKeyByIDRequest{UnwrappingKeyID: "w", WrappedKey: []byte("wrapped")}
	export := &transport.ExportKeyMaterialRequest{KeyID: "k"}
	importParams := &transport.GetImportParametersRequest{KeyID: "k"}
	importKey := &transport.ImportKeyRequest{KeyID: "k", WrappedKeyMaterial: []byte("m")}
	slots := &transport.ListPIVSlotsRequest{Backend: "software"}
	getCert := &transport.GetPIVCertificateRequest{Slot: "9a", Format: "pem"}
	pivKey := &transport.GeneratePIVKeyRequest{Slot: "9a"}
	storeCert := &transport.StorePIVCertificateRequest{Slot: "9a", Certificate: []byte("cert")}
	deleteCert := &transport.DeletePIVCertificateRequest{Slot: "9a"}
	importCert := &transport.StorePIVCertificateRequest{Slot: "9c", Certificate: []byte("cert")}
	exportCert := &transport.GetPIVCertificateRequest{Slot: "9c", Format: "der"}
	csr := &transport.GeneratePIVCSRRequest{Slot: "9a"}

	return map[string]pkcs11Case{
		ActionGenerateKey: {&PKCS11Payload{Action: ActionGenerateKey, GenerateKey: generate}, generate,
			func(r *PKCS11Result) any { return r.GenerateKey }},
		ActionSign: {&PKCS11Payload{Action: ActionSign, Sign: sign}, sign,
			func(r *PKCS11Result) any { return r.Sign }},
		ActionVerify: {&PKCS11Payload{Action: ActionVerify, Verify: verify}, verify,
			func(r *PKCS11Result) any { return r.Verify }},
		ActionEncrypt: {&PKCS11Payload{Action: ActionEncrypt, Encrypt: encrypt}, encrypt,
			func(r *PKCS11Result) any { return r.Encrypt }},
		ActionEncryptAsym: {&PKCS11Payload{Action: ActionEncryptAsym, EncryptAsym: encryptAsym}, encryptAsym,
			func(r *PKCS11Result) any { return r.EncryptAsym }},
		ActionDecrypt: {&PKCS11Payload{Action: ActionDecrypt, Decrypt: decrypt}, decrypt,
			func(r *PKCS11Result) any { return r.Decrypt }},
		ActionDeriveKey: {&PKCS11Payload{Action: ActionDeriveKey, DeriveKey: derive}, derive,
			func(r *PKCS11Result) any { return r.DeriveKey }},
		ActionDeriveKeyECDH: {&PKCS11Payload{Action: ActionDeriveKeyECDH, DeriveKeyECDH: ecdh}, ecdh,
			func(r *PKCS11Result) any { return r.DeriveKeyECDH }},
		ActionWrapKeyByID: {&PKCS11Payload{Action: ActionWrapKeyByID, WrapKeyByID: wrap}, wrap,
			func(r *PKCS11Result) any { return r.WrapKeyByID }},
		ActionUnwrapKeyByID: {&PKCS11Payload{Action: ActionUnwrapKeyByID, UnwrapKeyByID: unwrap}, unwrap,
			func(r *PKCS11Result) any { return r.UnwrapKeyByID }},
		ActionExportKeyMaterial: {&PKCS11Payload{Action: ActionExportKeyMaterial, ExportKeyMaterial: export}, export,
			func(r *PKCS11Result) any { return r.ExportKeyMaterial }},
		ActionGetImportParameters: {&PKCS11Payload{Action: ActionGetImportParameters, GetImportParameters: importParams}, importParams,
			func(r *PKCS11Result) any { return r.GetImportParameters }},
		ActionImportKey: {&PKCS11Payload{Action: ActionImportKey, ImportKey: importKey}, importKey,
			func(r *PKCS11Result) any { return r.ImportKey }},
		ActionListPIVSlots: {&PKCS11Payload{Action: ActionListPIVSlots, ListPIVSlots: slots}, slots,
			func(r *PKCS11Result) any { return r.ListPIVSlots }},
		ActionGetPIVCertificate: {&PKCS11Payload{Action: ActionGetPIVCertificate, GetPIVCertificate: getCert}, getCert,
			func(r *PKCS11Result) any { return r.GetPIVCertificate }},
		ActionGeneratePIVKey: {&PKCS11Payload{Action: ActionGeneratePIVKey, GeneratePIVKey: pivKey}, pivKey,
			func(r *PKCS11Result) any { return r.GeneratePIVKey }},
		ActionStorePIVCertificate:  {&PKCS11Payload{Action: ActionStorePIVCertificate, StorePIVCertificate: storeCert}, storeCert, nil},
		ActionDeletePIVCertificate: {&PKCS11Payload{Action: ActionDeletePIVCertificate, DeletePIVCertificate: deleteCert}, deleteCert, nil},
		ActionImportPIVCertificate: {&PKCS11Payload{Action: ActionImportPIVCertificate, ImportPIVCertificate: importCert}, importCert, nil},
		ActionExportPIVCertificate: {&PKCS11Payload{Action: ActionExportPIVCertificate, ExportPIVCertificate: exportCert}, exportCert,
			func(r *PKCS11Result) any { return r.ExportPIVCertificate }},
		ActionGeneratePIVCSR: {&PKCS11Payload{Action: ActionGeneratePIVCSR, GeneratePIVCSR: csr}, csr,
			func(r *PKCS11Result) any { return r.GeneratePIVCSR }},
	}
}

// sendPKCS11 serves handler on a fresh socket, sends one PKCS#11 payload
// and returns the decoded response.
//
// It needs no readiness wait after "go srv.Serve(ctx)": see the note on
// TestServer_AcceptsAndDispatchesTouch in server_test.go.
func sendPKCS11(t *testing.T, handler Handler, payload *PKCS11Payload) Response {
	t.Helper()
	srv, err := NewServer(testSocketPath(t), handler, testLogger())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Close()
	})
	go srv.Serve(ctx)

	conn, err := net.Dial("unix", srv.socketPath)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, json.NewEncoder(conn).Encode(Message{Type: MessageTypePKCS11, PKCS11: payload}))
	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))
	return resp
}

func newMockPKCS11Handler() *mockPKCS11Handler {
	return &mockPKCS11Handler{mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)}}
}

func TestPKCS11Cases_CoverEveryOperation(t *testing.T) {
	// Every dispatched action except barrier_status carries a request.
	assert.Len(t, pkcs11Cases(), len(pkcs11Handlers)-1)
}

func TestServer_PKCS11_EveryOperation_RoundTrip(t *testing.T) {
	for action, tc := range pkcs11Cases() {
		t.Run(action, func(t *testing.T) {
			handler := newMockPKCS11Handler()

			resp := sendPKCS11(t, handler, tc.payload)

			require.Equal(t, StatusOK, resp.Status, resp.Error)
			assert.Equal(t, tc.sent, handler.got, "the handler must receive the request the client sent")
			if tc.result != nil {
				require.NotNil(t, resp.PKCS11)
				assert.NotNil(t, tc.result(resp.PKCS11), "the reply must carry the %s result", action)
			}
		})
	}
}

func TestServer_PKCS11_EveryOperation_HandlerError(t *testing.T) {
	for action, tc := range pkcs11Cases() {
		t.Run(action, func(t *testing.T) {
			handler := newMockPKCS11Handler()
			handler.err = errors.New("key /secret/path not found")

			resp := sendPKCS11(t, handler, tc.payload)

			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, "handler returned error")
			assertNotEchoed(t, resp.Error, "/secret/path")
		})
	}
}

func TestServer_PKCS11_MissingRequest_RejectedBeforeHandler(t *testing.T) {
	for action := range pkcs11Cases() {
		if action == ActionListPIVSlots {
			continue // the only operation whose request is optional
		}
		t.Run(action, func(t *testing.T) {
			handler := newMockPKCS11Handler()

			resp := sendPKCS11(t, handler, &PKCS11Payload{Action: action})

			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, ErrInvalidMessage.Error())
			assert.Nil(t, handler.got, "an invalid request must never reach the handler")
		})
	}
}

func TestServer_PKCS11_Sign_SignatureBytesSurviveTheWire(t *testing.T) {
	tc := pkcs11Cases()[ActionSign]

	resp := sendPKCS11(t, newMockPKCS11Handler(), tc.payload)

	require.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, []byte("signature"), resp.PKCS11.Sign.Signature)
}

func TestServer_PKCS11_ListPIVSlots_NilRequestDefaults(t *testing.T) {
	handler := newMockPKCS11Handler()

	resp := sendPKCS11(t, handler, &PKCS11Payload{Action: ActionListPIVSlots})

	require.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, &transport.ListPIVSlotsRequest{}, handler.got)
	require.Len(t, resp.PKCS11.ListPIVSlots.Slots, 1)
	assert.Equal(t, "9a", resp.PKCS11.ListPIVSlots.Slots[0].Slot)
}

func TestServer_PKCS11_BarrierStatus_Success(t *testing.T) {
	handler := newMockPKCS11Handler()
	handler.barrierResult = &BarrierStatusResult{Strategy: "software"}

	resp := sendPKCS11(t, handler, &PKCS11Payload{Action: ActionBarrierStatus})

	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.PKCS11)
	require.NotNil(t, resp.PKCS11.BarrierStatus)
	assert.False(t, resp.PKCS11.BarrierStatus.Sealed)
	assert.Equal(t, "software", resp.PKCS11.BarrierStatus.Strategy)
}

func TestServer_PKCS11_BarrierStatus_Error(t *testing.T) {
	handler := newMockPKCS11Handler()
	handler.barrierErr = errors.New("barrier service unavailable")

	resp := sendPKCS11(t, handler, &PKCS11Payload{Action: ActionBarrierStatus})

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "handler returned error")
}

func TestServer_PKCS11_HandlerDoesNotImplementPKCS11Handler(t *testing.T) {
	// A plain mockHandler does NOT implement PKCS11Handler.
	handler := &mockHandler{statusResp: OKResponse(ActionDaemonReady)}

	resp := sendPKCS11(t, handler, &PKCS11Payload{Action: ActionBarrierStatus})

	assert.Equal(t, StatusError, resp.Status)
	assertNotEchoed(t, resp.Error, "does not implement PKCS11Handler")
}

func TestDispatchPKCS11_UnknownAction(t *testing.T) {
	handler := &mockPKCS11Handler{}
	payload := &PKCS11Payload{
		Action: "nonexistent",
	}

	resp, err := dispatchPKCS11(context.Background(), handler, payload)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown pkcs11 action")
}

func TestPkcs11OKResponse(t *testing.T) {
	result := &PKCS11Result{
		BarrierStatus: &BarrierStatusResult{
			Sealed: true,
		},
	}
	resp := pkcs11OKResponse(result)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Empty(t, resp.Action)
	assert.Empty(t, resp.Error)
	require.NotNil(t, resp.PKCS11)
	assert.True(t, resp.PKCS11.BarrierStatus.Sealed)
}

// ctxRecordingHandler answers GenerateKey by reporting the request context it
// was given: with block set it waits for that context to end first.
type ctxRecordingHandler struct {
	*mockPKCS11Handler
	block   bool
	started chan struct{}
	ended   chan error
}

func newCtxRecordingHandler(block bool) *ctxRecordingHandler {
	return &ctxRecordingHandler{
		mockPKCS11Handler: newMockPKCS11Handler(),
		block:             block,
		started:           make(chan struct{}),
		ended:             make(chan error, 1),
	}
}

func (h *ctxRecordingHandler) HandlePKCS11GenerateKey(ctx context.Context, _ *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	close(h.started)
	if h.block {
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	h.ended <- ctx.Err()
	return &transport.GenerateKeyResponse{}, nil
}

// startCtxServer serves handler on a fresh socket under serveCtx and returns
// a connection that has sent one GenerateKey request.
func startCtxServer(t *testing.T, serveCtx context.Context, handler Handler) net.Conn {
	t.Helper()
	srv, err := NewServer(testSocketPath(t), handler, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(serveCtx)

	conn, err := net.Dial("unix", srv.socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	payload := &PKCS11Payload{Action: ActionGenerateKey, GenerateKey: &transport.GenerateKeyRequest{KeyID: "k"}}
	require.NoError(t, json.NewEncoder(conn).Encode(Message{Type: MessageTypePKCS11, PKCS11: payload}))
	return conn
}

func TestServer_PKCS11_RequestContext_LiveWhileClientWaits(t *testing.T) {
	handler := newCtxRecordingHandler(false)
	conn := startCtxServer(t, context.Background(), handler)

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))
	assert.Equal(t, StatusOK, resp.Status, resp.Error)
	assert.NoError(t, <-handler.ended, "a client still waiting for its answer must not cancel the request")
}

func TestServer_PKCS11_RequestContext_CanceledWhenClientHangsUp(t *testing.T) {
	handler := newCtxRecordingHandler(true)
	conn := startCtxServer(t, context.Background(), handler)

	<-handler.started
	require.NoError(t, conn.Close())
	assert.ErrorIs(t, <-handler.ended, context.Canceled, "a client that hung up must cancel its request")
}

func TestServer_PKCS11_RequestContext_CanceledOnShutdown(t *testing.T) {
	handler := newCtxRecordingHandler(true)
	serveCtx, cancel := context.WithCancel(context.Background())
	startCtxServer(t, serveCtx, handler)

	<-handler.started
	cancel()
	assert.ErrorIs(t, <-handler.ended, context.Canceled, "server shutdown must cancel the request in flight")
}
