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

package pkcs11

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

const (
	// defaultIPCTimeout bounds dialing and every IPC operation that does
	// not generate a key.
	defaultIPCTimeout = 10 * time.Second

	// keyGenerationTimeout bounds the operations that generate a key pair.
	// A hardware token generating RSA-4096 on the card, as a YubiKey or
	// smart-card HSM does for generate_piv_key, searches for two 2048-bit
	// primes on a slow secure element and commonly takes a minute or more,
	// with no fixed upper bound. Under the 10-second default the client
	// would give up on a generation that is still going to succeed, leaving
	// the slot holding a key the caller never received.
	keyGenerationTimeout = 3 * time.Minute
)

// keyGenerationActions are the actions sendMessage waits on for
// keyGenerationTimeout instead of the default timeout.
var keyGenerationActions = map[string]bool{
	ipc.ActionGenerateKey:    true,
	ipc.ActionGeneratePIVKey: true,
}

// IPCTransport implements xkms.PKCS11Transport by communicating with
// a running xkey instance over a Unix domain socket. If xkey is not
// running, operations return connection errors.
type IPCTransport struct {
	socketPath           string
	timeout              time.Duration
	keyGenerationTimeout time.Duration
}

// Compile-time interface compliance check.
var _ xkms.PKCS11Transport = (*IPCTransport)(nil)

// NewIPCTransport creates a new IPC transport. The socketPath can be
// empty, in which case ipc.DefaultSocketPath resolves it: the
// XKEY_IPC_SOCKET env var, then the XKEY_HOME-derived instance socket,
// then the XDG runtime default. This is the same resolution the xkey CLI
// uses, so the module and the CLI always agree on which instance an
// unqualified caller talks to.
func NewIPCTransport(socketPath string) *IPCTransport {
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}
	return &IPCTransport{
		socketPath:           socketPath,
		timeout:              defaultIPCTimeout,
		keyGenerationTimeout: keyGenerationTimeout,
	}
}

// SocketPath returns the configured socket path.
func (t *IPCTransport) SocketPath() string {
	return t.socketPath
}

// Connect verifies the IPC socket exists and is reachable. It sends a
// barrier_status request to verify the xkey instance is responding.
func (t *IPCTransport) Connect(ctx context.Context) error {
	if _, err := os.Stat(t.socketPath); err != nil {
		return &DetailError{Err: ErrIPCConnectionFailed, Detail: fmt.Sprintf(": socket not found: %s", t.socketPath)}
	}
	// Verify connectivity by sending a barrier status request.
	msg := &ipc.Message{
		Type: ipc.MessageTypePKCS11,
		PKCS11: &ipc.PKCS11Payload{
			Action: ipc.ActionBarrierStatus,
		},
	}
	_, err := t.sendMessage(ctx, msg)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrIPCConnectionFailed, Cause: err}
	}
	return nil
}

// Close is a no-op for the IPC transport. Each request opens and closes
// its own connection.
func (t *IPCTransport) Close() error {
	return nil
}

// GenerateKey creates a key in the running xkey instance's backend.
func (t *IPCTransport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionGenerateKey, GenerateKey: req}
	return call(ctx, t, ipc.ErrPKCS11Operation, payload, func(r *ipc.PKCS11Result) *transport.GenerateKeyResponse { return r.GenerateKey })
}

// Sign signs data with the specified key via the running xkey instance.
func (t *IPCTransport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionSign, Sign: req}
	return call(ctx, t, ErrSigningFailed, payload, func(r *ipc.PKCS11Result) *transport.SignResponse { return r.Sign })
}

// Verify checks a signature via the running xkey instance.
func (t *IPCTransport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionVerify, Verify: req}
	return call(ctx, t, ErrVerifyFailed, payload, func(r *ipc.PKCS11Result) *transport.VerifyResponse { return r.Verify })
}

// Encrypt encrypts data with a symmetric key via the running xkey instance.
func (t *IPCTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionEncrypt, Encrypt: req}
	return call(ctx, t, ErrEncryptionFailed, payload, func(r *ipc.PKCS11Result) *transport.EncryptResponse { return r.Encrypt })
}

// EncryptAsym encrypts data with an asymmetric public key via the running
// xkey instance. The module routes CKM_RSA_PKCS_OAEP here rather than through
// Encrypt so the caller's chosen OAEP hash has a field to travel in.
func (t *IPCTransport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionEncryptAsym, EncryptAsym: req}
	return call(ctx, t, ErrEncryptionFailed, payload, func(r *ipc.PKCS11Result) *transport.EncryptAsymResponse { return r.EncryptAsym })
}

// Decrypt decrypts data via the running xkey instance.
func (t *IPCTransport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionDecrypt, Decrypt: req}
	return call(ctx, t, ErrDecryptionFailed, payload, func(r *ipc.PKCS11Result) *transport.DecryptResponse { return r.Decrypt })
}

// DeriveKey derives a key from a base key via the running xkey instance.
func (t *IPCTransport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionDeriveKey, DeriveKey: req}
	return call(ctx, t, ErrDerivationFailed, payload, func(r *ipc.PKCS11Result) *transport.DeriveKeyResponse { return r.DeriveKey })
}

// DeriveKeyECDH performs ECDH key agreement via the running xkey instance.
func (t *IPCTransport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionDeriveKeyECDH, DeriveKeyECDH: req}
	return call(ctx, t, ErrDerivationFailed, payload, func(r *ipc.PKCS11Result) *transport.DeriveKeyECDHResponse { return r.DeriveKeyECDH })
}

// WrapKeyByID wraps one stored key under another via the running xkey instance.
func (t *IPCTransport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionWrapKeyByID, WrapKeyByID: req}
	return call(ctx, t, ErrWrappingFailed, payload, func(r *ipc.PKCS11Result) *transport.WrapKeyByIDResponse { return r.WrapKeyByID })
}

// UnwrapKeyByID unwraps a key under a stored key via the running xkey instance.
func (t *IPCTransport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionUnwrapKeyByID, UnwrapKeyByID: req}
	return call(ctx, t, ErrWrappingFailed, payload, func(r *ipc.PKCS11Result) *transport.UnwrapKeyByIDResponse { return r.UnwrapKeyByID })
}

// ExportKeyMaterial exports key material via the running xkey instance. The
// embedded transport's export policy decides whether material is returned.
func (t *IPCTransport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionExportKeyMaterial, ExportKeyMaterial: req}
	return call(ctx, t, ErrExportFailed, payload, func(r *ipc.PKCS11Result) *transport.ExportKeyMaterialResponse { return r.ExportKeyMaterial })
}

// GetImportParameters begins an import ceremony via the running xkey instance.
func (t *IPCTransport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionGetImportParameters, GetImportParameters: req}
	return call(ctx, t, ErrGetImportParamsFailed, payload, func(r *ipc.PKCS11Result) *transport.GetImportParametersResponse { return r.GetImportParameters })
}

// ImportKey imports wrapped key material via the running xkey instance.
func (t *IPCTransport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionImportKey, ImportKey: req}
	return call(ctx, t, ErrImportFailed, payload, func(r *ipc.PKCS11Result) *transport.ImportKeyResponse { return r.ImportKey })
}

// ListPIVSlots returns the status of all PIV slots via the running xkey instance.
func (t *IPCTransport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionListPIVSlots, ListPIVSlots: req}
	return call(ctx, t, ipc.ErrPKCS11Operation, payload, func(r *ipc.PKCS11Result) *transport.ListPIVSlotsResponse { return r.ListPIVSlots })
}

// GetPIVCertificate retrieves a certificate from a PIV slot via the running
// xkey instance. An empty format defaults to PEM.
func (t *IPCTransport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionGetPIVCertificate, GetPIVCertificate: withPEMDefault(req)}
	return call(ctx, t, ipc.ErrPKCS11Operation, payload, func(r *ipc.PKCS11Result) *transport.GetPIVCertificateResponse { return r.GetPIVCertificate })
}

// GeneratePIVKey generates a key in a PIV slot via the running xkey instance.
func (t *IPCTransport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionGeneratePIVKey, GeneratePIVKey: req}
	return call(ctx, t, ipc.ErrPKCS11Operation, payload, func(r *ipc.PKCS11Result) *transport.GeneratePIVKeyResponse { return r.GeneratePIVKey })
}

// StorePIVCertificate stores a certificate in a PIV slot via the running xkey
// instance.
func (t *IPCTransport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callNoResult(ctx, t, &ipc.PKCS11Payload{Action: ipc.ActionStorePIVCertificate, StorePIVCertificate: req})
}

// DeletePIVCertificate removes the certificate from a PIV slot via the running
// xkey instance.
func (t *IPCTransport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callNoResult(ctx, t, &ipc.PKCS11Payload{Action: ipc.ActionDeletePIVCertificate, DeletePIVCertificate: req})
}

// ImportPIVCertificate imports a certificate into a PIV slot via the running
// xkey instance.
func (t *IPCTransport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callNoResult(ctx, t, &ipc.PKCS11Payload{Action: ipc.ActionImportPIVCertificate, ImportPIVCertificate: req})
}

// ExportPIVCertificate exports the certificate from a PIV slot via the running
// xkey instance. An empty format defaults to PEM.
func (t *IPCTransport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionExportPIVCertificate, ExportPIVCertificate: withPEMDefault(req)}
	return call(ctx, t, ipc.ErrPKCS11Operation, payload, func(r *ipc.PKCS11Result) *transport.GetPIVCertificateResponse { return r.ExportPIVCertificate })
}

// GeneratePIVCSR generates a CSR for a PIV slot key via the running xkey
// instance.
func (t *IPCTransport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	payload := &ipc.PKCS11Payload{Action: ipc.ActionGeneratePIVCSR, GeneratePIVCSR: req}
	return call(ctx, t, ipc.ErrPKCS11Operation, payload, func(r *ipc.PKCS11Result) *transport.GeneratePIVCSRResponse { return r.GeneratePIVCSR })
}

// withPEMDefault returns req with an empty format defaulted to PEM, copying
// rather than mutating the caller's request.
func withPEMDefault(req *transport.GetPIVCertificateRequest) *transport.GetPIVCertificateRequest {
	if req.Format != "" {
		return req
	}
	defaulted := *req
	defaulted.Format = "pem"
	return &defaulted
}

// call sends payload to the running xkey instance under ctx and extracts
// the operation's result. Failures are wrapped in sentinel so callers can
// match the operation that failed; a response without the result is a
// protocol violation reported the same way.
func call[Resp any](ctx context.Context, t *IPCTransport, sentinel error, payload *ipc.PKCS11Payload, result func(*ipc.PKCS11Result) *Resp) (*Resp, error) {
	resp, err := t.sendMessage(ctx, &ipc.Message{Type: ipc.MessageTypePKCS11, PKCS11: payload})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: sentinel, Cause: err}
	}
	if resp.PKCS11 == nil || result(resp.PKCS11) == nil {
		return nil, &DetailError{Err: sentinel, Detail: fmt.Sprintf(": missing %s result in response", payload.Action)}
	}
	return result(resp.PKCS11), nil
}

// callNoResult sends payload under ctx for an operation that returns only
// success or failure.
func callNoResult(ctx context.Context, t *IPCTransport, payload *ipc.PKCS11Payload) error {
	if _, err := t.sendMessage(ctx, &ipc.Message{Type: ipc.MessageTypePKCS11, PKCS11: payload}); err != nil {
		return &SentinelCauseError{Sentinel: ipc.ErrPKCS11Operation, Cause: err}
	}
	return nil
}

// operationTimeout returns how long sendMessage waits for msg's response:
// keyGenerationTimeout for a key generation, the default timeout otherwise.
func (t *IPCTransport) operationTimeout(msg *ipc.Message) time.Duration {
	if msg.PKCS11 != nil && keyGenerationActions[msg.PKCS11.Action] {
		return t.keyGenerationTimeout
	}
	return t.timeout
}

// exchangeResult is the outcome of one request/response exchange.
type exchangeResult struct {
	response *ipc.Response
	err      error
}

// sendMessage opens a Unix socket connection, sends the JSON message, reads
// the JSON response, and returns it. Each call is a fresh connection. Dialing
// is bounded by the default timeout; the exchange by operationTimeout or
// ctx's deadline, whichever is sooner.
//
// A ctx that has already ended sends nothing, so a side-effecting operation
// such as a key generation is never dispatched for a caller that has gone.
// A ctx that ends mid-exchange abandons the connection; the xkey instance
// sees it close and cancels the request it is running.
func (t *IPCTransport) sendMessage(ctx context.Context, msg *ipc.Message) (response *ipc.Response, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, &SentinelCauseError{Sentinel: ErrIPCRequestCanceled, Cause: ctxErr}
	}

	conn, err := ipc.Dial(t.socketPath, t.timeout)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrIPCConnectionFailed, Cause: err}
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// The caller's own deadline is not folded in here: ctx.Done below ends
	// the call, so a ctx that expires is always reported as the cancellation
	// rather than racing the connection's timer to an i/o timeout.
	if err := conn.SetDeadline(time.Now().Add(t.operationTimeout(msg))); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrIPCConnectionFailed, Cause: err}
	}

	done := make(chan exchangeResult, 1)
	go func() {
		resp, exchangeErr := exchange(conn, msg)
		done <- exchangeResult{response: resp, err: exchangeErr}
	}()

	select {
	case result := <-done:
		// The exchange can lose a race with a ctx that ended meanwhile;
		// report that as the cancellation it is.
		if result.err != nil && ctx.Err() != nil {
			return nil, &SentinelCauseError{Sentinel: ErrIPCRequestCanceled, Cause: errors.Join(ctx.Err(), result.err)}
		}
		return result.response, result.err
	case <-ctx.Done():
		// Expiring the deadline unblocks the exchange, which is drained so
		// no goroutine outlives the connection.
		deadlineErr := conn.SetDeadline(time.Now())
		<-done
		return nil, &SentinelCauseError{Sentinel: ErrIPCRequestCanceled, Cause: errors.Join(ctx.Err(), deadlineErr)}
	}
}

// exchange writes msg to conn as JSON and reads the JSON response.
func exchange(conn net.Conn, msg *ipc.Message) (*ipc.Response, error) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return nil, &SentinelCauseError{Sentinel: ipc.ErrProtocolError, Cause: err}
	}

	var resp ipc.Response
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, &SentinelCauseError{Sentinel: ipc.ErrProtocolError, Cause: err}
	}

	if resp.Status == ipc.StatusError {
		return nil, &DetailError{Err: ipc.ErrPKCS11Operation, Detail: fmt.Sprintf(": %s", resp.Error)}
	}

	return &resp, nil
}
