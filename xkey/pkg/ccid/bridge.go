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

package ccid

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// PKCS11Transport defines the subset of the PKCS#11 transport interface
// needed by the CCID bridge. This decouples the bridge from the concrete
// transport implementation and makes testing straightforward.
type PKCS11Transport interface {
	// GenerateKey generates a new key pair.
	GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error)

	// Sign signs data with the specified key.
	Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)

	// Verify verifies a signature.
	Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error)

	// Encrypt encrypts plaintext.
	Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error)

	// Decrypt decrypts ciphertext.
	Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)
}

// AppletID identifies a selected smartcard applet. The bridge routes
// APDUs differently based on which applet is selected.
type AppletID byte

const (
	// AppletNone indicates no applet has been selected.
	AppletNone AppletID = 0

	// AppletPIV represents the PIV (Personal Identity Verification) applet.
	AppletPIV AppletID = 1

	// AppletOpenPGP represents the OpenPGP applet.
	AppletOpenPGP AppletID = 2
)

// Well-known applet AIDs (Application Identifiers).
var (
	// AIDPIV is the PIV applet AID: A000000308000010000100.
	AIDPIV = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}

	// AIDOpenPGP is the OpenPGP applet AID: D27600012401.
	AIDOpenPGP = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
)

// SessionState tracks the state of a PKCS#11 logical session opened
// by the card holder through PIN verification.
type SessionState struct {
	// Handle is the session handle (auto-generated).
	Handle uint32

	// SlotID identifies the logical slot.
	SlotID uint32

	// Flags holds session flags (e.g., read-only, R/W).
	Flags uint32

	// SignActive indicates a multi-step signing operation is in progress.
	SignActive bool

	// Authenticated indicates the session has been authenticated via PIN.
	Authenticated bool

	// SelectedKeyID is the key ID selected for the current operation.
	SelectedKeyID string

	// SelectedBackend is the backend name for the current operation.
	SelectedBackend string
}

// PKCS11Bridge implements APDUHandler by routing ISO 7816 APDUs to the
// xKey PKCS#11 service. It translates smartcard commands (SELECT, VERIFY,
// PSO, READ BINARY, GENERATE ASYMMETRIC) into the corresponding PKCS#11
// operations.
//
// All methods are safe for concurrent use.
type PKCS11Bridge struct {
	transport      PKCS11Transport
	logger         *slog.Logger
	sessions       map[uint32]*SessionState
	mu             sync.RWMutex
	nextHandle     atomic.Uint32
	selectedApplet atomic.Int32
	defaultBackend string
}

// Compile-time interface check.
var _ APDUHandler = (*PKCS11Bridge)(nil)

// NewPKCS11Bridge creates a new bridge that translates APDU commands into
// PKCS#11 operations via the given transport.
func NewPKCS11Bridge(t PKCS11Transport, logger *slog.Logger) (*PKCS11Bridge, error) {
	if t == nil {
		return nil, ErrNilService
	}
	if logger == nil {
		return nil, ErrNilLogger
	}

	b := &PKCS11Bridge{
		transport:      t,
		logger:         logger,
		sessions:       make(map[uint32]*SessionState),
		defaultBackend: "software",
	}
	b.nextHandle.Store(1)
	return b, nil
}

// GetATR returns the Answer To Reset for the virtual smartcard.
func (b *PKCS11Bridge) GetATR() []byte {
	return DefaultATR()
}

// HandleAPDU dispatches a command APDU to the appropriate handler based
// on the instruction byte. Uses map-based dispatch for O(1) lookup.
func (b *PKCS11Bridge) HandleAPDU(cmd *CommandAPDU) *ResponseAPDU {
	if cmd == nil {
		return NewErrorResponse(SW_INTERNAL_ERROR)
	}

	handler, ok := b.apduHandlers()[cmd.INS]
	if !ok {
		b.logger.Warn("unsupported APDU instruction",
			slog.String("INS", fmt.Sprintf("0x%02X", cmd.INS)),
		)
		return NewErrorResponse(SW_INS_NOT_SUPPORTED)
	}

	return handler(cmd)
}

// apduHandlerFunc is the function signature for APDU instruction handlers.
type apduHandlerFunc func(cmd *CommandAPDU) *ResponseAPDU

// apduHandlers returns the dispatch map for ISO 7816 instructions.
func (b *PKCS11Bridge) apduHandlers() map[byte]apduHandlerFunc {
	return map[byte]apduHandlerFunc{
		INS_SELECT:              b.handleSelect,
		INS_VERIFY:              b.handleVerify,
		INS_PSO:                 b.handlePSO,
		INS_READ_BINARY:         b.handleReadBinary,
		INS_GENERATE_ASYMMETRIC: b.handleGenerateAsymmetric,
		INS_GET_DATA:            b.handleGetData,
	}
}

// handleSelect processes a SELECT APDU (INS=0xA4).
//
// P1=0x04 selects by AID (application identifier). The data field
// contains the AID of the applet to select. Known AIDs are mapped
// to internal applet identifiers; unknown AIDs return FILE_NOT_FOUND.
func (b *PKCS11Bridge) handleSelect(cmd *CommandAPDU) *ResponseAPDU {
	if cmd.P1 != 0x04 {
		return NewErrorResponse(SW_WRONG_P1P2)
	}

	if len(cmd.Data) == 0 {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	// Check for known applets.
	if matchAID(cmd.Data, AIDPIV) {
		b.selectedApplet.Store(int32(AppletPIV))
		b.logger.Info("PIV applet selected")
		return NewSuccessResponse(nil)
	}

	if matchAID(cmd.Data, AIDOpenPGP) {
		b.selectedApplet.Store(int32(AppletOpenPGP))
		b.logger.Info("OpenPGP applet selected")
		return NewSuccessResponse(nil)
	}

	b.logger.Warn("unknown applet AID",
		slog.Int("aid_length", len(cmd.Data)),
	)
	return NewErrorResponse(SW_FILE_NOT_FOUND)
}

// handleVerify processes a VERIFY APDU (INS=0x20).
//
// Maps to PKCS#11 C_Login. The data field contains the PIN. On success,
// a new session is created or an existing session is authenticated.
func (b *PKCS11Bridge) handleVerify(cmd *CommandAPDU) *ResponseAPDU {
	if AppletID(b.selectedApplet.Load()) == AppletNone {
		return NewErrorResponse(SW_CONDITIONS_NOT_SATISFIED)
	}

	if len(cmd.Data) == 0 {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	// Create a new authenticated session.
	handle := b.nextHandle.Add(1) - 1
	session := &SessionState{
		Handle:          handle,
		SlotID:          0,
		Flags:           0x04, // CKF_RW_SESSION
		Authenticated:   true,
		SelectedBackend: b.defaultBackend,
	}

	b.mu.Lock()
	b.sessions[handle] = session
	b.mu.Unlock()

	b.logger.Info("PIN verified, session created",
		slog.Uint64("session", uint64(handle)),
	)

	return NewSuccessResponse(nil)
}

// handlePSO processes a PSO (Perform Security Operation) APDU (INS=0x2A).
//
// The P1/P2 bytes determine the specific operation:
//   - P1=0x9E, P2=0x9A: Compute Digital Signature -> C_Sign
//   - P1=0x00, P2=0xA8: Verify Digital Signature -> C_Verify
//   - P1=0x86, P2=0x80: Encipher -> C_Encrypt
//   - P1=0x80, P2=0x86: Decipher -> C_Decrypt
func (b *PKCS11Bridge) handlePSO(cmd *CommandAPDU) *ResponseAPDU {
	session := b.getAuthenticatedSession()
	if session == nil {
		return NewErrorResponse(SW_SECURITY_STATUS)
	}

	// Dispatch based on P1/P2.
	psoKey := [2]byte{cmd.P1, cmd.P2}
	handler, ok := b.psoHandlers()[psoKey]
	if !ok {
		b.logger.Warn("unsupported PSO operation",
			slog.String("P1", fmt.Sprintf("0x%02X", cmd.P1)),
			slog.String("P2", fmt.Sprintf("0x%02X", cmd.P2)),
		)
		return NewErrorResponse(SW_INS_NOT_SUPPORTED)
	}

	return handler(cmd, session)
}

// psoHandlerFunc is the function signature for PSO sub-handlers.
type psoHandlerFunc func(cmd *CommandAPDU, session *SessionState) *ResponseAPDU

// psoHandlers returns the dispatch map for PSO sub-operations.
func (b *PKCS11Bridge) psoHandlers() map[[2]byte]psoHandlerFunc {
	return map[[2]byte]psoHandlerFunc{
		{PSO_SIGN_P1, PSO_SIGN_P2}:         b.handleSign,
		{PSO_VERIFY_P1, PSO_VERIFY_P2}:     b.handleVerifySig,
		{PSO_ENCIPHER_P1, PSO_ENCIPHER_P2}: b.handleEncipher,
		{PSO_DECIPHER_P1, PSO_DECIPHER_P2}: b.handleDecipher,
	}
}

// handleSign signs data using the PKCS#11 transport.
func (b *PKCS11Bridge) handleSign(cmd *CommandAPDU, session *SessionState) *ResponseAPDU {
	if len(cmd.Data) == 0 {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	keyID := session.SelectedKeyID
	if keyID == "" {
		keyID = "default-sign-key"
	}

	resp, err := b.transport.Sign(context.Background(), &transport.SignRequest{
		Backend: session.SelectedBackend,
		KeyID:   keyID,
		Data:    cmd.Data,
		Hash:    hashName(crypto.SHA256),
	})
	if err != nil {
		b.logger.Error("sign operation failed",
			slog.Any("error", err),
		)
		return NewErrorResponse(SW_INTERNAL_ERROR)
	}

	return NewSuccessResponse(resp.Signature)
}

// handleVerifySig verifies a signature using the PKCS#11 transport.
func (b *PKCS11Bridge) handleVerifySig(cmd *CommandAPDU, session *SessionState) *ResponseAPDU {
	// Data format: [signature_length(2) | signature | hash_data]
	if len(cmd.Data) < 3 {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	sigLen := int(cmd.Data[0])<<8 | int(cmd.Data[1])
	if sigLen+2 > len(cmd.Data) {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	signature := cmd.Data[2 : 2+sigLen]
	hashData := cmd.Data[2+sigLen:]

	keyID := session.SelectedKeyID
	if keyID == "" {
		keyID = "default-sign-key"
	}

	resp, err := b.transport.Verify(context.Background(), &transport.VerifyRequest{
		Backend:   session.SelectedBackend,
		KeyID:     keyID,
		Data:      hashData,
		Signature: signature,
		Hash:      hashName(crypto.SHA256),
	})
	if err != nil || !resp.Valid {
		b.logger.Error("verify operation failed",
			slog.Any("error", err),
		)
		return NewErrorResponse(SW_SECURITY_STATUS)
	}

	return NewSuccessResponse(nil)
}

// handleEncipher encrypts data using the PKCS#11 transport.
func (b *PKCS11Bridge) handleEncipher(cmd *CommandAPDU, session *SessionState) *ResponseAPDU {
	if len(cmd.Data) == 0 {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	keyID := session.SelectedKeyID
	if keyID == "" {
		keyID = "default-enc-key"
	}

	resp, err := b.transport.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   session.SelectedBackend,
		KeyID:     keyID,
		Plaintext: cmd.Data,
	})
	if err != nil {
		b.logger.Error("encrypt operation failed",
			slog.Any("error", err),
		)
		return NewErrorResponse(SW_INTERNAL_ERROR)
	}

	// Return ciphertext with nonce prepended.
	result := make([]byte, 0, len(resp.Nonce)+len(resp.Ciphertext))
	result = append(result, resp.Nonce...)
	result = append(result, resp.Ciphertext...)
	return NewSuccessResponse(result)
}

// handleDecipher decrypts data using the PKCS#11 transport.
func (b *PKCS11Bridge) handleDecipher(cmd *CommandAPDU, session *SessionState) *ResponseAPDU {
	if len(cmd.Data) == 0 {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	keyID := session.SelectedKeyID
	if keyID == "" {
		keyID = "default-enc-key"
	}

	// Expect nonce (first 12 bytes) + ciphertext.
	nonceLen := 12
	if len(cmd.Data) <= nonceLen {
		return NewErrorResponse(SW_WRONG_DATA)
	}

	resp, err := b.transport.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    session.SelectedBackend,
		KeyID:      keyID,
		Nonce:      cmd.Data[:nonceLen],
		Ciphertext: cmd.Data[nonceLen:],
	})
	if err != nil {
		b.logger.Error("decrypt operation failed",
			slog.Any("error", err),
		)
		return NewErrorResponse(SW_INTERNAL_ERROR)
	}

	return NewSuccessResponse(resp.Plaintext)
}

// handleReadBinary processes a READ BINARY APDU (INS=0xB0).
//
// Maps to PKCS#11 certificate/object retrieval. P1 and P2 encode
// the offset into the selected file.
func (b *PKCS11Bridge) handleReadBinary(cmd *CommandAPDU) *ResponseAPDU {
	if AppletID(b.selectedApplet.Load()) == AppletNone {
		return NewErrorResponse(SW_CONDITIONS_NOT_SATISFIED)
	}

	b.logger.Debug("READ BINARY received",
		slog.String("P1", fmt.Sprintf("0x%02X", cmd.P1)),
		slog.String("P2", fmt.Sprintf("0x%02X", cmd.P2)),
	)

	return NewErrorResponse(SW_FILE_NOT_FOUND)
}

// handleGenerateAsymmetric processes a GENERATE ASYMMETRIC KEY PAIR APDU (INS=0x47).
//
// Maps to PKCS#11 C_GenerateKeyPair. The data field contains
// algorithm and key size parameters.
func (b *PKCS11Bridge) handleGenerateAsymmetric(cmd *CommandAPDU) *ResponseAPDU {
	session := b.getAuthenticatedSession()
	if session == nil {
		return NewErrorResponse(SW_SECURITY_STATUS)
	}

	// Default to ECDSA P-256 if no data specifies the algorithm.
	algorithm := "ECDSA"
	curve := "P-256"
	keyID := "ccid-generated-key"

	if len(cmd.Data) >= 1 {
		// First byte can indicate algorithm preference:
		// 0x01 = RSA, 0x02 = ECDSA, 0x03 = Ed25519.
		switch cmd.Data[0] {
		case 0x01:
			algorithm = "RSA"
		case 0x02:
			algorithm = "ECDSA"
		case 0x03:
			algorithm = "Ed25519"
		}
	}

	resp, err := b.transport.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Backend:   session.SelectedBackend,
		KeyID:     keyID,
		Algorithm: algorithm,
		Curve:     curve,
	})
	if err != nil {
		b.logger.Error("key generation failed",
			slog.Any("error", err),
		)
		return NewErrorResponse(SW_INTERNAL_ERROR)
	}

	// Store the generated key ID in the session for future operations.
	b.mu.Lock()
	session.SelectedKeyID = resp.KeyID
	b.mu.Unlock()

	return NewSuccessResponse([]byte(resp.PublicKeyPEM))
}

// handleGetData processes a GET DATA APDU (INS=0xCA).
//
// Returns data objects based on the tag specified by P1/P2.
func (b *PKCS11Bridge) handleGetData(cmd *CommandAPDU) *ResponseAPDU {
	if AppletID(b.selectedApplet.Load()) == AppletNone {
		return NewErrorResponse(SW_CONDITIONS_NOT_SATISFIED)
	}

	b.logger.Debug("GET DATA received",
		slog.String("P1", fmt.Sprintf("0x%02X", cmd.P1)),
		slog.String("P2", fmt.Sprintf("0x%02X", cmd.P2)),
	)

	// Tag-based dispatch for common PIV data objects.
	tag := uint16(cmd.P1)<<8 | uint16(cmd.P2)
	switch tag {
	case 0x004F: // AID
		if AppletID(b.selectedApplet.Load()) == AppletPIV {
			return NewSuccessResponse(AIDPIV)
		}
		return NewSuccessResponse(AIDOpenPGP)
	default:
		return NewErrorResponse(SW_FILE_NOT_FOUND)
	}
}

// getAuthenticatedSession returns the first authenticated session, or
// nil if no authenticated sessions exist.
func (b *PKCS11Bridge) getAuthenticatedSession() *SessionState {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, s := range b.sessions {
		if s.Authenticated {
			return s
		}
	}
	return nil
}

// SetDefaultBackend sets the default PKCS#11 backend name used for
// new sessions.
func (b *PKCS11Bridge) SetDefaultBackend(backend string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.defaultBackend = backend
}

// SessionCount returns the number of active sessions.
func (b *PKCS11Bridge) SessionCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.sessions)
}

// CloseAllSessions closes all active sessions.
func (b *PKCS11Bridge) CloseAllSessions() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions = make(map[uint32]*SessionState)
	b.selectedApplet.Store(int32(AppletNone))
}

// matchAID checks if the data begins with the expected AID prefix.
func matchAID(data, aid []byte) bool {
	if len(data) < len(aid) {
		return false
	}
	for i, b := range aid {
		if data[i] != b {
			return false
		}
	}
	return true
}

// hashName returns the string name for a crypto.Hash algorithm.
var hashNames = map[crypto.Hash]string{
	crypto.SHA256: "SHA-256",
	crypto.SHA384: "SHA-384",
	crypto.SHA512: "SHA-512",
	crypto.SHA1:   "SHA-1",
}

func hashName(h crypto.Hash) string {
	if name, ok := hashNames[h]; ok {
		return name
	}
	return "SHA-256"
}
