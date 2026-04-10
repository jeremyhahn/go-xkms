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

package xkeysigner

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// defaultSocketEnvVar is the environment variable for the IPC socket path.
const defaultSocketEnvVar = "XKEY_IPC_SOCKET"

// defaultSlot is the default PIV slot for authentication.
const defaultSlot = "9a"

// ipcTimeout is the timeout for IPC operations.
const ipcTimeout = 5 * time.Second

// validPIVSlots contains the set of valid PIV slot identifiers for O(1) lookup.
var validPIVSlots = map[string]bool{
	"9a": true, // authentication
	"9c": true, // digital signature
	"9d": true, // key management
	"9e": true, // card authentication
}

// hashNames maps crypto.Hash values to their IPC wire format names.
var hashNames = map[crypto.Hash]string{
	crypto.SHA256: "SHA-256",
	crypto.SHA384: "SHA-384",
	crypto.SHA512: "SHA-512",
}

// SignerConfig configures the IPC signer.
type SignerConfig struct {
	// SocketPath is the Unix domain socket path for the xkey daemon.
	// Defaults to XKEY_IPC_SOCKET env var or the platform default.
	SocketPath string

	// Slot is the PIV slot identifier: "9a" (default), "9c", "9d", "9e".
	Slot string
}

// Signer implements crypto.Signer by delegating signing operations to the
// xkey daemon via IPC over a Unix domain socket. Each Sign call opens a
// fresh connection, sends the request, and reads the response.
type Signer struct {
	socketPath string
	slot       string
	publicKey  crypto.PublicKey
	closed     atomic.Bool
}

// ipcMessage matches the xkey IPC wire format for requests.
type ipcMessage struct {
	Type   string     `json:"type"`
	PKCS11 *ipcPKCS11 `json:"pkcs11,omitempty"`
}

// ipcPKCS11 carries PKCS#11-specific request data.
type ipcPKCS11 struct {
	Action  string         `json:"action"`
	Sign    *ipcSignParams `json:"sign,omitempty"`
	PIVCert *ipcPIVCert    `json:"piv_cert,omitempty"`
}

// ipcSignParams contains parameters for a sign operation.
type ipcSignParams struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Data    string `json:"data"`
	Hash    string `json:"hash,omitempty"`
}

// ipcPIVCert contains parameters for a PIV certificate operation.
type ipcPIVCert struct {
	Backend string `json:"backend"`
	Slot    string `json:"slot"`
	Format  string `json:"format,omitempty"`
}

// ipcResponse matches the xkey IPC wire format for responses.
type ipcResponse struct {
	Status string           `json:"status"`
	Error  string           `json:"error,omitempty"`
	PKCS11 *ipcPKCS11Result `json:"pkcs11,omitempty"`
}

// ipcPKCS11Result carries PKCS#11-specific response data.
type ipcPKCS11Result struct {
	Sign    *ipcSignResult    `json:"sign,omitempty"`
	PIVCert *ipcPIVCertResult `json:"piv_cert,omitempty"`
}

// ipcSignResult contains the result of a sign operation.
type ipcSignResult struct {
	Signature string `json:"signature"`
}

// ipcPIVCertResult contains the certificate data.
type ipcPIVCertResult struct {
	Certificate string `json:"certificate"`
	Slot        string `json:"slot"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    string `json:"not_after"`
}

// NewSigner creates a new IPC-backed crypto.Signer. It validates the config,
// connects to the xkey daemon to fetch the PIV certificate, and extracts the
// public key. The signer is ready to use for TLS client authentication.
func NewSigner(config *SignerConfig) (*Signer, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	socketPath := config.SocketPath
	if socketPath == "" {
		socketPath = os.Getenv(defaultSocketEnvVar)
	}
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}

	slot := config.Slot
	if slot == "" {
		slot = defaultSlot
	}
	if !validPIVSlots[slot] {
		return nil, ErrInvalidSlot
	}

	s := &Signer{
		socketPath: socketPath,
		slot:       slot,
	}

	// Fetch the certificate to extract the public key.
	cert, err := s.Certificate()
	if err != nil {
		return nil, err
	}

	s.publicKey = cert.PublicKey
	if s.publicKey == nil {
		return nil, ErrNilPublicKey
	}

	return s, nil
}

// Public returns the public key associated with the PIV slot certificate.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign delegates the signing operation to the xkey daemon via IPC. The digest
// parameter should be the pre-hashed message. The opts parameter specifies the
// hash function used to produce the digest.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}

	hashName := ""
	if opts != nil {
		if name, ok := hashNames[opts.HashFunc()]; ok {
			hashName = name
		}
	}

	msg := &ipcMessage{
		Type: "pkcs11",
		PKCS11: &ipcPKCS11{
			Action: "sign",
			Sign: &ipcSignParams{
				KeyID: "piv-" + s.slot,
				Data:  base64.StdEncoding.EncodeToString(digest),
				Hash:  hashName,
			},
		},
	}

	resp, err := s.sendIPC(msg)
	if err != nil {
		return nil, err
	}

	if resp.Status != "ok" {
		return nil, ErrSignFailed
	}
	if resp.PKCS11 == nil || resp.PKCS11.Sign == nil {
		return nil, ErrSignFailed
	}

	signature, err := base64.StdEncoding.DecodeString(resp.PKCS11.Sign.Signature)
	if err != nil {
		return nil, ErrSignFailed
	}

	// Return a copy to prevent caller from mutating internal data.
	result := make([]byte, len(signature))
	copy(result, signature)
	return result, nil
}

// Certificate fetches the PIV slot certificate from the xkey daemon via IPC.
func (s *Signer) Certificate() (*x509.Certificate, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}

	msg := &ipcMessage{
		Type: "pkcs11",
		PKCS11: &ipcPKCS11{
			Action: "get_piv_certificate",
			PIVCert: &ipcPIVCert{
				Slot:   s.slot,
				Format: "pem",
			},
		},
	}

	resp, err := s.sendIPC(msg)
	if err != nil {
		return nil, err
	}

	if resp.Status != "ok" {
		return nil, ErrNoCertificate
	}
	if resp.PKCS11 == nil || resp.PKCS11.PIVCert == nil {
		return nil, ErrNoCertificate
	}

	certPEM := resp.PKCS11.PIVCert.Certificate
	if certPEM == "" {
		return nil, ErrNoCertificate
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, ErrInvalidCertFormat
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrInvalidCertFormat
	}

	return cert, nil
}

// Close marks the signer as closed. Subsequent calls to Sign or Certificate
// will return ErrClosed. Close is idempotent.
func (s *Signer) Close() error {
	s.closed.Store(true)
	return nil
}

// sendIPC opens a connection to the xkey daemon, sends the message, reads the
// response, and closes the connection.
func (s *Signer) sendIPC(msg *ipcMessage) (*ipcResponse, error) {
	conn, err := net.DialTimeout("unix", s.socketPath, ipcTimeout)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSocketNotFound
		}
		return nil, ErrConnectionFailed
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(ipcTimeout)); err != nil {
		return nil, ErrConnectionFailed
	}

	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		return nil, ErrConnectionFailed
	}

	var resp ipcResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, ErrConnectionFailed
	}

	return &resp, nil
}

// defaultSocketPath returns the platform default IPC socket path. It uses
// $XDG_RUNTIME_DIR/xkey/xkey.sock when set, and /tmp/xkey-$UID/xkey.sock
// otherwise. This mirrors the logic in xkey/pkg/ipc/socket.go without
// importing it (to avoid circular dependencies).
func defaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir + "/xkey/xkey.sock"
	}
	uid := os.Getuid()
	return "/tmp/xkey-" + itoa(uid) + "/xkey.sock"
}

// itoa converts a non-negative integer to its string representation
// without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
