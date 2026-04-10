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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed ECDSA P-256 certificate for testing.
func generateTestCert(t *testing.T) (certPEM string, key *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return string(pem.EncodeToMemory(certBlock)), privKey
}

// startMockIPCServer starts a mock IPC server on a temporary Unix socket.
// The handler function receives raw JSON and returns the response bytes.
func startMockIPCServer(t *testing.T, handler func(raw json.RawMessage) []byte) string {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				dec := json.NewDecoder(c)
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return
				}
				resp := handler(raw)
				_, _ = c.Write(resp)
			}(conn)
		}
	}()

	// Wait for the server to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return sockPath
}

// certHandler returns a mock IPC handler that serves the given PEM certificate.
func certHandler(certPEM string) func(raw json.RawMessage) []byte {
	return func(raw json.RawMessage) []byte {
		var msg ipcMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return errorResponse("decode error")
		}

		if msg.PKCS11 == nil {
			return errorResponse("no pkcs11 payload")
		}

		switch msg.PKCS11.Action {
		case "get_piv_certificate":
			resp := ipcResponse{
				Status: "ok",
				PKCS11: &ipcPKCS11Result{
					PIVCert: &ipcPIVCertResult{
						Certificate: certPEM,
						Slot:        msg.PKCS11.PIVCert.Slot,
						Subject:     "CN=test-signer",
						Issuer:      "CN=test-signer",
						NotAfter:    "2030-01-01T00:00:00Z",
					},
				},
			}
			data, _ := json.Marshal(resp)
			return data

		case "sign":
			// Decode the data and sign it with a real key (not available here),
			// so just return a fake signature.
			sig := base64.StdEncoding.EncodeToString([]byte("test-signature"))
			resp := ipcResponse{
				Status: "ok",
				PKCS11: &ipcPKCS11Result{
					Sign: &ipcSignResult{
						Signature: sig,
					},
				},
			}
			data, _ := json.Marshal(resp)
			return data

		default:
			return errorResponse("unknown action: " + msg.PKCS11.Action)
		}
	}
}

// errorResponse creates a JSON error response.
func errorResponse(msg string) []byte {
	resp := ipcResponse{
		Status: "error",
		Error:  msg,
	}
	data, _ := json.Marshal(resp)
	return data
}

func TestNewSigner_ValidConfig(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)
	require.NotNil(t, signer)

	assert.NotNil(t, signer.Public())
	assert.IsType(t, &ecdsa.PublicKey{}, signer.Public())
}

func TestNewSigner_NilConfig(t *testing.T) {
	signer, err := NewSigner(nil)
	assert.Nil(t, signer)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestNewSigner_DefaultSocket(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	t.Setenv(defaultSocketEnvVar, sockPath)

	signer, err := NewSigner(&SignerConfig{})
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.NotNil(t, signer.Public())
}

func TestNewSigner_DefaultSlot(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
	})
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Default slot is "9a".
	assert.Equal(t, "9a", signer.slot)
}

func TestNewSigner_InvalidSlot(t *testing.T) {
	signer, err := NewSigner(&SignerConfig{
		SocketPath: "/tmp/nonexistent.sock",
		Slot:       "invalid",
	})
	assert.Nil(t, signer)
	assert.True(t, errors.Is(err, ErrInvalidSlot))
}

func TestNewSigner_AllValidSlots(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	slots := []string{"9a", "9c", "9d", "9e"}
	for _, slot := range slots {
		t.Run("slot_"+slot, func(t *testing.T) {
			signer, err := NewSigner(&SignerConfig{
				SocketPath: sockPath,
				Slot:       slot,
			})
			require.NoError(t, err)
			require.NotNil(t, signer)
			assert.Equal(t, slot, signer.slot)
		})
	}
}

func TestNewSigner_ConnectionFailed(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	assert.Nil(t, signer)
	assert.Error(t, err)
}

func TestSigner_Public(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	pub := signer.Public()
	require.NotNil(t, pub)
	assert.IsType(t, &ecdsa.PublicKey{}, pub)
}

func TestSigner_Sign_Success(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	digest := []byte("test-digest-data")
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.Equal(t, "test-signature", string(sig))
}

func TestSigner_Sign_Closed(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	require.NoError(t, signer.Close())

	digest := []byte("test-digest")
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	assert.Nil(t, sig)
	assert.True(t, errors.Is(err, ErrClosed))
}

func TestSigner_Sign_IPCError(t *testing.T) {
	certPEM, _ := generateTestCert(t)

	// Create a server that returns cert successfully but errors on sign.
	callCount := 0
	handler := func(raw json.RawMessage) []byte {
		var msg ipcMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return errorResponse("decode error")
		}

		if msg.PKCS11 == nil {
			return errorResponse("no pkcs11 payload")
		}

		switch msg.PKCS11.Action {
		case "get_piv_certificate":
			callCount++
			resp := ipcResponse{
				Status: "ok",
				PKCS11: &ipcPKCS11Result{
					PIVCert: &ipcPIVCertResult{
						Certificate: certPEM,
						Slot:        "9a",
					},
				},
			}
			data, _ := json.Marshal(resp)
			return data

		case "sign":
			return errorResponse("signing key unavailable")

		default:
			return errorResponse("unknown action")
		}
	}

	sockPath := startMockIPCServer(t, handler)

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	digest := []byte("test-digest")
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	assert.Nil(t, sig)
	assert.True(t, errors.Is(err, ErrSignFailed))
}

func TestSigner_Sign_NilOpts(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	digest := []byte("test-digest")
	sig, err := signer.Sign(rand.Reader, digest, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
}

func TestSigner_Sign_VariousHashes(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	for _, h := range hashes {
		t.Run(h.String(), func(t *testing.T) {
			digest := []byte("test-digest")
			sig, err := signer.Sign(rand.Reader, digest, h)
			require.NoError(t, err)
			require.NotEmpty(t, sig)
		})
	}
}

func TestSigner_Certificate_Success(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	cert, err := signer.Certificate()
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "test-signer", cert.Subject.CommonName)
}

func TestSigner_Certificate_NotFound(t *testing.T) {
	handler := func(raw json.RawMessage) []byte {
		return errorResponse("no certificate in slot")
	}
	sockPath := startMockIPCServer(t, handler)

	// Cannot create a signer because NewSigner fetches the cert during init.
	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	assert.Nil(t, signer)
	assert.True(t, errors.Is(err, ErrNoCertificate))
}

func TestSigner_Certificate_InvalidPEM(t *testing.T) {
	handler := func(raw json.RawMessage) []byte {
		resp := ipcResponse{
			Status: "ok",
			PKCS11: &ipcPKCS11Result{
				PIVCert: &ipcPIVCertResult{
					Certificate: "not-valid-pem-data",
					Slot:        "9a",
				},
			},
		}
		data, _ := json.Marshal(resp)
		return data
	}
	sockPath := startMockIPCServer(t, handler)

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	assert.Nil(t, signer)
	assert.True(t, errors.Is(err, ErrInvalidCertFormat))
}

func TestSigner_Certificate_EmptyCert(t *testing.T) {
	handler := func(raw json.RawMessage) []byte {
		resp := ipcResponse{
			Status: "ok",
			PKCS11: &ipcPKCS11Result{
				PIVCert: &ipcPIVCertResult{
					Certificate: "",
					Slot:        "9a",
				},
			},
		}
		data, _ := json.Marshal(resp)
		return data
	}
	sockPath := startMockIPCServer(t, handler)

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	assert.Nil(t, signer)
	assert.True(t, errors.Is(err, ErrNoCertificate))
}

func TestSigner_Certificate_NilPKCS11Result(t *testing.T) {
	handler := func(raw json.RawMessage) []byte {
		resp := ipcResponse{
			Status: "ok",
			PKCS11: nil,
		}
		data, _ := json.Marshal(resp)
		return data
	}
	sockPath := startMockIPCServer(t, handler)

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	assert.Nil(t, signer)
	assert.True(t, errors.Is(err, ErrNoCertificate))
}

func TestSigner_Certificate_Closed(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	require.NoError(t, signer.Close())

	cert, err := signer.Certificate()
	assert.Nil(t, cert)
	assert.True(t, errors.Is(err, ErrClosed))
}

func TestSigner_Close_Idempotent(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	// Close multiple times should not panic or error.
	require.NoError(t, signer.Close())
	require.NoError(t, signer.Close())
	require.NoError(t, signer.Close())

	// Verify the signer is closed.
	_, err = signer.Sign(rand.Reader, []byte("test"), crypto.SHA256)
	assert.True(t, errors.Is(err, ErrClosed))
}

func TestSigner_Sign_NilPKCS11Result(t *testing.T) {
	certPEM, _ := generateTestCert(t)

	callCount := 0
	handler := func(raw json.RawMessage) []byte {
		var msg ipcMessage
		_ = json.Unmarshal(raw, &msg)

		if msg.PKCS11 != nil && msg.PKCS11.Action == "get_piv_certificate" {
			callCount++
			resp := ipcResponse{
				Status: "ok",
				PKCS11: &ipcPKCS11Result{
					PIVCert: &ipcPIVCertResult{
						Certificate: certPEM,
						Slot:        "9a",
					},
				},
			}
			data, _ := json.Marshal(resp)
			return data
		}

		// Return ok but with nil PKCS11 result for sign.
		resp := ipcResponse{
			Status: "ok",
			PKCS11: nil,
		}
		data, _ := json.Marshal(resp)
		return data
	}
	sockPath := startMockIPCServer(t, handler)

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, []byte("test"), crypto.SHA256)
	assert.Nil(t, sig)
	assert.True(t, errors.Is(err, ErrSignFailed))
}

func TestSigner_Sign_InvalidBase64Signature(t *testing.T) {
	certPEM, _ := generateTestCert(t)

	handler := func(raw json.RawMessage) []byte {
		var msg ipcMessage
		_ = json.Unmarshal(raw, &msg)

		if msg.PKCS11 != nil && msg.PKCS11.Action == "get_piv_certificate" {
			resp := ipcResponse{
				Status: "ok",
				PKCS11: &ipcPKCS11Result{
					PIVCert: &ipcPIVCertResult{
						Certificate: certPEM,
						Slot:        "9a",
					},
				},
			}
			data, _ := json.Marshal(resp)
			return data
		}

		// Return an invalid base64 signature.
		resp := ipcResponse{
			Status: "ok",
			PKCS11: &ipcPKCS11Result{
				Sign: &ipcSignResult{
					Signature: "!!!not-valid-base64!!!",
				},
			},
		}
		data, _ := json.Marshal(resp)
		return data
	}
	sockPath := startMockIPCServer(t, handler)

	signer, err := NewSigner(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, []byte("test"), crypto.SHA256)
	assert.Nil(t, sig)
	assert.True(t, errors.Is(err, ErrSignFailed))
}

func TestValidPIVSlots(t *testing.T) {
	assert.True(t, validPIVSlots["9a"])
	assert.True(t, validPIVSlots["9c"])
	assert.True(t, validPIVSlots["9d"])
	assert.True(t, validPIVSlots["9e"])
	assert.False(t, validPIVSlots["9f"])
	assert.False(t, validPIVSlots[""])
	assert.False(t, validPIVSlots["invalid"])
}

func TestHashNames(t *testing.T) {
	assert.Equal(t, "SHA-256", hashNames[crypto.SHA256])
	assert.Equal(t, "SHA-384", hashNames[crypto.SHA384])
	assert.Equal(t, "SHA-512", hashNames[crypto.SHA512])
}

func TestDefaultSocketPath(t *testing.T) {
	// Test with XDG_RUNTIME_DIR set.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	path := defaultSocketPath()
	assert.Equal(t, "/run/user/1000/xkey/xkey.sock", path)

	// Test without XDG_RUNTIME_DIR (fallback).
	t.Setenv("XDG_RUNTIME_DIR", "")
	path = defaultSocketPath()
	assert.Contains(t, path, "/tmp/xkey-")
	assert.Contains(t, path, "/xkey.sock")
}

func TestItoa(t *testing.T) {
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "1", itoa(1))
	assert.Equal(t, "42", itoa(42))
	assert.Equal(t, "1000", itoa(1000))
	assert.Equal(t, "-1", itoa(-1))
	assert.Equal(t, "-42", itoa(-42))
}
