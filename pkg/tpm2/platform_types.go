package tpm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Re-export types from go-keychain/pkg/types for convenience

// KeyAttributes is provided by go-keychain/pkg/types
type KeyAttributes = types.KeyAttributes

// Password is provided by go-keychain/pkg/types
type Password = types.Password

// DEFAULT_PASSWORD is the default password
const DEFAULT_PASSWORD = "changeme"

// CertificateStorer interface for certificate storage operations
type CertificateStorer interface {
	Get(cn string) (*x509.Certificate, error)
	Save(cn string, cert *x509.Certificate) error
	Delete(cn string) error
}

// AESGCM provides AES-GCM encryption
type AESGCM struct {
	random io.Reader
}

// NewAESGCM creates a new AESGCM instance
func NewAESGCM(random io.Reader) *AESGCM {
	if random == nil {
		random = rand.Reader
	}
	return &AESGCM{random: random}
}

// GenerateKey generates a 32-byte AES-256 key
func (a *AESGCM) GenerateKey() []byte {
	key := make([]byte, 32) // AES-256
	if _, err := a.random.Read(key); err != nil {
		panic(fmt.Sprintf("failed to generate random key: %v", err))
	}
	return key
}

// Encrypt encrypts plaintext using AES-GCM
func (a *AESGCM) Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (a *AESGCM) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Errors
var (
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrCertNotFound       = errors.New("certificate not found")
	ErrCorruptCopy        = errors.New("corrupt copy")
)
