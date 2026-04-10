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

// Package agent implements an SSH agent that uses xkmsd as its key backend.
package agent

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// KeyBackend interface errors.
var (
	ErrBackendKeyNotFound    = errors.New("backend: key not found")
	ErrBackendKeyExists      = errors.New("backend: key already exists")
	ErrBackendInvalidKeyType = errors.New("backend: invalid key type")
	ErrBackendInvalidKeySize = errors.New("backend: invalid key size")
	ErrBackendInvalidCurve   = errors.New("backend: invalid elliptic curve")
	ErrBackendInvalidKeyData = errors.New("backend: invalid key data")
	ErrBackendConnectionErr  = errors.New("backend: connection error")
	ErrBackendUnsupportedAlg = errors.New("backend: unsupported algorithm")
	ErrBackendClosed         = errors.New("backend: backend is closed")
)

// KeyType represents SSH-compatible key algorithms.
type KeyType = types.KeyAlgorithmString

// KeyType constants for SSH-compatible key algorithms.
const (
	KeyTypeUnknown KeyType = ""
	KeyTypeRSA     KeyType = types.AlgorithmRSA
	KeyTypeECDSA   KeyType = types.AlgorithmECDSA
	KeyTypeEd25519 KeyType = types.AlgorithmEd25519
)

// GenerateOptions specifies parameters for key generation.
type GenerateOptions struct {
	// Bits is the key size for RSA keys (2048, 3072, or 4096).
	// Ignored for ECDSA and Ed25519 keys.
	Bits int

	// Curve specifies the elliptic curve for ECDSA keys.
	// Valid values: "P-256", "P-384", "P-521".
	// Ignored for RSA and Ed25519 keys.
	Curve string

	// Comment is an optional description for the key.
	Comment string
}

// DefaultGenerateOptions returns sensible defaults for key generation.
func DefaultGenerateOptions() *GenerateOptions {
	return &GenerateOptions{
		Bits:  types.RSAKeySize3072,
		Curve: types.CurveP256.String(),
	}
}

// Validate checks that the GenerateOptions are valid for the given key type.
func (o *GenerateOptions) Validate(keyType KeyType) error {
	if o == nil {
		return nil // Will use defaults
	}

	switch keyType {
	case KeyTypeRSA:
		if o.Bits != 0 && o.Bits != types.RSAKeySize2048 &&
			o.Bits != types.RSAKeySize3072 && o.Bits != types.RSAKeySize4096 {
			return ErrBackendInvalidKeySize
		}
	case KeyTypeECDSA:
		if o.Curve != "" && o.Curve != types.CurveP256.String() &&
			o.Curve != types.CurveP384.String() && o.Curve != types.CurveP521.String() {
			return ErrBackendInvalidCurve
		}
	case KeyTypeEd25519:
		// Ed25519 has no configurable options
	default:
		return ErrBackendInvalidKeyType
	}

	return nil
}

// KeyBackend abstracts key storage and cryptographic operations for the SSH agent.
// Implementations must be safe for concurrent use by multiple goroutines.
//
// This interface provides a unified API for different key storage backends:
//   - XKMSdBackend: Uses the xkmsd SDK for remote key management
//   - LocalBackend: Stores keys locally using a storage.Backend
type KeyBackend interface {
	// ListKeys returns all SSH-compatible keys managed by this backend.
	// Returns an empty slice if no keys exist.
	ListKeys(ctx context.Context) ([]*KeyInfo, error)

	// GetPublicKey returns the SSH public key for the given key ID.
	// Returns ErrBackendKeyNotFound if the key does not exist.
	GetPublicKey(ctx context.Context, keyID string) (ssh.PublicKey, error)

	// Sign signs data with the specified key using the given algorithm.
	// The algorithm parameter specifies the signature scheme:
	//   - "ed25519" for Ed25519 keys
	//   - "rsa-sha256", "rsa-sha512" for RSA keys
	//   - "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512" for ECDSA keys
	// Returns ErrBackendKeyNotFound if the key does not exist.
	// Returns ErrBackendSignFailed if the signing operation fails.
	Sign(ctx context.Context, keyID string, data []byte, algorithm string) ([]byte, error)

	// GenerateKey generates a new SSH key with the specified parameters.
	// Returns ErrBackendKeyExists if a key with the same ID already exists.
	// Returns ErrBackendInvalidKeyType if the key type is not supported.
	// Returns ErrBackendGenerateFailed if key generation fails.
	GenerateKey(ctx context.Context, keyID string, keyType KeyType, opts *GenerateOptions) (*KeyInfo, error)

	// ImportKey imports an existing SSH private key.
	// The privateKeyPEM must be a PEM-encoded private key.
	// Supported formats: RSA, ECDSA, Ed25519 in PKCS#1, PKCS#8, or OpenSSH format.
	// Returns ErrBackendKeyExists if a key with the same ID already exists.
	// Returns ErrBackendInvalidKeyData if the PEM data is invalid.
	// Returns ErrBackendImportFailed if the import fails.
	ImportKey(ctx context.Context, keyID string, privateKeyPEM []byte) (*KeyInfo, error)

	// DeleteKey deletes the key with the given ID.
	// Returns ErrBackendKeyNotFound if the key does not exist.
	// Returns ErrBackendDeleteFailed if deletion fails.
	DeleteKey(ctx context.Context, keyID string) error

	// Close releases any resources held by the backend.
	// After Close is called, all other methods will return ErrBackendClosed.
	Close() error
}

// SignatureAlgorithm maps SSH key types to their signature algorithms.
type SignatureAlgorithm string

// Signature algorithm constants.
const (
	SigAlgoEd25519     SignatureAlgorithm = "ed25519"
	SigAlgoRSASHA256   SignatureAlgorithm = "rsa-sha256"
	SigAlgoRSASHA512   SignatureAlgorithm = "rsa-sha512"
	SigAlgoECDSASHA256 SignatureAlgorithm = "ecdsa-sha256"
	SigAlgoECDSASHA384 SignatureAlgorithm = "ecdsa-sha384"
	SigAlgoECDSASHA512 SignatureAlgorithm = "ecdsa-sha512"
)

// SignatureAlgorithmForKey returns the default signature algorithm for a key type.
func SignatureAlgorithmForKey(keyType KeyType) SignatureAlgorithm {
	switch keyType {
	case KeyTypeEd25519:
		return SigAlgoEd25519
	case KeyTypeRSA:
		return SigAlgoRSASHA256
	case KeyTypeECDSA:
		return SigAlgoECDSASHA256
	default:
		return ""
	}
}

// SignatureAlgorithmFromSSH converts an SSH key type to a signature algorithm.
func SignatureAlgorithmFromSSH(sshKeyType string) SignatureAlgorithm {
	switch sshKeyType {
	case ssh.KeyAlgoED25519:
		return SigAlgoEd25519
	case ssh.KeyAlgoRSA:
		return SigAlgoRSASHA256
	case ssh.KeyAlgoRSASHA256:
		return SigAlgoRSASHA256
	case ssh.KeyAlgoRSASHA512:
		return SigAlgoRSASHA512
	case ssh.KeyAlgoECDSA256:
		return SigAlgoECDSASHA256
	case ssh.KeyAlgoECDSA384:
		return SigAlgoECDSASHA384
	case ssh.KeyAlgoECDSA521:
		return SigAlgoECDSASHA512
	default:
		return ""
	}
}

// String returns the string representation of the signature algorithm.
func (s SignatureAlgorithm) String() string {
	return string(s)
}

// IsValidKeyType returns true if the key type is supported for SSH.
func IsValidKeyType(keyType KeyType) bool {
	switch keyType {
	case KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519:
		return true
	default:
		return false
	}
}

// KeyTypeFromSSH converts an SSH key algorithm string to a KeyType.
func KeyTypeFromSSH(sshKeyType string) KeyType {
	switch sshKeyType {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return KeyTypeRSA
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return KeyTypeECDSA
	case ssh.KeyAlgoED25519:
		return KeyTypeEd25519
	default:
		return ""
	}
}

// CurveFromSSHKeyType extracts the curve name from an SSH ECDSA key type.
func CurveFromSSHKeyType(sshKeyType string) string {
	switch sshKeyType {
	case ssh.KeyAlgoECDSA256:
		return types.CurveP256.String()
	case ssh.KeyAlgoECDSA384:
		return types.CurveP384.String()
	case ssh.KeyAlgoECDSA521:
		return types.CurveP521.String()
	default:
		return ""
	}
}

// KeyTypeToString converts a KeyType to its string representation
// suitable for use with xkmsd backend APIs.
// Returns the canonical algorithm names that xkmsd expects.
func KeyTypeToString(keyType KeyType) string {
	switch keyType {
	case KeyTypeEd25519:
		return "Ed25519"
	case KeyTypeRSA:
		return "RSA"
	case KeyTypeECDSA:
		return "ECDSA"
	default:
		return ""
	}
}

// ParseKeyType parses a string into a KeyType.
// Accepts case-insensitive algorithm names and SSH-style algorithm identifiers.
func ParseKeyType(s string) KeyType {
	switch s {
	case "ed25519", "Ed25519", "ED25519", ssh.KeyAlgoED25519:
		return KeyTypeEd25519
	case "rsa", "RSA", ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return KeyTypeRSA
	case "ecdsa", "ECDSA", ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return KeyTypeECDSA
	default:
		return ""
	}
}
