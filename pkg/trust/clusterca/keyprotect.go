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

package clusterca

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// KeyProtectionMode selects how the node-local cluster CA keystore password is
// protected at rest. The values match the canonical stack seal vocabulary.
type KeyProtectionMode string

const (
	// KeyProtectAuto selects the strongest available protection: a
	// TPM/HSM-sealed key when a usable sealer is present, else an
	// operator passphrase, else (only when insecure mode is explicitly
	// allowed) plaintext. This is the default.
	KeyProtectAuto KeyProtectionMode = ""

	// KeyProtectNone stores the CA keystore in plaintext PKCS#8. Permitted
	// only for development/testing with insecure mode explicitly enabled.
	KeyProtectNone KeyProtectionMode = "none"

	// KeyProtectPassphrase encrypts the CA keystore (PBES2) with an
	// operator-supplied passphrase.
	KeyProtectPassphrase KeyProtectionMode = "passphrase"

	// KeyProtectTPM2 encrypts the CA keystore with a random key that is
	// TPM-sealed to a node-local blob (PCR-policy bound), unsealed at boot
	// with no operator interaction.
	KeyProtectTPM2 KeyProtectionMode = "tpm2"

	// KeyProtectPKCS11 is the HSM equivalent of KeyProtectTPM2.
	KeyProtectPKCS11 KeyProtectionMode = "pkcs11"
)

// caKeySealFile is the node-local file holding the sealed CA-keystore password
// blob for hardware-sealed modes.
const caKeySealFile = "ca-key-seal.json"

// KeyProtection resolves the password used to encrypt the node-local cluster
// CA keystore, reusing the stack's standard seal machinery (a hardware
// types.Sealer for tpm2/pkcs11, an operator passphrase otherwise) so no
// parallel key-protection crypto is introduced. It is deliberately transport-
// and backend-agnostic: the composition root injects a ready Sealer and the
// operator passphrase; this type only decides the mode and performs the
// seal/unseal + cache bookkeeping.
type KeyProtection struct {
	// Mode selects the protection strategy (KeyProtectAuto by default).
	Mode KeyProtectionMode

	// DataDir is where the sealed password blob is cached (hardware modes).
	DataDir string

	// Passphrase is the operator passphrase for KeyProtectPassphrase (and the
	// passphrase fallback in KeyProtectAuto), sealed in a long-lived memguard
	// enclave. Nil disables passphrase mode. The composition root converts
	// the resolved config-sourced types.SecretValue into this Secret (see
	// Server.clusterCAKeyProtection) so the plaintext passphrase is never
	// held as a plain Go string.
	Passphrase *secure.Secret

	// Sealer seals/unseals the random CA-keystore password for the hardware
	// modes. Nil when no TPM/HSM is available; KeyProtectAuto then falls back
	// to passphrase.
	Sealer types.Sealer

	// SealStrategyID identifies which hardware strategy Sealer represents
	// ("tpm2" / "pkcs11"), for logging and mode validation. Optional.
	SealStrategyID string

	// AllowInsecure permits plaintext CA keys (KeyProtectNone / the last
	// resort of KeyProtectAuto). The caller derives it from an explicit
	// KeyProtectNone selection; it is not a daemon-level insecure mode.
	AllowInsecure bool

	// Logger receives protection-selection diagnostics.
	Logger *slog.Logger
}

// Resolve returns the password to encrypt the CA keystore and whether
// plaintext persistence must be permitted (only true for the none mode). It
// performs a first-boot seal or a subsequent-boot unseal for hardware modes,
// caching the sealed blob under DataDir so restarts recover the same password
// without operator interaction.
func (k *KeyProtection) Resolve(ctx context.Context) (types.Password, bool, error) {
	logger := k.Logger
	if logger == nil {
		logger = slog.Default()
	}

	switch k.effectiveMode() {
	case KeyProtectTPM2, KeyProtectPKCS11:
		pw, err := k.resolveSealed(ctx)
		if err != nil {
			return nil, false, err
		}
		logger.Info("cluster CA keystore protected by hardware-sealed key",
			"strategy", k.sealStrategyLabel())
		return pw, false, nil

	case KeyProtectPassphrase:
		logger.Info("cluster CA keystore protected by operator passphrase")
		pw, err := passwordFromSecret(k.Passphrase)
		if err != nil {
			return nil, false, err
		}
		return pw, false, nil

	case KeyProtectNone:
		if !k.AllowInsecure {
			return nil, false, &ErrNoSecureCAKeyProtection{}
		}
		logger.Warn("cluster CA keystore is UNPROTECTED (plaintext keys) — development/testing only")
		pw, err := types.NewPassword(nil)
		if err != nil {
			return nil, false, err
		}
		return pw, true, nil

	default:
		return nil, false, &ErrNoSecureCAKeyProtection{}
	}
}

// effectiveMode resolves KeyProtectAuto against what is available, and returns
// an explicit mode unchanged. An unavailable explicit mode resolves to itself
// so Resolve surfaces a precise error rather than silently downgrading.
func (k *KeyProtection) effectiveMode() KeyProtectionMode {
	switch k.Mode {
	case KeyProtectTPM2, KeyProtectPKCS11, KeyProtectPassphrase, KeyProtectNone:
		return k.Mode
	case KeyProtectAuto:
		switch {
		case k.Sealer != nil && k.Sealer.CanSeal():
			if k.SealStrategyID == string(KeyProtectPKCS11) {
				return KeyProtectPKCS11
			}
			return KeyProtectTPM2
		case k.Passphrase != nil:
			return KeyProtectPassphrase
		case k.AllowInsecure:
			return KeyProtectNone
		default:
			// No secure option and insecure not allowed → surface the error.
			return KeyProtectAuto
		}
	default:
		return KeyProtectAuto
	}
}

// resolveSealed loads the cached sealed password blob and unseals it, or on
// first boot generates a random password, seals it, and caches the blob.
func (k *KeyProtection) resolveSealed(ctx context.Context) (types.Password, error) {
	if k.Sealer == nil || !k.Sealer.CanSeal() {
		return nil, &ErrSealerUnavailable{Mode: string(k.effectiveMode())}
	}
	blobPath := filepath.Join(k.DataDir, caKeySealFile)

	if data, err := os.ReadFile(blobPath); err == nil {
		var sealed types.SealedData
		if jsonErr := json.Unmarshal(data, &sealed); jsonErr != nil {
			return nil, &ErrSealBlobCorrupt{Path: blobPath, Err: jsonErr}
		}
		plaintext, unsealErr := k.Sealer.Unseal(ctx, &sealed, &types.UnsealOptions{})
		if unsealErr != nil {
			return nil, unsealErr
		}
		return types.NewPassword(plaintext)
	}

	// First boot: generate a random 32-byte keystore password and seal it.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	sealed, err := k.Sealer.Seal(ctx, secret, &types.SealOptions{})
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(k.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		return nil, err
	}
	return types.NewPassword(secret)
}

// passwordFromSecret opens sec and converts its plaintext into a
// types.Password, mirroring types.NewPasswordFromString's "empty is no
// authentication, not an error" contract for the nil case: a nil Secret
// (KeyProtection.Passphrase never set) still resolves to a usable,
// passwordless Password rather than an error, matching the pre-enclave
// behaviour of NewPasswordFromString("").
func passwordFromSecret(sec *secure.Secret) (types.Password, error) {
	if sec == nil {
		return types.NewPassword(nil)
	}
	buf, err := sec.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	//secure:unborrowed allocates-protected types.NewPassword copies the passphrase into its own protected Buffer
	return types.NewPassword(buf.Bytes())
}

// sealStrategyLabel returns a human label for the active hardware strategy.
func (k *KeyProtection) sealStrategyLabel() string {
	if k.SealStrategyID != "" {
		return k.SealStrategyID
	}
	return string(KeyProtectTPM2)
}
