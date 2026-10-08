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
	"log/slog"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	"github.com/jeremyhahn/go-enclave"
)

// NodeLocalBackendsParams configures NewNodeLocalBackends. It is the single,
// product-agnostic description of how a composition root (xkmsd, quicbaasd, any
// SDK consumer) builds the PRE-NODE key backends the cluster ACME provisioner
// needs — before the embedded qrdb datastore exists — so every product wires
// cluster CA key protection the same way rather than reinventing it.
type NodeLocalBackendsParams struct {
	// DataDir is the node-local cluster identity directory (e.g.
	// {Storage.Path}/cluster-ca). Keys live under DataDir/keys, certificates
	// under DataDir/certs.
	DataDir string

	// CAConfig is the CA identity hierarchy whose signing keys the software
	// backend holds. The resolved keystore password (below) is injected into
	// its identities so the keys are encrypted at rest. May be nil when only a
	// node transport key (no pre-staged CA) is needed.
	CAConfig *ca.MultiIdentityCAConfig

	// Protection selects how the node-local CA signing keystore is protected at
	// rest (TPM/HSM-sealed, passphrase, or — insecure — plaintext). Its DataDir
	// is defaulted to this params' DataDir when unset.
	Protection KeyProtection

	// HardwareTPM, when a *tpm2 backend, is reused as the "tpm2" node key
	// backend so the TPM is never opened twice (a shared open from the seal
	// autodetect). Nil disables hardware node keys (software only).
	HardwareTPM types.Sealer

	// Logger receives diagnostics. Defaults to slog.Default when nil.
	Logger *slog.Logger
}

// injectKeystorePassword resolves the KeyProtection keystore password and
// injects it into every CA identity's key configs and software keystore, so the
// software backend encrypts the CA signing keys at rest. It is a no-op when the
// protection resolves to plaintext (development) or no CA config is supplied.
func injectKeystorePassword(ctx context.Context, protection *KeyProtection, caConfig *ca.MultiIdentityCAConfig) error {
	password, plaintext, err := protection.Resolve(ctx)
	if err != nil {
		return err
	}
	if plaintext || password == nil || caConfig == nil {
		return nil
	}
	pwBytes := password.Bytes()
	defer enclave.Wipe(pwBytes)
	// Each target field gets its own enclave (NewLiteralSecretValue reseals
	// pwBytes afresh per call) rather than sharing one SecretValue struct
	// copy across every identity's key and keystore password fields.
	for i := range caConfig.Identity {
		id := &caConfig.Identity[i]
		for j := range id.Keys {
			if id.Keys[j].Password, err = types.NewLiteralSecretValue(ctx, pwBytes); err != nil {
				return err
			}
		}
		if id.Keystores != nil && id.Keystores.Software != nil {
			if id.Keystores.Software.Password, err = types.NewLiteralSecretValue(ctx, pwBytes); err != nil {
				return err
			}
		}
	}
	return nil
}

// NewNodeLocalBackends builds the PRE-NODE key-backend resolver the cluster ACME
// provisioner uses. It runs before the embedded qrdb datastore exists, so the
// backends are constructed directly over node-local storage under DataDir. The
// CA signing keystore is protected at rest via the canonical seal strategies
// (KeyProtection): the resolved keystore password is injected into the CA
// identities so the software backend encrypts the keys with it. A hardware node
// key ("tpm2") reuses the single TPM opened by the seal autodetect.
//
// This is the one shared implementation every product's composition root calls
// so cluster CA key protection works identically across the stack.
func NewNodeLocalBackends(ctx context.Context, params *NodeLocalBackendsParams) (func(string) (xkms.Backend, error), error) {
	set, err := newNodeLocalBackendSet(ctx, params)
	if err != nil {
		return nil, err
	}
	return set.resolve, nil
}

// nodeLocalBackendSet is the node-local software backend plus the underlying
// storage handles, so a caller (e.g. the barrier key strategy) can copy the key
// blobs into a replicated store during promotion.
type nodeLocalBackendSet struct {
	resolve     func(string) (xkms.Backend, error)
	keyStorage  storage.Backend
	certStorage storage.Backend
}

// newNodeLocalBackendSet builds the node-local backends and returns the resolver
// together with the underlying key/cert storage handles.
func newNodeLocalBackendSet(ctx context.Context, params *NodeLocalBackendsParams) (*nodeLocalBackendSet, error) {
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}

	protection := params.Protection
	if protection.DataDir == "" {
		protection.DataDir = params.DataDir
	}
	if protection.Logger == nil {
		protection.Logger = logger
	}
	if protection.Sealer == nil {
		protection.Sealer = params.HardwareTPM
	}

	if err := injectKeystorePassword(ctx, &protection, params.CAConfig); err != nil {
		return nil, err
	}

	// Build the node-local software backend (CA signing keys + node transport
	// key) over persistent storage so material survives restarts.
	keyStorage, err := storage.NewFile(filepath.Join(params.DataDir, "keys"))
	if err != nil {
		return nil, err
	}
	certStorage, err := storage.NewFile(filepath.Join(params.DataDir, "certs"))
	if err != nil {
		return nil, err
	}
	softwareBackend, err := newSoftwareBackend(keyStorage, certStorage)
	if err != nil {
		return nil, err
	}

	hardwareTPM := params.HardwareTPM

	resolve := func(name string) (xkms.Backend, error) {
		// Reuse the single TPM opened by the seal autodetect for a hardware node
		// key so the device is never opened twice (swtpm hangs on a second open).
		// The TPM backend is both a types.Sealer and a types.KeyProvider.
		if name == "tpm2" && hardwareTPM != nil {
			if provider, ok := hardwareTPM.(types.KeyProvider); ok {
				return xkms.New(&xkms.BackendConfig{
					Backend:     provider,
					CertStorage: certStorage,
				})
			}
		}
		// Software keys (CA signing key and, by default, the node transport key)
		// resolve to the node-local software backend.
		return softwareBackend, nil
	}

	return &nodeLocalBackendSet{
		resolve:     resolve,
		keyStorage:  keyStorage,
		certStorage: certStorage,
	}, nil
}
