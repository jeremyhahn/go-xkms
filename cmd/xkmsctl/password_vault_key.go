// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
)

// This file is the key-factor half of the vault verbs: a vault factor whose
// secret only a private key the operator holds recovers -- a certificate's
// key or a TPM key. The key is reached through the same xkms key backends
// xkmsd and xkey use, opened locally from flags; vaulttoken (shared with
// xkey) does the work.
//
//   --key-file / --cert-file       a software key (PEM), e.g. a client certificate's
//   --tpm-device / --tpm-data-dir  a TPM 2.0 key, under "platform" or a named policy
//
// xkmsctl is built without CGO, so it has no PKCS#11: PIV cards and PKCS#11
// tokens are xkey's (ErrVaultKeyNeedsXkey).

// Key-factor flags.
const (
	keyFactorFlag  = "key-factor"
	keyUnlockFlag  = "key"
	keyFileFlag    = "key-file"
	certFileFlag   = "cert-file"
	keyIDFlag      = "key-id"
	tpmDeviceFlag  = "tpm-device"
	tpmDataDirFlag = "tpm-data-dir"
	tpmPolicyFlag  = "tpm-policy"
	tpmCreateFlag  = "tpm-create"
)

// Key-factor errors.
var (
	// ErrVaultKeyConflict indicates a key factor combined with another
	// factor, or with more than one key source.
	ErrVaultKeyConflict = errors.New("vault: a key factor takes exactly one key source (--key-file or --tpm-data-dir) and no --passkey or --passphrase")

	// ErrVaultKeySourceRequired indicates a key factor without a key source.
	ErrVaultKeySourceRequired = errors.New("vault: name the key: --key-file (software) or --tpm-data-dir (TPM)")

	// ErrVaultKeyFileInvalid indicates a key or certificate file that is not
	// a PEM private key or certificate.
	ErrVaultKeyFileInvalid = errors.New("vault: not a PEM private key or certificate")

	// ErrVaultKeyNeedsXkey indicates a PIV or PKCS#11 key factor: xkmsctl
	// is built without CGO and so without PKCS#11, and those factors are
	// xkey's.
	ErrVaultKeyNeedsXkey = errors.New("vault: use xkey for PIV/PKCS#11 factors")
)

// addKeyFactorEnrollFlags declares the key-factor flags of enroll and
// recover.
func addKeyFactorEnrollFlags(cmd *cobra.Command) {
	cmd.Flags().String(keyFactorFlag, "", "enroll a key factor instead: certificate or tpm (piv: use xkey)")
	addKeySourceFlags(cmd)
	cmd.Flags().String(tpmPolicyFlag, "", "TPM policy --tpm-create binds the key to: \"platform\" (default) or a named policy in --tpm-data-dir")
	cmd.Flags().Bool(tpmCreateFlag, false, "create the TPM key --key-id when it does not exist")
}

// addKeyFactorUnlockFlags declares --key and the key sources on unlock.
func addKeyFactorUnlockFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(keyUnlockFlag, false, "unlock with a certificate or TPM key factor whose key is given by the key-source flags")
	addKeySourceFlags(cmd)
}

func addKeySourceFlags(cmd *cobra.Command) {
	cmd.Flags().String(keyFileFlag, "", "PEM private key of a software key factor (e.g. a client certificate's key)")
	cmd.Flags().String(certFileFlag, "", "PEM certificate of the key (a certificate factor needs one)")
	cmd.Flags().String(keyIDFlag, "", "the TPM key's ID (label)")
	cmd.Flags().String(tpmDeviceFlag, "/dev/tpmrm0", "TPM 2.0 device, or tcp://host:port for a TPM over TCP (swtpm)")
	cmd.Flags().String(tpmDataDirFlag, "", "TPM data directory: the TPM's key store and named-policy registry (xkey's data directory shares them)")
}

// keySource is a resolved key-factor key source: a token for a software key,
// or a backend lookup for a TPM.
type keySource struct {
	ref    client.PasswordVaultKeyRef
	token  vaulttoken.Token
	cert   *x509.Certificate
	lookup vaulttoken.Lookup
	close  func()
}

// resolveVaultKeySource returns the key-factor credential source the verb
// asked for, or nil when it asked for none.
func resolveVaultKeySource(cmd *cobra.Command, label string, purpose vaultCredentialPurpose) (vaultCredentialSource, func(), error) {
	fr := newFlagReader(cmd)
	var factor string
	if purpose == vaultUnlock {
		if !fr.Bool(keyUnlockFlag) {
			return nil, nil, fr.Err()
		}
	} else if factor = fr.String(keyFactorFlag); factor == "" {
		return nil, nil, fr.Err()
	}
	if fr.Bool("passkey") || fr.String("passphrase") != "" {
		return nil, nil, ErrVaultKeyConflict
	}
	if factor == vaulttoken.FactorPIV {
		return nil, nil, ErrVaultKeyNeedsXkey
	}
	if err := fr.Err(); err != nil {
		return nil, nil, err
	}
	src, err := openKeySource(cmd, factor)
	if err != nil {
		return nil, nil, err
	}
	if purpose == vaultUnlock {
		return src.unlockSource(), src.close, nil
	}
	return src.enrollSource(factor, label), src.close, nil
}

// openKeySource opens the one key source the flags name.
func openKeySource(cmd *cobra.Command, factor string) (*keySource, error) {
	fr := newFlagReader(cmd)
	keyFile, certFile := fr.String(keyFileFlag), fr.String(certFileFlag)
	dataDir, keyID := fr.String(tpmDataDirFlag), fr.String(keyIDFlag)
	if err := fr.Err(); err != nil {
		return nil, err
	}
	switch {
	case keyFile != "" && dataDir != "":
		return nil, ErrVaultKeyConflict
	case keyFile != "":
		return softwareKeySource(keyFile, certFile)
	case dataDir != "":
		return tpmKeySource(cmd, factor, dataDir, keyID)
	default:
		return nil, ErrVaultKeySourceRequired
	}
}

// softwareKeySource reads a PEM private key (and certificate) from files.
func softwareKeySource(keyFile, certFile string) (*keySource, error) {
	priv, err := readPEMPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}
	tok, err := vaulttoken.NewKeyToken(priv)
	if err != nil {
		return nil, err
	}
	src := &keySource{ref: client.PasswordVaultKeyRef{Backend: "software"}, token: tok, close: func() {}}
	if certFile != "" {
		if src.cert, err = readPEMCertificate(certFile); err != nil {
			return nil, err
		}
	}
	return src, nil
}

// vaultTPM is the host's TPM as the vault's TPM key source uses it: the
// key backend of the TPM policy service, and Close.
type vaultTPM interface {
	Backend() *client.TPM2Backend
	Close() error
}

// openTPMHost opens the host's TPM and the TPM policy service over it --
// the same one xkey runs -- with its stores under dataDir. It is a variable
// so tests can run on the simulator.
var openTPMHost = func(dataDir, device string) (vaultTPM, error) {
	return localtpm.OpenHost(localtpm.DeviceParams{DataDir: dataDir, Device: device}, openFileStore)
}

// openFileStore opens the file store rooted at dir, the engine xkey uses
// unless its config selects another.
func openFileStore(dir string) (client.StorageBackend, error) {
	return client.StorageOpenEngine(client.StorageEngineConfig{Kind: client.StorageEngineFile, Path: dir})
}

// tpmKeySource opens the TPM with its key store and policy registry in
// dataDir, creating the key under --tpm-policy with --tpm-create.
func tpmKeySource(cmd *cobra.Command, factor, dataDir, keyID string) (*keySource, error) {
	fr := newFlagReader(cmd)
	device := fr.String(tpmDeviceFlag)
	var create bool
	var policy string
	if cmd.Flags().Lookup(tpmCreateFlag) != nil {
		create, policy = fr.Bool(tpmCreateFlag), fr.String(tpmPolicyFlag)
	}
	if err := fr.Err(); err != nil {
		return nil, err
	}
	if policy == "" && factor == vaulttoken.FactorTPM {
		policy = client.TPMPolicyPlatform
	}
	host, err := openTPMHost(dataDir, device)
	if err != nil {
		return nil, err
	}
	if create {
		if err := createTPMKey(host.Backend(), keyID, policy); err != nil {
			return nil, errors.Join(err, host.Close())
		}
	}
	src, err := backendKeySource(host.Backend(), string(client.BackendTPM2), keyID, host.Close)
	if err != nil {
		return nil, err
	}
	src.ref.TPMPolicy = policy
	return src, nil
}

// createTPMKey creates EC P-256 encryption key keyID in the TPM, bound to
// policy, unless it exists. The TPM policy service records the binding, so
// the policy lists the key and cannot be deleted under it.
func createTPMKey(kp client.KeyProvider, keyID, policy string) error {
	ctx := context.Background()
	if keys, err := kp.ListKeys(ctx); err == nil {
		for _, k := range keys {
			if k != nil && k.CN == keyID {
				return nil
			}
		}
	}
	_, err := kp.GenerateKey(ctx, &client.KeyAttributes{
		CN: keyID, KeyAlgorithm: x509.ECDSA, KeyType: client.KeyTypeEncryption,
		ECCAttributes: &client.ECCAttributes{Curve: elliptic.P256()}, TPMPolicy: policy,
	})
	return err
}

// backendKeySource wraps a key provider as the one xkms backend a key
// factor resolves through.
// The key provider belongs to what opened it, and closeFn -- that owner's
// Close -- is the source's close.
func backendKeySource(kp client.KeyProvider, name, keyID string, closeFn func() error) (*keySource, error) {
	b, err := client.NewServiceBackend(&client.ServiceBackendConfig{Backend: kp, CertStorage: client.NewStorageMemory()})
	if err != nil {
		return nil, errors.Join(err, closeFn())
	}
	lookup := func(string) (client.ServiceBackend, error) { return b, nil }
	return &keySource{
		ref:    client.PasswordVaultKeyRef{Backend: name, KeyID: keyID},
		lookup: lookup,
		close: func() {
			if err := closeFn(); err != nil {
				fmt.Fprintln(os.Stderr, "warning: closing the key backend:", err)
			}
		},
	}, nil
}

// enrollSource resolves the key, self-tests it and builds the enrollment
// credential.
func (s *keySource) enrollSource(factor, label string) vaultCredentialSource {
	return func(ctx context.Context, _ client.Client) (client.PasswordVaultCredential, error) {
		key, err := s.key(ctx, factor)
		if err != nil {
			return client.PasswordVaultCredential{}, err
		}
		if err := vaulttoken.SelfTest(ctx, key.Token); err != nil {
			return client.PasswordVaultCredential{}, err
		}
		return vaulttoken.EnrollCredential(factor, key, label)
	}
}

// key resolves the factor's key from the source.
func (s *keySource) key(ctx context.Context, factor string) (*vaulttoken.Key, error) {
	if s.token == nil {
		return vaulttoken.Resolve(ctx, s.lookup, factor, s.ref)
	}
	if factor != vaulttoken.FactorPIV && factor != vaulttoken.FactorCertificate && factor != vaulttoken.FactorTPM {
		return nil, vaulttoken.ErrUnknownFactor
	}
	if factor == vaulttoken.FactorCertificate && s.cert == nil {
		return nil, vaulttoken.ErrCertificateRequired
	}
	if s.cert != nil {
		a, errA := vaulttoken.Fingerprint(s.token.Public())
		b, errB := vaulttoken.Fingerprint(s.cert.PublicKey)
		if errA != nil || errB != nil || a != b {
			return nil, vaulttoken.ErrCertificateMismatch
		}
	}
	return &vaulttoken.Key{Token: s.token, Certificate: s.cert, Ref: s.ref}, nil
}

// unlockSource reads the vault's factors and recovers the secret of the one
// the source holds the key of.
func (s *keySource) unlockSource() vaultCredentialSource {
	return func(ctx context.Context, cl client.Client) (client.PasswordVaultCredential, error) {
		status, err := cl.PasswordVaultStatus(ctx)
		if err != nil {
			return client.PasswordVaultCredential{}, &WrappedError{Sentinel: ErrVaultStatusFailed, Err: err}
		}
		if s.token != nil {
			return vaulttoken.UnlockCredential(ctx, s.token, status.Factors)
		}
		return vaulttoken.Find(ctx, s.lookup, status.Factors)
	}
}

func readPEMPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator names the key file
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrVaultKeyFileInvalid
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, ErrVaultKeyFileInvalid
}

func readPEMCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator names the certificate file
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrVaultKeyFileInvalid
	}
	return x509.ParseCertificate(block.Bytes)
}
