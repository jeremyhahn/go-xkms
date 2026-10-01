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
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	"github.com/jeremyhahn/go-xkms/pkg/vaulttoken"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// This file is the key-factor half of the vault verbs: a vault factor whose
// secret only a private key the operator holds recovers -- the slot 9d key
// of a PIV card or a PKCS#11 token, a certificate's key, or a TPM key. The
// key is reached through the same xkms key backends xkmsd and xkey use,
// opened locally from flags; vaulttoken (shared with xkey) does the work.
//
//   --key-file / --cert-file      a software key (PEM), e.g. a client certificate's
//   --key-pkcs11-module ...          a PKCS#11 token: a PIV card's module, an HSM, SoftHSM
//   --tpm-device / --tpm-keystore a TPM 2.0 key under the built-in "platform" policy

// Key-factor flags.
const (
	keyFactorFlag     = "key-factor"
	keyUnlockFlag     = "key"
	keyFileFlag       = "key-file"
	certFileFlag      = "cert-file"
	keyIDFlag         = "key-id"
	pkcs11LibraryFlag = "key-pkcs11-module"
	pkcs11TokenFlag   = "key-pkcs11-token"
	keyPINFlag        = "key-pin"
	tpmDeviceFlag     = "tpm-device"
	tpmKeystoreFlag   = "tpm-keystore"
	tpmPolicyFlag     = "tpm-policy"
	tpmCreateFlag     = "tpm-create"
)

// Key-factor errors.
var (
	// ErrVaultKeyConflict indicates a key factor combined with another
	// factor, or with more than one key source.
	ErrVaultKeyConflict = errors.New("vault: a key factor takes exactly one key source (--key-file, --key-pkcs11-module or --tpm-keystore) and no --passkey or --passphrase")

	// ErrVaultKeySourceRequired indicates a key factor without a key source.
	ErrVaultKeySourceRequired = errors.New("vault: name the key: --key-file (software), --key-pkcs11-module (PIV card, PKCS#11 token) or --tpm-keystore (TPM)")

	// ErrVaultKeyFileInvalid indicates a key or certificate file that is not
	// a PEM private key or certificate.
	ErrVaultKeyFileInvalid = errors.New("vault: not a PEM private key or certificate")

	// ErrVaultPKCS11Unavailable indicates a PKCS#11 key source in an
	// xkmsctl built without PKCS#11 (the CGO-free release build).
	ErrVaultPKCS11Unavailable = errors.New("vault: this xkmsctl was built without PKCS#11 support (build with -tags pkcs11), or use xkey")

	// ErrVaultTPMUnavailable indicates an xkmsctl without the TPM 2.0 key
	// backend.
	ErrVaultTPMUnavailable = errors.New("vault: this xkmsctl was built without the TPM 2.0 key backend")

	// ErrVaultTPMNamedPolicy indicates --tpm-create with a named TPM policy:
	// a named policy lives in a policy registry xkmsctl does not run locally.
	ErrVaultTPMNamedPolicy = errors.New("vault: xkmsctl creates TPM keys under the built-in \"platform\" policy only; create a key under a named policy with xkey")
)

// addKeyFactorEnrollFlags declares the key-factor flags of enroll and
// recover.
func addKeyFactorEnrollFlags(cmd *cobra.Command) {
	cmd.Flags().String(keyFactorFlag, "", "enroll a key factor instead: piv, certificate or tpm")
	addKeySourceFlags(cmd)
	cmd.Flags().String(tpmPolicyFlag, "", "TPM policy the TPM key is bound to (recorded; --tpm-create supports \"platform\")")
	cmd.Flags().Bool(tpmCreateFlag, false, "create the TPM key --key-id in --tpm-keystore when it does not exist")
}

// addKeyFactorUnlockFlags declares --key and the key sources on unlock.
func addKeyFactorUnlockFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(keyUnlockFlag, false, "unlock with a PIV, certificate or TPM key factor whose key is given by the key-source flags")
	addKeySourceFlags(cmd)
}

func addKeySourceFlags(cmd *cobra.Command) {
	cmd.Flags().String(keyFileFlag, "", "PEM private key of a software key factor (e.g. a client certificate's key)")
	cmd.Flags().String(certFileFlag, "", "PEM certificate of the key (a certificate factor needs one)")
	cmd.Flags().String(keyIDFlag, "", "the key's ID (label) in the PKCS#11 token or TPM keystore; piv defaults to slot 9d")
	cmd.Flags().String(pkcs11LibraryFlag, "", "PKCS#11 module of the PIV card or token")
	cmd.Flags().String(pkcs11TokenFlag, "", "PKCS#11 token label")
	cmd.Flags().String(keyPINFlag, "", "user PIN of the PKCS#11 token holding the key ('-' reads stdin; prompted when omitted)")
	cmd.Flags().String(tpmDeviceFlag, "/dev/tpmrm0", "TPM 2.0 device")
	cmd.Flags().String(tpmKeystoreFlag, "", "directory holding the TPM key blobs")
}

// keySource is a resolved key-factor key source: a token for a software key,
// or a backend lookup for a PKCS#11 token or TPM.
type keySource struct {
	ref    client.PasswordVaultKeyRef
	token  vaultkey.Token
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
	library, keystore := fr.String(pkcs11LibraryFlag), fr.String(tpmKeystoreFlag)
	keyID := fr.String(keyIDFlag)
	if err := fr.Err(); err != nil {
		return nil, err
	}
	sources := 0
	for _, set := range []bool{keyFile != "", library != "", keystore != ""} {
		if set {
			sources++
		}
	}
	switch {
	case sources > 1:
		return nil, ErrVaultKeyConflict
	case sources == 0:
		return nil, ErrVaultKeySourceRequired
	case keyFile != "":
		return softwareKeySource(keyFile, certFile)
	case library != "":
		return pkcs11KeySource(cmd, library, keyID)
	default:
		return tpmKeySource(cmd, factor, keystore, keyID)
	}
}

// softwareKeySource reads a PEM private key (and certificate) from files.
func softwareKeySource(keyFile, certFile string) (*keySource, error) {
	priv, err := readPEMPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}
	tok, err := vaultkey.NewKeyToken(priv)
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

// pkcs11KeySource opens the PKCS#11 token -- a PIV card's module, an HSM,
// SoftHSM -- as an xkms key backend.
func pkcs11KeySource(cmd *cobra.Command, library, keyID string) (*keySource, error) {
	factory, ok := xkms.GetBackendFactory(xkms.BackendPKCS11)
	if !ok {
		return nil, ErrVaultPKCS11Unavailable
	}
	fr := newFlagReader(cmd)
	token, pinFlag := fr.String(pkcs11TokenFlag), fr.String(keyPINFlag)
	if err := fr.Err(); err != nil {
		return nil, err
	}
	pin, err := resolveSecret(pinFlag, "PKCS#11 PIN")
	if err != nil {
		return nil, err
	}
	kp, err := factory(map[string]interface{}{
		"library": library, "label": token, "pin": pin,
		"key_storage": storage.New(), "cert_storage": storage.New(),
	})
	if err != nil {
		return nil, err
	}
	if l, ok := kp.(interface{ Login() error }); ok {
		if err := l.Login(); err != nil {
			return nil, err
		}
	}
	return backendKeySource(kp, string(xkms.BackendPKCS11), keyID)
}

// tpmBackendConfig is the TPM 2.0 backend configuration for device with
// key blobs in blobs. It is a variable so tests can run on the simulator.
var tpmBackendConfig = func(device string, blobs storage.Backend) map[string]interface{} {
	return map[string]interface{}{"device": device, "key_storage": blobs}
}

// tpmKeySource opens the TPM with its key blobs in keystore, creating the
// key under the built-in platform policy with --tpm-create.
func tpmKeySource(cmd *cobra.Command, factor, keystore, keyID string) (*keySource, error) {
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
	blobs, err := file.New(keystore)
	if err != nil {
		return nil, err
	}
	factory, ok := xkms.GetBackendFactory(xkms.BackendTPM2)
	if !ok {
		return nil, ErrVaultTPMUnavailable
	}
	kp, err := factory(tpmBackendConfig(device, blobs))
	if err != nil {
		return nil, err
	}
	if create {
		if policy != "" && policy != types.TPMPolicyPlatform {
			_ = kp.Close()
			return nil, ErrVaultTPMNamedPolicy
		}
		if err := createTPMKey(kp, keyID); err != nil {
			_ = kp.Close()
			return nil, err
		}
	}
	src, err := backendKeySource(kp, string(xkms.BackendTPM2), keyID)
	if err != nil {
		return nil, err
	}
	src.ref.TPMPolicy = policy
	if factor == vaulttoken.FactorTPM && src.ref.TPMPolicy == "" {
		src.ref.TPMPolicy = types.TPMPolicyPlatform
	}
	return src, nil
}

// createTPMKey creates EC P-256 encryption key keyID in the TPM unless it
// exists.
func createTPMKey(kp types.KeyProvider, keyID string) error {
	ctx := context.Background()
	if keys, err := kp.ListKeys(ctx); err == nil {
		for _, k := range keys {
			if k != nil && k.CN == keyID {
				return nil
			}
		}
	}
	_, err := kp.GenerateKey(ctx, &types.KeyAttributes{
		CN: keyID, KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeEncryption,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}, TPMPolicy: types.TPMPolicyPlatform,
	})
	return err
}

// backendKeySource wraps a key provider as the one xkms backend a key
// factor resolves through.
func backendKeySource(kp types.KeyProvider, name, keyID string) (*keySource, error) {
	b, err := xkms.New(&xkms.BackendConfig{Backend: kp, CertStorage: storage.New()})
	if err != nil {
		_ = kp.Close()
		return nil, err
	}
	lookup := func(string) (xkms.Backend, error) { return b, nil }
	return &keySource{
		ref:    client.PasswordVaultKeyRef{Backend: name, KeyID: keyID},
		lookup: lookup,
		close:  func() { _ = b.Close() },
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
		a, errA := vaultkey.Fingerprint(s.token.Public())
		b, errB := vaultkey.Fingerprint(s.cert.PublicKey)
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
