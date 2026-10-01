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

package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/spf13/cobra"
)

// PIV login errors.
var (
	// ErrAuthPIVSignerCreationFailed indicates the slot's crypto.Signer
	// could not be constructed from its stored certificate.
	ErrAuthPIVSignerCreationFailed = errors.New("auth: failed to create PIV signer")

	// ErrAuthPIVLoginFailed indicates the server rejected the mTLS PIV
	// login exchange.
	ErrAuthPIVLoginFailed = errors.New("auth: PIV login failed")

	// ErrAuthPIVClientCreationFailed indicates the session login-plane
	// client could not be constructed.
	ErrAuthPIVClientCreationFailed = errors.New("auth: failed to create PIV login client")
)

// buildAuthPIVConfig builds the PIVConfig for the "auth login --piv" command
// from its own --backend flag plus the same unified-config-resolved storage
// settings the "piv" command group uses (storage path, PKCS#11
// library/token, and the PIN/SO-PIN's dedicated stdin/env sources). The
// backend is read from --backend rather than through pivConfigString because
// "auth login" is a sibling command tree to "piv" and declares its own
// --backend flag with a different default; every other setting resolves
// through the same GetConfig().PIV fields buildPIVConfig reads
// (go-xkms#871).
func buildAuthPIVConfig(cmd *cobra.Command) (*PIVConfig, error) {
	backendFlag, _ := cmd.Flags().GetString("backend")
	backend := PIVBackendType(backendFlag)
	if backend == "" {
		backend = PIVBackendSoftware
	}

	storageType := PIVStorageType(pivStorageOverride(cmd))
	if storageType == "" {
		storageType = defaultPIVStorageTypeForBackend(backend)
	}

	var cfgPIV xkeyconfig.PIVConfig
	if cfg := GetConfig(); cfg != nil {
		cfgPIV = cfg.PIV
	}

	pkcs11PIN, err := resolvePIVPKCS11Secret(cmd, pivPKCS11PINSource)
	if err != nil {
		return nil, err
	}
	pkcs11SOPIN, err := resolvePIVPKCS11Secret(cmd, pivPKCS11SOPINSource)
	if err != nil {
		return nil, err
	}

	return &PIVConfig{
		Backend:       backend,
		StorageType:   storageType,
		StoragePath:   pivConfigString(cmd, "storage-path", cfgPIV.StoragePath),
		TPMDevice:     pivConfigString(cmd, "tpm-device", cfgPIV.TPMDevice),
		PKCS11Library: pivConfigString(cmd, "pkcs11-library", cfgPIV.PKCS11Library),
		PKCS11Token:   pivConfigString(cmd, "pkcs11-token", cfgPIV.PKCS11Token),
		PKCS11PIN:     pkcs11PIN,
		PKCS11SOPIN:   pkcs11SOPIN,
	}, nil
}

// runAuthLoginPIV authenticates to serverURL by presenting the certificate
// stored in a PIV slot as the TLS client certificate, signing the handshake
// with the slot's private key via an xkms.PIVCryptoSigner. Possession of the
// key IS the credential: there is no username and no WebAuthn ceremony. On
// success the returned access/refresh token pair is stored under the same
// token store "xkey auth login" (WebAuthn) and "xkey auth token" use.
func runAuthLoginPIV(cmd *cobra.Command, logger *slog.Logger, serverURL string) (err error) {
	slotFlag, _ := cmd.Flags().GetString("slot")
	slot, err := validatePIVSlot(slotFlag)
	if err != nil {
		return err
	}

	pivCfg, err := buildAuthPIVConfig(cmd)
	if err != nil {
		return err
	}
	if err := ensurePIVInitialized(pivCfg, logger); err != nil {
		return err
	}

	storage, err := createPIVStorage(pivCfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrPIVCertificateNotFound, err)
	}

	pivSigner, err := xkms.NewPIVCryptoSigner(string(pivCfg.Backend), xkms.PIVSlot(slot), cert.PublicKey)
	if err != nil {
		return errors.Join(ErrAuthPIVSignerCreationFailed, err)
	}

	clientCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  pivSigner,
		Leaf:        cert,
	}

	registry, registryCleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer registryCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	// A PIV login needs no WebAuthn enrollment, so the server need not be
	// registered: a registered server contributes its recorded pin, an
	// unregistered one is reached by the URL given and verified by the auth
	// root pool alone.
	serverEntry, err := registry.Lookup(ctx, serverURL)
	registered := err == nil
	if errors.Is(err, serverregistry.ErrServerNotFound) {
		serverEntry = &serverregistry.ServerEntry{URL: serverURL}
	} else if err != nil {
		return errors.Join(ErrAuthServerLookupFailed, err)
	}

	// Without a recorded pin the roots come from the xKey trust store, the
	// system pool and --tls-ca, so `auth login --piv` reaches a server by the
	// CA an operator added just as the WebAuthn path does (#250).
	// LoginClientConfig ignores RootCAs when SPKIPin is set.
	tlsCAFile, _ := cmd.Flags().GetString("tls-ca")
	var roots *x509.CertPool
	if serverEntry.CAFingerprint == "" {
		pool, poolErr := authRootPool(tlsCAFile)
		if poolErr != nil {
			return poolErr
		}
		roots = pool
	}

	loginClient, err := xkms.NewLoginClient(xkms.LoginClientConfig{
		BaseURL:           serverEntry.URL,
		ClientCertificate: &clientCert,
		SPKIPin:           serverEntry.CAFingerprint,
		RootCAs:           roots,
		Timeout:           defaultAuthTimeout,
	})
	if err != nil {
		return errors.Join(ErrAuthPIVClientCreationFailed, err)
	}

	out := cmd.OutOrStdout()
	slotName := xkms.PIVSlotName(slot)
	_, _ = fmt.Fprintf(out, "Authenticating to %s with PIV slot %s (%s)...\n", serverEntry.URL, slot, slotName)

	pair, err := loginClient.PIVLogin(ctx)
	if err != nil {
		return errors.Join(ErrAuthPIVLoginFailed, err)
	}

	server, err := identifyLoginServer(ctx, authClientConfig{
		ServerURL: serverEntry.URL,
		SPKIPin:   serverEntry.CAFingerprint,
		TLSCAFile: tlsCAFile,
	})
	if err != nil {
		return err
	}
	if err := storeAuthTokenPair(ctx, logger, server, tokenstoreSourcePIV, pair); err != nil {
		return err
	}
	if registered {
		serverEntry.LastConnectedAt = time.Now().UTC()
		if updateErr := registry.Update(ctx, serverEntry); updateErr != nil {
			logger.Warn("failed to update server last connected time",
				slog.String("url", serverEntry.URL),
				slog.Any("error", updateErr))
		}
	}

	_, _ = fmt.Fprintf(out, "Authenticated to %s with PIV slot %s. Token pair stored.\n", serverEntry.URL, slot)
	return nil
}
