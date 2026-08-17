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
	"errors"
	"fmt"
	"log/slog"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
// from its own --backend flag plus the same Viper-bound storage settings the
// "piv" command group uses (storage path, PKCS#11 library/token/PIN). The
// backend is read from --backend rather than from Viper because "auth
// login" is a sibling command tree to "piv" and does not share its
// persistent flags.
func buildAuthPIVConfig(cmd *cobra.Command) *PIVConfig {
	backendFlag, _ := cmd.Flags().GetString("backend")
	backend := PIVBackendType(backendFlag)
	if backend == "" {
		backend = PIVBackendSoftware
	}

	return &PIVConfig{
		Backend:       backend,
		StorageType:   defaultPIVStorageTypeForBackend(backend),
		StoragePath:   viper.GetString(viperKeyPIVStoragePath),
		TPMDevice:     viper.GetString(viperKeyPIVTPMDevice),
		PKCS11Library: viper.GetString(viperKeyPIVPKCS11Library),
		PKCS11Token:   viper.GetString(viperKeyPIVPKCS11Token),
		PKCS11PIN:     viper.GetString(viperKeyPIVPKCS11PIN),
		PKCS11SOPIN:   viper.GetString(viperKeyPIVPKCS11SOPIN),
	}
}

// runAuthLoginPIV authenticates to serverURL by presenting the certificate
// stored in a PIV slot as the TLS client certificate, signing the handshake
// with the slot's private key via an xkms.PIVCryptoSigner. Possession of the
// key IS the credential: there is no username and no WebAuthn ceremony. On
// success the returned access/refresh token pair is stored under the same
// token store "xkey auth login" (WebAuthn) and "xkey auth token" use.
func runAuthLoginPIV(cmd *cobra.Command, logger *slog.Logger, serverURL string) error {
	slotFlag, _ := cmd.Flags().GetString("slot")
	slot, err := validatePIVSlot(slotFlag)
	if err != nil {
		return err
	}

	pivCfg := buildAuthPIVConfig(cmd)
	if err := ensurePIVInitialized(pivCfg, logger); err != nil {
		return err
	}

	storage, err := createPIVStorage(pivCfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

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

	serverEntry, err := registry.Lookup(ctx, serverURL)
	if err != nil {
		return errors.Join(ErrAuthServerLookupFailed, err)
	}

	loginClient, err := xkms.NewLoginClient(xkms.LoginClientConfig{
		BaseURL:           serverEntry.URL,
		ClientCertificate: &clientCert,
		SPKIPin:           serverEntry.CAFingerprint,
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

	if err := storeAuthTokenPair(ctx, logger, serverEntry.URL, tokenstoreSourcePIV, pair); err != nil {
		return err
	}

	serverEntry.LastConnectedAt = time.Now().UTC()
	if updateErr := registry.Update(ctx, serverEntry); updateErr != nil {
		logger.Warn("failed to update server last connected time",
			slog.String("url", serverEntry.URL),
			slog.Any("error", updateErr))
	}

	_, _ = fmt.Fprintf(out, "Authenticated to %s with PIV slot %s. Token pair stored.\n", serverEntry.URL, slot)
	return nil
}
