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

//go:build ble

package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// OATH phone sync errors.
var (
	// ErrOATHSyncFailed indicates OATH credential sync with phone failed.
	ErrOATHSyncFailed = errors.New("oath: phone sync failed")

	// ErrOATHPushFailed indicates pushing OATH credential to phone failed.
	ErrOATHPushFailed = errors.New("oath: push to phone failed")

	// ErrOATHPullFailed indicates pulling OATH credentials from phone failed.
	ErrOATHPullFailed = errors.New("oath: pull from phone failed")
)

// oathSyncPhoneCmd synchronizes OATH credentials with a paired phone.
var oathSyncPhoneCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync OATH credentials with a paired phone",
	Long: `Synchronize OATH TOTP/HOTP credentials between this device and a
paired phone over a secure BLE Noise protocol channel.

Credentials present on this device but not on the phone are pushed.
Credentials present on the phone but not on this device are pulled.

Examples:
  xkey oath sync
  xkey oath sync --device "Pixel 8"
  xkey oath sync --timeout 2m`,
	RunE: runOATHSync,
}

// oathPushPhoneCmd pushes an OATH credential to a paired phone.
var oathPushPhoneCmd = &cobra.Command{
	Use:   "push <name-or-id>",
	Short: "Push OATH credential to a paired phone",
	Long: `Push an OATH TOTP/HOTP credential to a paired phone device over
a secure BLE Noise protocol channel.

The credential is sent to the phone for storage. This allows generating
OTP codes on the phone using the same shared secret.

Examples:
  xkey oath push "GitHub"
  xkey oath push "GitHub" --device "Pixel 8"`,
	Args: cobra.ExactArgs(1),
	RunE: runOATHPush,
}

// oathPullPhoneCmd pulls OATH credentials from a paired phone.
var oathPullPhoneCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull OATH credentials from a paired phone",
	Long: `Pull OATH TOTP/HOTP credentials from a paired phone device over
a secure BLE Noise protocol channel.

Retrieves all credentials stored on the phone and imports any that
are not already present in the local store.

Examples:
  xkey oath pull
  xkey oath pull --device "Pixel 8"`,
	RunE: runOATHPull,
}

func init() {
	OATHCmd.AddCommand(oathSyncPhoneCmd)
	OATHCmd.AddCommand(oathPushPhoneCmd)
	OATHCmd.AddCommand(oathPullPhoneCmd)

	// Sync flags
	oathSyncPhoneCmd.Flags().String("device", "", "Paired device name")
	oathSyncPhoneCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	oathSyncPhoneCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")

	// Push flags
	oathPushPhoneCmd.Flags().String("device", "", "Paired device name")
	oathPushPhoneCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	oathPushPhoneCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")

	// Pull flags
	oathPullPhoneCmd.Flags().String("device", "", "Paired device name")
	oathPullPhoneCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	oathPullPhoneCmd.Flags().String("store", defaultOATHStorePath, "Path to credential store")

	// Bind flags to viper
	_ = viper.BindPFlag("oath.sync.device", oathSyncPhoneCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("oath.sync.timeout", oathSyncPhoneCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("oath.push.device", oathPushPhoneCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("oath.push.timeout", oathPushPhoneCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("oath.pull.device", oathPullPhoneCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("oath.pull.timeout", oathPullPhoneCmd.Flags().Lookup("timeout"))
}

// runOATHSync synchronizes OATH credentials between this device and a phone.
func runOATHSync(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	storePath, _ := cmd.Flags().GetString("store")
	logger := slog.Default()

	// Load phone config
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	// Open local OATH store
	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	fmt.Fprintf(cmd.OutOrStdout(), "Syncing OATH credentials with device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHSyncFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrOATHSyncFailed, err)
	}

	// Get local credentials
	localCreds, err := store.List()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHSyncFailed, err)
	}

	// Get remote credentials from phone
	fmt.Fprintln(cmd.OutOrStdout(), "Fetching phone credentials...")
	req := phone.NewRequest(phone.MethodLocalOATHList, &phone.LocalOATHListParams{})
	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHSyncFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrOATHSyncFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalOATHListResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode list result: %v", ErrOATHSyncFailed, err)
	}

	// Build maps for comparison
	localMap := make(map[string]*oath.Credential, len(localCreds))
	for _, cred := range localCreds {
		localMap[strings.ToLower(cred.Name)] = cred
	}

	remoteMap := make(map[string]phone.OATHCredentialInfo, len(result.Credentials))
	for _, cred := range result.Credentials {
		remoteMap[strings.ToLower(cred.Name)] = cred
	}

	// Push local credentials missing on phone
	pushed := 0
	for _, cred := range localCreds {
		if _, exists := remoteMap[strings.ToLower(cred.Name)]; !exists {
			fmt.Fprintf(cmd.OutOrStdout(), "  Pushing: %s\n", cred.Name)
			pushReq := phone.NewRequest(phone.MethodLocalOATHAdd, &phone.LocalOATHAddParams{
				Credential: credentialToPhoneInfo(cred),
			})
			pushResp, pushErr := phoneBackend.SendRequest(ctx, pushReq)
			if pushErr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "    Error: %v\n", pushErr)
				continue
			}
			if pushResp.Error != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "    Error: %s\n", pushResp.Error.Message)
				continue
			}
			pushed++
		}
	}

	// Pull remote credentials missing locally
	pulled := 0
	for _, remoteCred := range result.Credentials {
		if _, exists := localMap[strings.ToLower(remoteCred.Name)]; !exists {
			fmt.Fprintf(cmd.OutOrStdout(), "  Pulling: %s\n", remoteCred.Name)
			localCred := deviceInfoToCredential(remoteCred)
			if addErr := store.Add(localCred); addErr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "    Error: %v\n", addErr)
				continue
			}
			pulled++
		}
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "Sync complete: %d pushed, %d pulled\n", pushed, pulled)

	return nil
}

// runOATHPush pushes an OATH credential to a paired phone.
func runOATHPush(cmd *cobra.Command, args []string) error {
	nameOrID := args[0]
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	storePath, _ := cmd.Flags().GetString("store")
	logger := slog.Default()

	// Load phone config
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	// Open local OATH store and find credential
	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	cred, err := store.Get(nameOrID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHCredentialNotFound, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Pushing \"%s\" to device \"%s\"...\n\n", cred.Name, device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHPushFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrOATHPushFailed, err)
	}

	// Push credential to phone
	fmt.Fprintln(cmd.OutOrStdout(), "Sending credential...")
	req := phone.NewRequest(phone.MethodLocalOATHAdd, &phone.LocalOATHAddParams{
		Credential: credentialToPhoneInfo(cred),
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHPushFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrOATHPushFailed, resp.Error.Code, resp.Error.Message)
	}

	pushResult, err := phone.DecodeResult[phone.LocalOATHAddResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode push result: %v", ErrOATHPushFailed, err)
	}

	if pushResult.Success {
		fmt.Fprintf(cmd.OutOrStdout(), "  Credential ID: %s\n", pushResult.CredentialID)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Credential pushed successfully.")

	return nil
}

// runOATHPull pulls OATH credentials from a paired phone.
func runOATHPull(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	storePath, _ := cmd.Flags().GetString("store")
	logger := slog.Default()

	// Load phone config
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	// Open local OATH store
	store, err := oath.NewFileStore(storePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHStoreOpenFailed, err)
	}
	defer func() { _ = store.Close() }()

	fmt.Fprintf(cmd.OutOrStdout(), "Pulling OATH credentials from device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHPullFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrOATHPullFailed, err)
	}

	// Fetch credentials from phone
	fmt.Fprintln(cmd.OutOrStdout(), "Fetching credentials...")
	req := phone.NewRequest(phone.MethodLocalOATHList, &phone.LocalOATHListParams{})
	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOATHPullFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrOATHPullFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalOATHListResult](resp)
	if err != nil {
		return fmt.Errorf("%w: failed to decode list result: %v", ErrOATHPullFailed, err)
	}

	if len(result.Credentials) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No credentials found on phone.")
		return nil
	}

	// Import credentials not already in local store
	imported := 0
	skipped := 0
	for _, remoteCred := range result.Credentials {
		localCred := deviceInfoToCredential(remoteCred)
		if err := store.Add(localCred); err != nil {
			if errors.Is(err, oath.ErrCredentialExists) {
				skipped++
				continue
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  Error importing %s: %v\n", remoteCred.Name, err)
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  Imported: %s\n", remoteCred.Name)
		imported++
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "Pull complete: %d imported, %d already present\n", imported, skipped)

	return nil
}

// connectToPhone establishes a BLE connection to a paired phone device.
func connectToPhone(device *PairedDevice, timeout time.Duration, logger *slog.Logger) (*phone.PhoneKeyBackend, error) {
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid local noise key: %w", err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid phone noise key: %w", err)
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid local noise key: %w", err)
	}

	return phone.NewPhoneKeyBackend(&phone.PhoneKeyBackendConfig{
		DeviceAddress:        device.Address,
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		ScanTimeout:          30 * time.Second,
		ConnectTimeout:       30 * time.Second,
		OperationTimeout:     timeout,
		Logger:               logger,
	})
}

// credentialToPhoneInfo converts a local OATH credential to the phone
// protocol representation.
func credentialToPhoneInfo(cred *oath.Credential) phone.OATHCredentialInfo {
	return phone.OATHCredentialInfo{
		Name:        cred.Name,
		Issuer:      cred.Issuer,
		AccountName: cred.AccountName,
		Secret:      cred.Secret,
		Type:        cred.Type,
		Algorithm:   cred.Algorithm,
		Digits:      cred.Digits,
		Period:      cred.Period,
		Counter:     cred.Counter,
	}
}

// deviceInfoToCredential converts a phone OATH credential to a local
// OATH credential.
func deviceInfoToCredential(info phone.OATHCredentialInfo) *oath.Credential {
	algorithm := info.Algorithm
	if algorithm == "" {
		algorithm = oath.DefaultAlgorithm
	}
	digits := info.Digits
	if digits == 0 {
		digits = oath.DefaultDigits
	}
	period := info.Period
	if period == 0 {
		period = oath.DefaultPeriod
	}
	otpType := info.Type
	if otpType == "" {
		otpType = oath.TypeTOTP
	}

	name := info.Name
	if name == "" && info.Issuer != "" {
		name = info.Issuer
	}

	id := strings.ToLower(name)
	if info.Issuer != "" && info.AccountName != "" {
		id = fmt.Sprintf("%s:%s", strings.ToLower(info.Issuer), strings.ToLower(info.AccountName))
	}

	return &oath.Credential{
		ID:          id,
		Name:        name,
		Issuer:      info.Issuer,
		AccountName: info.AccountName,
		Secret:      info.Secret,
		Type:        otpType,
		Algorithm:   algorithm,
		Digits:      digits,
		Period:      period,
		Counter:     info.Counter,
		CreatedAt:   time.Now(),
	}
}
