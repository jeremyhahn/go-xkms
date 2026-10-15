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

//go:build !ble

package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/spf13/cobra"
)

// OATH phone sync errors (stub).
var (
	// ErrOATHSyncFailed indicates OATH credential sync with phone failed.
	ErrOATHSyncFailed = errors.New("oath: phone sync failed")

	// ErrOATHPushFailed indicates pushing OATH credential to phone failed.
	ErrOATHPushFailed = errors.New("oath: push to phone failed")

	// ErrOATHPullFailed indicates pulling OATH credentials from phone failed.
	ErrOATHPullFailed = errors.New("oath: pull from phone failed")
)

// oathSyncPhoneCmd synchronizes OATH credentials with a paired phone.
// This is a stub implementation when built without BLE support.
var oathSyncPhoneCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync OATH credentials with a paired phone",
	Long: `Synchronize OATH TOTP/HOTP credentials with a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone OATH sync, rebuild with the 'ble' build tag:

    go build -tags ble

When BLE is enabled, this command connects to the paired phone and
synchronizes OATH credentials bidirectionally.

Examples:
  xkey oath sync
  xkey oath sync --device "Pixel 8"`,
	RunE: runOATHSyncStub,
}

// oathPushPhoneCmd pushes an OATH credential to a paired phone.
// This is a stub implementation when built without BLE support.
var oathPushPhoneCmd = &cobra.Command{
	Use:   "push <name-or-id>",
	Short: "Push OATH credential to a paired phone",
	Long: `Push an OATH credential to a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone OATH push, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey oath push "GitHub"
  xkey oath push "GitHub" --device "Pixel 8"`,
	Args: cobra.ExactArgs(1),
	RunE: runOATHPushStub,
}

// oathPullPhoneCmd pulls OATH credentials from a paired phone.
// This is a stub implementation when built without BLE support.
var oathPullPhoneCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull OATH credentials from a paired phone",
	Long: `Pull OATH credentials from a paired phone device.

NOTE: This binary was built without Bluetooth Low Energy (BLE) support.
To enable phone OATH pull, rebuild with the 'ble' build tag:

    go build -tags ble

Examples:
  xkey oath pull
  xkey oath pull --device "Pixel 8"`,
	RunE: runOATHPullStub,
}

func init() {
	OATHCmd.AddCommand(oathSyncPhoneCmd)
	OATHCmd.AddCommand(oathPushPhoneCmd)
	OATHCmd.AddCommand(oathPullPhoneCmd)

	registerOATHSyncPhoneFlags(oathSyncPhoneCmd)
	registerOATHPushPhoneFlags(oathPushPhoneCmd)
	registerOATHPullPhoneFlags(oathPullPhoneCmd)
}

// runOATHSyncStub returns an error indicating BLE support is not available.
func runOATHSyncStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runOATHPushStub returns an error indicating BLE support is not available.
func runOATHPushStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// runOATHPullStub returns an error indicating BLE support is not available.
func runOATHPullStub(cmd *cobra.Command, args []string) error {
	return ErrDeviceBLEUnavailable
}

// credentialToPhoneInfo converts a local OATH credential to the phone
// protocol representation. The result carries a copy of the shared secret in
// protected memory, which the caller releases with OATHCredentialInfo.Destroy
// once it has been sent.
func credentialToPhoneInfo(cred *oath.Credential) (pairingproto.OATHCredentialInfo, error) {
	plain, err := cred.Secret()
	if err != nil {
		return pairingproto.OATHCredentialInfo{}, err
	}
	defer secure.Wipe(plain)
	secret, err := xkms.NewSecretText(plain)
	if err != nil {
		return pairingproto.OATHCredentialInfo{}, err
	}
	return pairingproto.OATHCredentialInfo{
		Name:        cred.Name,
		Issuer:      cred.Issuer,
		AccountName: cred.AccountName,
		Secret:      secret,
		Type:        cred.Type,
		Algorithm:   cred.Algorithm,
		Digits:      cred.Digits,
		Period:      cred.Period,
		Counter:     cred.Counter,
	}, nil
}

// deviceInfoToCredential converts a phone OATH credential to a local
// OATH credential, adopting the secret into protected memory. The error is
// oath.ErrProtectedMemory (wrapped) when that allocation fails.
func deviceInfoToCredential(info pairingproto.OATHCredentialInfo) (*oath.Credential, error) {
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

	cred := &oath.Credential{
		ID:          id,
		Name:        name,
		Issuer:      info.Issuer,
		AccountName: info.AccountName,
		Type:        otpType,
		Algorithm:   algorithm,
		Digits:      digits,
		Period:      period,
		Counter:     info.Counter,
		CreatedAt:   time.Now(),
	}
	plain, err := info.Secret.Copy()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(plain)
	if err := cred.SetSecret(plain); err != nil {
		return nil, err
	}
	return cred, nil
}
