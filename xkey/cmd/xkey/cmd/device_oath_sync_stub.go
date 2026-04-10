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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
