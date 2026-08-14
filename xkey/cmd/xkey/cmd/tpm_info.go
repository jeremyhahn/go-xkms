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

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TPMInfo holds information about the TPM device
type TPMInfo struct {
	Manufacturer  string `json:"manufacturer"`
	VendorID      string `json:"vendor_id"`
	Family        string `json:"family"`
	Revision      string `json:"revision"`
	FirmwareMajor int64  `json:"firmware_major"`
	FirmwareMinor int64  `json:"firmware_minor"`
	Model         string `json:"model"`
	FIPS1402      bool   `json:"fips_140_2"`
	Type          string `json:"type"`
	Device        string `json:"device"`
	Provisioned   bool   `json:"provisioned"`

	// Capabilities
	MaxAuthFail       uint32 `json:"max_auth_fail"`
	LockoutCounter    uint32 `json:"lockout_counter"`
	LockoutInterval   uint32 `json:"lockout_interval"`
	LockoutRecovery   uint32 `json:"lockout_recovery"`
	NVBufferMax       uint32 `json:"nv_buffer_max"`
	NVIndexesDefined  uint32 `json:"nv_indexes_defined"`
	NVIndexesMax      uint32 `json:"nv_indexes_max"`
	PersistentLoaded  uint32 `json:"persistent_loaded"`
	PersistentAvail   uint32 `json:"persistent_available"`
	TransientMin      uint32 `json:"transient_min"`
	TransientAvail    uint32 `json:"transient_available"`
	ActiveSessionsMax uint32 `json:"active_sessions_max"`

	// Key status
	EKPresent     bool `json:"ek_present"`
	SRKPresent    bool `json:"srk_present"`
	IAKPresent    bool `json:"iak_present"`
	IDevIDPresent bool `json:"idevid_present"`
}

// tpmInfoCmd represents the tpm info command
var tpmInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display TPM information",
	Long: `Display comprehensive TPM information including:
  - Manufacturer and vendor information
  - Firmware version
  - TPM type (hardware/simulator)
  - Capabilities and limits
  - Current provisioning state

Examples:
  # Show TPM info in text format
  xkey tpm info

  # Show TPM info in JSON format
  xkey tpm info -o json

  # Show TPM info for simulator
  xkey tpm info --simulator`,
	RunE: runTPMInfo,
}

func runTPMInfo(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	// Try to open TPM - don't require it to be initialized
	tpm, err := openTPMForProvisioning()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTPMDeviceNotFound, Cause: err}
	}
	defer func() { _ = tpm.Close() }()

	// Get fixed properties
	props, err := tpm.FixedProperties()
	if err != nil {
		return &DetailError{Err: ErrTPMOperationFailed, Detail: fmt.Sprintf(": failed to get TPM properties: %v", err)}
	}

	info := buildTPMInfo(tpm, props)

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		return outputJSON(out, info)
	default:
		return outputText(out, info)
	}
}

func buildTPMInfo(tpm xkms.TrustedPlatformModule, props *xkms.PropertiesFixed) *TPMInfo {
	info := &TPMInfo{
		Manufacturer:      props.Manufacturer,
		VendorID:          strings.TrimSpace(props.VendorID),
		Family:            strings.TrimSpace(props.Family),
		Revision:          props.Revision,
		FirmwareMajor:     props.FwMajor,
		FirmwareMinor:     props.FwMinor,
		Model:             strings.TrimSpace(props.Model),
		FIPS1402:          props.Fips1402,
		Device:            tpm.Device(),
		MaxAuthFail:       props.MaxAuthFail,
		LockoutCounter:    props.LockoutCounter,
		LockoutInterval:   props.LockoutInterval,
		LockoutRecovery:   props.LockoutRecovery,
		NVBufferMax:       props.NVBufferMax,
		NVIndexesDefined:  props.NVIndexesDefined,
		NVIndexesMax:      props.NVIndexesMax,
		PersistentLoaded:  props.PersistentLoaded,
		PersistentAvail:   props.PersistentAvail,
		TransientMin:      props.TransientMin,
		TransientAvail:    props.TransientAvail,
		ActiveSessionsMax: props.ActiveSessionsMax,
	}

	// Determine TPM type
	if tpmCfg.useSimulator {
		info.Type = "Simulator"
	} else {
		info.Type = "Hardware"
	}

	// Check provisioning state
	info.checkProvisioningState(tpm)

	return info
}

func (info *TPMInfo) checkProvisioningState(tpm xkms.TrustedPlatformModule) {
	// Check EK
	if _, err := tpm.EKAttributes(); err == nil {
		info.EKPresent = true
	}

	// Check SRK
	if _, err := tpm.SSRKAttributes(); err == nil {
		info.SRKPresent = true
	}

	// Check IAK
	if _, err := tpm.IAKAttributes(); err == nil {
		info.IAKPresent = true
	}

	// Check IDevID
	if _, err := tpm.IDevIDAttributes(); err == nil {
		info.IDevIDPresent = true
	}

	// TPM is considered provisioned if EK and SRK are present
	info.Provisioned = info.EKPresent && info.SRKPresent
}

func outputJSON(out io.Writer, info *TPMInfo) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}

func outputText(out io.Writer, info *TPMInfo) error {
	fmt.Fprintln(out, "TPM Information")
	fmt.Fprintln(out, "===============")
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Device Information:")
	fmt.Fprintf(out, "  Manufacturer:     %s\n", info.Manufacturer)
	fmt.Fprintf(out, "  Vendor ID:        %s\n", info.VendorID)
	fmt.Fprintf(out, "  Family:           %s\n", info.Family)
	fmt.Fprintf(out, "  Revision:         %s\n", info.Revision)
	fmt.Fprintf(out, "  Firmware:         %d.%d\n", info.FirmwareMajor, info.FirmwareMinor)
	fmt.Fprintf(out, "  Model:            %s\n", info.Model)
	fmt.Fprintf(out, "  Type:             %s\n", info.Type)
	fmt.Fprintf(out, "  Device Path:      %s\n", info.Device)
	fmt.Fprintf(out, "  FIPS 140-2:       %t\n", info.FIPS1402)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Provisioning State:")
	fmt.Fprintf(out, "  Provisioned:      %t\n", info.Provisioned)
	fmt.Fprintf(out, "  EK Present:       %t\n", info.EKPresent)
	fmt.Fprintf(out, "  SRK Present:      %t\n", info.SRKPresent)
	fmt.Fprintf(out, "  IAK Present:      %t\n", info.IAKPresent)
	fmt.Fprintf(out, "  IDevID Present:   %t\n", info.IDevIDPresent)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Capabilities:")
	fmt.Fprintf(out, "  Max Auth Failures:     %d\n", info.MaxAuthFail)
	fmt.Fprintf(out, "  Lockout Counter:       %d\n", info.LockoutCounter)
	fmt.Fprintf(out, "  Lockout Interval:      %d\n", info.LockoutInterval)
	fmt.Fprintf(out, "  Lockout Recovery:      %d\n", info.LockoutRecovery)
	fmt.Fprintf(out, "  NV Buffer Max:         %d\n", info.NVBufferMax)
	fmt.Fprintf(out, "  NV Indexes Defined:    %d\n", info.NVIndexesDefined)
	fmt.Fprintf(out, "  NV Indexes Max:        %d\n", info.NVIndexesMax)
	fmt.Fprintf(out, "  Persistent Loaded:     %d\n", info.PersistentLoaded)
	fmt.Fprintf(out, "  Persistent Available:  %d\n", info.PersistentAvail)
	fmt.Fprintf(out, "  Transient Min:         %d\n", info.TransientMin)
	fmt.Fprintf(out, "  Transient Available:   %d\n", info.TransientAvail)
	fmt.Fprintf(out, "  Active Sessions Max:   %d\n", info.ActiveSessionsMax)

	return nil
}
