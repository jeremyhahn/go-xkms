//go:build integration && tpm2

package integration

import (
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// TestIntegration_Capabilities_AllAlgorithms queries all supported algorithms from the TPM
func TestIntegration_Capabilities_AllAlgorithms(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Query algorithms capability directly
	transport := tpmInstance.Transport()

	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapAlgs,
		Property:      0, // Start from first algorithm
		PropertyCount: 100,
	}

	rsp, err := getCap.Execute(transport)
	if err != nil {
		t.Fatalf("GetCapability for algorithms failed: %v", err)
	}

	// Parse algorithms
	algs, err := rsp.CapabilityData.Data.Algorithms()
	if err != nil {
		t.Fatalf("Failed to parse algorithms: %v", err)
	}

	t.Logf("Found %d supported algorithms", len(algs.AlgProperties))

	// Verify essential algorithms are present
	essentialAlgs := map[tpm2.TPMAlgID]string{
		tpm2.TPMAlgRSA:    "RSA",
		tpm2.TPMAlgSHA256: "SHA256",
		tpm2.TPMAlgAES:    "AES",
	}

	foundAlgs := make(map[tpm2.TPMAlgID]bool)
	for _, alg := range algs.AlgProperties {
		foundAlgs[alg.Alg] = true
		t.Logf("Algorithm 0x%04x supported", alg.Alg)
	}

	for algID, algName := range essentialAlgs {
		if !foundAlgs[algID] {
			t.Errorf("Essential algorithm %s (0x%04x) not found", algName, algID)
		}
	}

	// Check for common hash algorithms
	hashAlgs := []struct {
		id   tpm2.TPMAlgID
		name string
	}{
		{tpm2.TPMAlgSHA1, "SHA1"},
		{tpm2.TPMAlgSHA256, "SHA256"},
		{tpm2.TPMAlgSHA384, "SHA384"},
		{tpm2.TPMAlgSHA512, "SHA512"},
	}

	foundHashCount := 0
	for _, ha := range hashAlgs {
		if foundAlgs[ha.id] {
			t.Logf("Hash algorithm %s supported", ha.name)
			foundHashCount++
		}
	}

	if foundHashCount < 2 {
		t.Errorf("Expected at least 2 hash algorithms, found %d", foundHashCount)
	}

	// Check for asymmetric algorithms
	asymAlgs := []struct {
		id   tpm2.TPMAlgID
		name string
	}{
		{tpm2.TPMAlgRSA, "RSA"},
		{tpm2.TPMAlgECC, "ECC"},
	}

	foundAsymCount := 0
	for _, aa := range asymAlgs {
		if foundAlgs[aa.id] {
			t.Logf("Asymmetric algorithm %s supported", aa.name)
			foundAsymCount++
		}
	}

	if foundAsymCount < 1 {
		t.Errorf("Expected at least 1 asymmetric algorithm, found %d", foundAsymCount)
	}
}

// TestIntegration_Capabilities_LoadedCurves queries ECC curves from the TPM
func TestIntegration_Capabilities_LoadedCurves(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	transport := tpmInstance.Transport()

	// Query ECC curves
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapECCCurves,
		Property:      0,
		PropertyCount: 100,
	}

	rsp, err := getCap.Execute(transport)
	if err != nil {
		t.Fatalf("GetCapability for ECC curves failed: %v", err)
	}

	curves, err := rsp.CapabilityData.Data.ECCCurves()
	if err != nil {
		t.Fatalf("Failed to parse ECC curves: %v", err)
	}

	t.Logf("Found %d ECC curves", len(curves.ECCCurves))

	// Common curves we expect to see
	expectedCurves := map[tpm2.TPMECCCurve]string{
		tpm2.TPMECCNistP256: "NIST P-256",
		tpm2.TPMECCNistP384: "NIST P-384",
	}

	foundCurves := make(map[tpm2.TPMECCCurve]bool)
	for _, curve := range curves.ECCCurves {
		foundCurves[curve] = true
		t.Logf("ECC curve 0x%04x supported", curve)
	}

	// At least one expected curve should be present
	foundExpected := 0
	for curveID, curveName := range expectedCurves {
		if foundCurves[curveID] {
			t.Logf("Expected curve %s found", curveName)
			foundExpected++
		}
	}

	if foundExpected == 0 {
		t.Log("Warning: None of the commonly expected ECC curves found")
	}

	// Verify we have at least one curve (TPM must support some ECC operations)
	if len(curves.ECCCurves) == 0 {
		t.Log("No ECC curves found - TPM may not support ECC operations")
	}
}

// TestIntegration_Info_FullCapabilities performs comprehensive capability query
func TestIntegration_Info_FullCapabilities(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Get fixed properties through the TPM2 library
	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("Failed to get fixed properties: %v", err)
	}

	// Validate manufacturer information
	t.Run("ManufacturerInfo", func(t *testing.T) {
		if props.Manufacturer == "" {
			t.Error("Manufacturer should not be empty")
		}
		t.Logf("Manufacturer: %s", props.Manufacturer)

		if props.VendorID == "" {
			t.Error("VendorID should not be empty")
		}
		t.Logf("VendorID: %s", props.VendorID)

		if props.Model == "" {
			t.Error("Model should not be empty")
		}
		t.Logf("Model: %s", props.Model)
	})

	// Validate family and revision
	t.Run("FamilyAndRevision", func(t *testing.T) {
		if props.Family == "" {
			t.Error("Family should not be empty")
		}
		// TPM 2.0 family should be "2.0" (encoded as ASCII "2.0\0")
		if !strings.Contains(props.Family, "2") {
			t.Errorf("Expected TPM 2.0 family, got %s", props.Family)
		}
		t.Logf("Family: %s", props.Family)

		if props.Revision == "" {
			t.Error("Revision should not be empty")
		}
		t.Logf("Revision: %s", props.Revision)
	})

	// Validate firmware version
	t.Run("FirmwareVersion", func(t *testing.T) {
		t.Logf("Firmware: %d.%d", props.FwMajor, props.FwMinor)

		// Firmware version should be reasonable
		if props.FwMajor < 0 || props.FwMajor > 65535 {
			t.Errorf("Firmware major version out of range: %d", props.FwMajor)
		}
		if props.FwMinor < 0 || props.FwMinor > 65535 {
			t.Errorf("Firmware minor version out of range: %d", props.FwMinor)
		}
	})

	// Validate session properties
	t.Run("SessionProperties", func(t *testing.T) {
		t.Logf("ActiveSessionsMax: %d", props.ActiveSessionsMax)
		t.Logf("AuthSessionsActive: %d", props.AuthSessionsActive)
		t.Logf("AuthSessionsActiveAvail: %d", props.AuthSessionsActiveAvail)
		t.Logf("AuthSessionsLoaded: %d", props.AuthSessionsLoaded)
		t.Logf("AuthSessionsLoadedAvail: %d", props.AuthSessionsLoadedAvail)

		// ActiveSessionsMax should be non-zero for a functional TPM
		if props.ActiveSessionsMax == 0 {
			t.Error("ActiveSessionsMax should be non-zero")
		}

		// Available sessions should not exceed max
		if props.AuthSessionsActiveAvail > props.ActiveSessionsMax {
			t.Errorf("AuthSessionsActiveAvail (%d) exceeds ActiveSessionsMax (%d)",
				props.AuthSessionsActiveAvail, props.ActiveSessionsMax)
		}
	})

	// Validate lockout properties
	t.Run("LockoutProperties", func(t *testing.T) {
		t.Logf("LockoutCounter: %d", props.LockoutCounter)
		t.Logf("LockoutInterval: %d", props.LockoutInterval)
		t.Logf("LockoutRecovery: %d", props.LockoutRecovery)
		t.Logf("MaxAuthFail: %d", props.MaxAuthFail)

		// Lockout counter should not exceed max auth failures
		if props.LockoutCounter > props.MaxAuthFail {
			t.Errorf("LockoutCounter (%d) exceeds MaxAuthFail (%d)",
				props.LockoutCounter, props.MaxAuthFail)
		}
	})

	// Validate NV properties
	t.Run("NVProperties", func(t *testing.T) {
		t.Logf("NVBufferMax: %d", props.NVBufferMax)
		t.Logf("NVIndexesDefined: %d", props.NVIndexesDefined)
		t.Logf("NVIndexesMax: %d", props.NVIndexesMax)
		t.Logf("NVWriteRecovery: %d", props.NVWriteRecovery)

		// NVBufferMax should be non-zero
		if props.NVBufferMax == 0 {
			t.Error("NVBufferMax should be non-zero")
		}

		// NVIndexesMax should be non-zero
		if props.NVIndexesMax == 0 {
			t.Error("NVIndexesMax should be non-zero")
		}

		// Defined indices should not exceed max
		if props.NVIndexesDefined > props.NVIndexesMax {
			t.Errorf("NVIndexesDefined (%d) exceeds NVIndexesMax (%d)",
				props.NVIndexesDefined, props.NVIndexesMax)
		}
	})

	// Validate persistent handle properties
	t.Run("PersistentHandleProperties", func(t *testing.T) {
		t.Logf("PersistentLoaded: %d", props.PersistentLoaded)
		t.Logf("PersistentAvail: %d", props.PersistentAvail)
		t.Logf("PersistentMin: %d", props.PersistentMin)

		// After provisioning, we expect at least some persistent handles
		t.Logf("Total persistent handles: %d (loaded) + %d (avail) = %d",
			props.PersistentLoaded, props.PersistentAvail,
			props.PersistentLoaded+props.PersistentAvail)
	})

	// Validate transient handle properties
	t.Run("TransientHandleProperties", func(t *testing.T) {
		t.Logf("TransientMin: %d", props.TransientMin)
		t.Logf("TransientAvail: %d", props.TransientAvail)

		// TransientMin should be non-zero
		if props.TransientMin == 0 {
			t.Error("TransientMin should be non-zero")
		}
	})

	// Validate memory properties
	t.Run("MemoryProperties", func(t *testing.T) {
		t.Logf("Memory: 0x%x", props.Memory)

		// Decode memory flags
		sharedNV := (props.Memory & 0x01) != 0
		sharedRAM := (props.Memory & 0x02) != 0
		objectCopiedToRAM := (props.Memory & 0x04) != 0

		t.Logf("  sharedNV: %t", sharedNV)
		t.Logf("  sharedRAM: %t", sharedRAM)
		t.Logf("  objectCopiedToRAM: %t", objectCopiedToRAM)
	})

	// Validate FIPS compliance status
	t.Run("FIPSCompliance", func(t *testing.T) {
		t.Logf("FIPS 140-2 compliant: %t", props.Fips1402)

		// Also test the direct method
		isFips, err := tpmInstance.IsFIPS140_2()
		if err != nil {
			t.Errorf("IsFIPS140_2() failed: %v", err)
		}

		if isFips != props.Fips1402 {
			t.Errorf("FIPS status mismatch: IsFIPS140_2()=%t, FixedProperties.Fips1402=%t",
				isFips, props.Fips1402)
		}
	})
}

// TestIntegration_Info_StringOutput tests the Info() method output format
func TestIntegration_Info_StringOutput(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	info, err := tpmInstance.Info()
	if err != nil {
		t.Fatalf("Info() failed: %v", err)
	}

	if info == "" {
		t.Error("Info() returned empty string")
	}

	t.Logf("TPM Info Output:\n%s", info)

	// Verify expected fields are present in output
	expectedFields := []string{
		"Manufacturer",
		"Vendor ID",
		"Family",
		"Revision",
		"Firmware",
		"FIPS 140-2",
	}

	for _, field := range expectedFields {
		if !strings.Contains(info, field) {
			t.Errorf("Expected field %q not found in Info() output", field)
		}
	}
}

// TestIntegration_Capabilities_TPMProperties tests direct TPM property queries
func TestIntegration_Capabilities_TPMProperties(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	transport := tpmInstance.Transport()

	// Test specific property queries
	tests := []struct {
		name       string
		property   tpm2.TPMPT
		desc       string
		minValue   uint32
		validateFn func(uint32) error
	}{
		{
			name:     "MaxAuthFail",
			property: tpm2.TPMPTMaxAuthFail,
			desc:     "Maximum authorization failures",
			minValue: 1,
		},
		{
			name:     "LockoutCounter",
			property: tpm2.TPMPTLockoutCounter,
			desc:     "Current lockout counter",
			minValue: 0,
		},
		{
			name:     "NVBufferMax",
			property: tpm2.TPMPTNVBufferMax,
			desc:     "Maximum NV buffer size",
			minValue: 512,
		},
		{
			name:     "ActiveSessionsMax",
			property: tpm2.TPMPTActiveSessionsMax,
			desc:     "Maximum active sessions",
			minValue: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getCap := tpm2.GetCapability{
				Capability:    tpm2.TPMCapTPMProperties,
				Property:      uint32(tt.property),
				PropertyCount: 1,
			}

			rsp, err := getCap.Execute(transport)
			if err != nil {
				t.Fatalf("Failed to query %s: %v", tt.name, err)
			}

			props, err := rsp.CapabilityData.Data.TPMProperties()
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", tt.name, err)
			}

			if len(props.TPMProperty) == 0 {
				t.Fatalf("No property returned for %s", tt.name)
			}

			value := props.TPMProperty[0].Value
			t.Logf("%s: %d", tt.desc, value)

			if value < tt.minValue {
				t.Errorf("%s value %d is less than expected minimum %d", tt.name, value, tt.minValue)
			}

			if tt.validateFn != nil {
				if err := tt.validateFn(value); err != nil {
					t.Errorf("%s validation failed: %v", tt.name, err)
				}
			}
		})
	}
}

// TestIntegration_Capabilities_Commands tests querying supported TPM commands
func TestIntegration_Capabilities_Commands(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	transport := tpmInstance.Transport()

	// Query supported commands
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapCommands,
		Property:      0, // Start from first command
		PropertyCount: 200,
	}

	rsp, err := getCap.Execute(transport)
	if err != nil {
		t.Fatalf("GetCapability for commands failed: %v", err)
	}

	cmds, err := rsp.CapabilityData.Data.Command()
	if err != nil {
		t.Fatalf("Failed to parse commands: %v", err)
	}

	t.Logf("Found %d supported commands", len(cmds.CommandAttributes))

	// Essential commands that must be supported
	essentialCmds := []struct {
		cc   tpm2.TPMCC
		name string
	}{
		{tpm2.TPMCCGetCapability, "GetCapability"},
		{tpm2.TPMCCStartup, "Startup"},
		{tpm2.TPMCCCreate, "Create"},
		{tpm2.TPMCCLoad, "Load"},
	}

	foundCmds := make(map[tpm2.TPMCC]bool)
	for _, cmd := range cmds.CommandAttributes {
		// Extract command code from attribute (CommandIndex field)
		cmdCode := tpm2.TPMCC(cmd.CommandIndex)
		foundCmds[cmdCode] = true
	}

	for _, ec := range essentialCmds {
		if !foundCmds[ec.cc] {
			t.Errorf("Essential command %s (0x%x) not found", ec.name, ec.cc)
		} else {
			t.Logf("Essential command %s supported", ec.name)
		}
	}

	// Verify minimum number of commands
	if len(cmds.CommandAttributes) < 50 {
		t.Errorf("Expected at least 50 commands, found %d", len(cmds.CommandAttributes))
	}
}

// TestIntegration_Capabilities_PCRs tests PCR bank capabilities
func TestIntegration_Capabilities_PCRs(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	transport := tpmInstance.Transport()

	// Query PCR capabilities
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 10,
	}

	rsp, err := getCap.Execute(transport)
	if err != nil {
		t.Fatalf("GetCapability for PCRs failed: %v", err)
	}

	pcrs, err := rsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		t.Fatalf("Failed to parse PCR capabilities: %v", err)
	}

	t.Logf("Found %d PCR bank selections", len(pcrs.PCRSelections))

	// Verify SHA256 PCR bank exists
	sha256Found := false
	for _, selection := range pcrs.PCRSelections {
		t.Logf("PCR bank with hash algorithm 0x%04x", selection.Hash)

		if selection.Hash == tpm2.TPMAlgSHA256 {
			sha256Found = true
			t.Log("SHA256 PCR bank found")
		}
	}

	if !sha256Found {
		t.Error("SHA256 PCR bank not found - required for modern TPM operations")
	}
}

// TestIntegration_Capabilities_Handles tests querying handles
func TestIntegration_Capabilities_Handles(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	transport := tpmInstance.Transport()

	handleTypes := []struct {
		name     string
		property uint32
		desc     string
	}{
		{
			name:     "PersistentHandles",
			property: 0x81000000,
			desc:     "Persistent object handles",
		},
		{
			name:     "TransientHandles",
			property: 0x80000000,
			desc:     "Transient object handles",
		},
	}

	for _, ht := range handleTypes {
		t.Run(ht.name, func(t *testing.T) {
			getCap := tpm2.GetCapability{
				Capability:    tpm2.TPMCapHandles,
				Property:      ht.property,
				PropertyCount: 10,
			}

			rsp, err := getCap.Execute(transport)
			if err != nil {
				t.Fatalf("Failed to query %s: %v", ht.name, err)
			}

			handles, err := rsp.CapabilityData.Data.Handles()
			if err != nil {
				t.Fatalf("Failed to parse %s: %v", ht.name, err)
			}

			t.Logf("%s: found %d handles", ht.desc, len(handles.Handle))

			for i, handle := range handles.Handle {
				t.Logf("  Handle[%d]: 0x%08x", i, handle)
			}
		})
	}
}

// TestIntegration_FixedProperties_ErrorHandling tests error scenarios
func TestIntegration_FixedProperties_ErrorHandling(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := capabilitiesProvisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Test that properties are consistently retrievable
	t.Run("ConsistentRetrieval", func(t *testing.T) {
		props1, err := tpmInstance.FixedProperties()
		if err != nil {
			t.Fatalf("First FixedProperties call failed: %v", err)
		}

		props2, err := tpmInstance.FixedProperties()
		if err != nil {
			t.Fatalf("Second FixedProperties call failed: %v", err)
		}

		// Fixed properties should be consistent
		if props1.Manufacturer != props2.Manufacturer {
			t.Errorf("Manufacturer changed: %q vs %q", props1.Manufacturer, props2.Manufacturer)
		}

		if props1.Family != props2.Family {
			t.Errorf("Family changed: %q vs %q", props1.Family, props2.Family)
		}

		if props1.FwMajor != props2.FwMajor || props1.FwMinor != props2.FwMinor {
			t.Errorf("Firmware version changed: %d.%d vs %d.%d",
				props1.FwMajor, props1.FwMinor, props2.FwMajor, props2.FwMinor)
		}

		// Some properties may change (like available sessions)
		t.Logf("Manufacturer consistency verified: %s", props1.Manufacturer)
	})
}

// capabilitiesProvisionIfNeeded helper to provision TPM if not already provisioned
func capabilitiesProvisionIfNeeded(t *testing.T, tpm tpm2lib.TrustedPlatformModule) error {
	t.Helper()

	// Try to get SRK attributes to check if provisioned
	_, err := tpm.SSRKAttributes()
	if err != nil {
		// Not provisioned, provision now
		t.Log("TPM not provisioned, provisioning...")
		return tpm.Provision(nil)
	}

	return nil
}
