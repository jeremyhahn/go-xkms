package tpm2

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// CommandInfo describes a single TPM command with its hex code, name,
// and a short description from TCG TPM 2.0 Part 3.
type CommandInfo struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TPMProperty represents a single TPM property with its canonical name,
// raw hex value, and human-readable formatted value.
type TPMProperty struct {
	Name  string `json:"name"`  // e.g., "TPM2_PT_REVISION"
	Raw   string `json:"raw"`   // e.g., "0x8A"
	Value string `json:"value"` // e.g., "1.38" (formatted, empty if raw-only)
}

// PropertiesFixed contains fixed TPM properties queried from the device.
type PropertiesFixed struct {
	ActiveSessionsMax       uint32
	AuthSessionsActive      uint32
	AuthSessionsActiveAvail uint32
	AuthSessionsLoaded      uint32
	AuthSessionsLoadedAvail uint32
	Family                  string
	Fips1402                bool
	FwMajor                 int64
	FwMinor                 int64
	Level                   uint32
	LoadedCurves            uint32
	LockoutCounter          uint32
	LockoutInterval         uint32
	LockoutRecovery         uint32
	Manufacturer            string
	MaxECCKeyBits           uint32
	MaxRSAKeyBits           uint32
	Model                   string
	MaxAuthFail             uint32
	Memory                  uint32
	NVBufferMax             uint32
	NVIndexesDefined        uint32
	NVIndexesMax            uint32
	NVWriteRecovery         uint32
	PersistentAvail         uint32
	PersistentLoaded        uint32
	PersistentMin           uint32
	Revision                string
	SupportedAlgorithms     []string
	TransientAvail          uint32
	TransientMin            uint32
	VendorID                string
	InputBufferMax          uint32
	MaxDigestSize           uint32
	MaxObjectContext        uint32
	DayOfYear               uint32
	Year                    uint32
	PCRCount                uint32
	PCRSelectMin            uint32
	ContextGapMax           uint32
	NVCountersMax           uint32
	ClockUpdate             uint32
	ContextHash             uint32
	ContextSym              uint32
	ContextSymSize          uint32
	OrderlyCount            uint32
	MaxCommandSize          uint32
	MaxResponseSize         uint32
	MaxSessionContext       uint32
	PSFamilyIndicator       uint32
	PSLevel                 uint32
	PSRevision              uint32
	PSDayOfYear             uint32
	PSYear                  uint32
	SplitMax                uint32
	TotalCommands           uint32
	LibraryCommands         uint32
	VendorCommands          uint32
	MaxCapBuffer            uint32
	HRLoadedMin             uint32
	Permanent               uint32
	StartupClear            uint32
	NVCounters              uint32
	NVCountersAvail         uint32
	AlgorithmSet            uint32
	AuditCounter0           uint32
	AuditCounter1           uint32

	// Handle enumeration results
	PersistentHandles []tpm2.TPMHandle
	TransientHandles  []tpm2.TPMHandle
	NVIndexes         []NVIndexInfo
}

// cleanTPMString strips non-printable characters and trims whitespace from
// TPM property strings. Real TPMs can embed null bytes and other control
// characters in their vendor string properties; only printable ASCII
// (32-126) is retained.
func cleanTPMString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// isPrintable returns true if every rune in s is printable ASCII (32-126).
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return len(s) > 0
}

// tpmPTNames maps all TPMPT constants from go-tpm v0.9.7 to their official
// TPM2_PT_* canonical names as shown by tpm2_getcap. Both fixed (0x100-0x1FF)
// and variable (0x200-0x2FF) properties are included.
var tpmPTNames = map[tpm2.TPMPT]string{
	// Fixed properties (PT_FIXED, 0x100 range)
	tpm2.TPMPTFamilyIndicator:   "TPM2_PT_FAMILY_INDICATOR",
	tpm2.TPMPTLevel:             "TPM2_PT_LEVEL",
	tpm2.TPMPTRevision:          "TPM2_PT_REVISION",
	tpm2.TPMPTDayofYear:         "TPM2_PT_DAY_OF_YEAR",
	tpm2.TPMPTYear:              "TPM2_PT_YEAR",
	tpm2.TPMPTManufacturer:      "TPM2_PT_MANUFACTURER",
	tpm2.TPMPTVendorString1:     "TPM2_PT_VENDOR_STRING_1",
	tpm2.TPMPTVendorString2:     "TPM2_PT_VENDOR_STRING_2",
	tpm2.TPMPTVendorString3:     "TPM2_PT_VENDOR_STRING_3",
	tpm2.TPMPTVendorString4:     "TPM2_PT_VENDOR_STRING_4",
	tpm2.TPMPTVendorTPMType:     "TPM2_PT_VENDOR_TPM_TYPE",
	tpm2.TPMPTFirmwareVersion1:  "TPM2_PT_FIRMWARE_VERSION_1",
	tpm2.TPMPTFirmwareVersion2:  "TPM2_PT_FIRMWARE_VERSION_2",
	tpm2.TPMPTInputBuffer:       "TPM2_PT_INPUT_BUFFER",
	tpm2.TPMPTHRTransientMin:    "TPM2_PT_HR_TRANSIENT_MIN",
	tpm2.TPMPTHRPersistentMin:   "TPM2_PT_HR_PERSISTENT_MIN",
	tpm2.TPMPTHRLoadedMin:       "TPM2_PT_HR_LOADED_MIN",
	tpm2.TPMPTActiveSessionsMax: "TPM2_PT_ACTIVE_SESSIONS_MAX",
	tpm2.TPMPTPCRCount:          "TPM2_PT_PCR_COUNT",
	tpm2.TPMPTPCRSelectMin:      "TPM2_PT_PCR_SELECT_MIN",
	tpm2.TPMPTContextGapMax:     "TPM2_PT_CONTEXT_GAP_MAX",
	tpm2.TPMPTNVCountersMax:     "TPM2_PT_NV_COUNTERS_MAX",
	tpm2.TPMPTNVIndexMax:        "TPM2_PT_NV_INDEX_MAX",
	tpm2.TPMPTMemory:            "TPM2_PT_MEMORY",
	tpm2.TPMPTClockUpdate:       "TPM2_PT_CLOCK_UPDATE",
	tpm2.TPMPTContextHash:       "TPM2_PT_CONTEXT_HASH",
	tpm2.TPMPTContextSym:        "TPM2_PT_CONTEXT_SYM",
	tpm2.TPMPTContextSymSize:    "TPM2_PT_CONTEXT_SYM_SIZE",
	tpm2.TPMPTOrderlyCount:      "TPM2_PT_ORDERLY_COUNT",
	tpm2.TPMPTMaxCommandSize:    "TPM2_PT_MAX_COMMAND_SIZE",
	tpm2.TPMPTMaxResponseSize:   "TPM2_PT_MAX_RESPONSE_SIZE",
	tpm2.TPMPTMaxDigest:         "TPM2_PT_MAX_DIGEST",
	tpm2.TPMPTMaxObjectContext:  "TPM2_PT_MAX_OBJECT_CONTEXT",
	tpm2.TPMPTMaxSessionContext: "TPM2_PT_MAX_SESSION_CONTEXT",
	tpm2.TPMPTPSFamilyIndicator: "TPM2_PT_PS_FAMILY_INDICATOR",
	tpm2.TPMPTPSLevel:           "TPM2_PT_PS_LEVEL",
	tpm2.TPMPTPSRevision:        "TPM2_PT_PS_REVISION",
	tpm2.TPMPTPSDayOfYear:       "TPM2_PT_PS_DAY_OF_YEAR",
	tpm2.TPMPTPSYear:            "TPM2_PT_PS_YEAR",
	tpm2.TPMPTSplitMax:          "TPM2_PT_SPLIT_MAX",
	tpm2.TPMPTTotalCommands:     "TPM2_PT_TOTAL_COMMANDS",
	tpm2.TPMPTLibraryCommands:   "TPM2_PT_LIBRARY_COMMANDS",
	tpm2.TPMPTVendorCommands:    "TPM2_PT_VENDOR_COMMANDS",
	tpm2.TPMPTNVBufferMax:       "TPM2_PT_NV_BUFFER_MAX",
	tpm2.TPMPTModes:             "TPM2_PT_MODES",
	tpm2.TPMPTMaxCapBuffer:      "TPM2_PT_MAX_CAP_BUFFER",

	// Variable properties (PT_VAR, 0x200 range)
	tpm2.TPMPTPermanent:         "TPM2_PT_PERMANENT",
	tpm2.TPMPTStartupClear:      "TPM2_PT_STARTUP_CLEAR",
	tpm2.TPMPTHRNVIndex:         "TPM2_PT_HR_NV_INDEX",
	tpm2.TPMPTHRLoaded:          "TPM2_PT_HR_LOADED",
	tpm2.TPMPTHRLoadedAvail:     "TPM2_PT_HR_LOADED_AVAIL",
	tpm2.TPMPTHRActive:          "TPM2_PT_HR_ACTIVE",
	tpm2.TPMPTHRActiveAvail:     "TPM2_PT_HR_ACTIVE_AVAIL",
	tpm2.TPMPTHRTransientAvail:  "TPM2_PT_HR_TRANSIENT_AVAIL",
	tpm2.TPMPTHRPersistent:      "TPM2_PT_HR_PERSISTENT",
	tpm2.TPMPTHRPersistentAvail: "TPM2_PT_HR_PERSISTENT_AVAIL",
	tpm2.TPMPTNVCounters:        "TPM2_PT_NV_COUNTERS",
	tpm2.TPMPTNVCountersAvail:   "TPM2_PT_NV_COUNTERS_AVAIL",
	tpm2.TPMPTAlgorithmSet:      "TPM2_PT_ALGORITHM_SET",
	tpm2.TPMPTLoadedCurves:      "TPM2_PT_LOADED_CURVES",
	tpm2.TPMPTLockoutCounter:    "TPM2_PT_LOCKOUT_COUNTER",
	tpm2.TPMPTMaxAuthFail:       "TPM2_PT_MAX_AUTH_FAIL",
	tpm2.TPMPTLockoutInterval:   "TPM2_PT_LOCKOUT_INTERVAL",
	tpm2.TPMPTLockoutRecovery:   "TPM2_PT_LOCKOUT_RECOVERY",
	tpm2.TPMPTNVWriteRecovery:   "TPM2_PT_NV_WRITE_RECOVERY",
	tpm2.TPMPTAuditCounter0:     "TPM2_PT_AUDIT_COUNTER_0",
	tpm2.TPMPTAuditCounter1:     "TPM2_PT_AUDIT_COUNTER_1",
}

// queryPropertyBatch queries all TPM properties starting at startProp via
// GetCapability with pagination. It returns a map of property to value pairs.
func queryPropertyBatch(t transport.TPM, startProp tpm2.TPMPT, count uint32) (map[tpm2.TPMPT]uint32, error) {
	result := make(map[tpm2.TPMPT]uint32)
	prop := startProp
	for {
		resp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: count,
		}.Execute(t)
		if err != nil {
			return result, err
		}
		props, err := resp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return result, err
		}
		if len(props.TPMProperty) == 0 {
			break
		}
		for _, p := range props.TPMProperty {
			result[tpm2.TPMPT(p.Property)] = p.Value
		}
		if !resp.MoreData {
			break
		}
		last := props.TPMProperty[len(props.TPMProperty)-1]
		prop = tpm2.TPMPT(last.Property + 1)
	}
	return result, nil
}

// IsFIPS140_2 reports whether the TPM is currently operating in
// FIPS 140-2 mode, as advertised via TPM_PT_MODES (TCG TPM 2.0 Library
// Part 2, §6.13). A TPM reports FIPS_140_2 mode only when the firmware
// was built to enforce FIPS-only operation at runtime; this is distinct
// from the module-level CMVP certification of the silicon+firmware.
//
// Per TCG, TPM2_GetCapability with a property that the TPM does not
// implement returns the NEXT implemented property starting from the
// requested index — it does not return an error. Callers that do not
// verify the returned property index will silently read an unrelated
// value. This implementation:
//
//  1. Verifies the returned property is exactly TPM_PT_MODES before
//     reading its value.
//  2. Treats a missing/non-implemented TPM_PT_MODES as "not running in
//     FIPS mode" (false, nil) — the TPM is not advertising FIPS mode,
//     which is the correct answer for runtime operational status.
//  3. Parses the value as a bitfield: TPM_PT_MODES bit 0 = FIPS_140_2.
//     A non-zero value with bit 0 clear means some other mode bit is
//     set but not FIPS mode, which must also return false.
func (tpm *TPM2) IsFIPS140_2() (bool, error) {
	modesResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTModes),
		PropertyCount: 1,
	}.Execute(tpm.transport)
	if err != nil {
		return false, err
	}
	modes, err := modesResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return false, err
	}
	if len(modes.TPMProperty) == 0 {
		return false, nil
	}
	// The TPM returns the next implemented property if TPM_PT_MODES is
	// not supported; that response is NOT a FIPS mode answer.
	if modes.TPMProperty[0].Property != tpm2.TPMPTModes {
		return false, nil
	}
	// TPM_PT_MODES is a bitfield; bit 0 is FIPS_140_2.
	return modes.TPMProperty[0].Value&0x1 == 0x1, nil
}

// FixedProperties queries the TPM for its fixed properties. Individual property
// query failures are logged but do not abort the entire operation, ensuring that
// partial results are returned even when certain properties are unsupported.
func (tpm *TPM2) FixedProperties() (*PropertiesFixed, error) {
	props := &PropertiesFixed{}

	if v, err := activeSessionsMax(tpm.transport); err == nil {
		props.ActiveSessionsMax = v
	} else {
		tpm.logger.Debug("failed to query activeSessionsMax", slog.String("error", err.Error()))
	}

	if v, err := persistentLoaded(tpm.transport); err == nil {
		props.PersistentLoaded = v
	} else {
		tpm.logger.Debug("failed to query persistentLoaded", slog.String("error", err.Error()))
	}

	if v, err := persistentAvail(tpm.transport); err == nil {
		props.PersistentAvail = v
	} else {
		tpm.logger.Debug("failed to query persistentAvail", slog.String("error", err.Error()))
	}

	if v, err := persistentMin(tpm.transport); err == nil {
		props.PersistentMin = v
	} else {
		tpm.logger.Debug("failed to query persistentMin", slog.String("error", err.Error()))
	}

	if v, err := transientMin(tpm.transport); err == nil {
		props.TransientMin = v
	} else {
		tpm.logger.Debug("failed to query transientMin", slog.String("error", err.Error()))
	}

	if v, err := transientAvail(tpm.transport); err == nil {
		props.TransientAvail = v
	} else {
		tpm.logger.Debug("failed to query transientAvail", slog.String("error", err.Error()))
	}

	if v, err := authSessionsLoaded(tpm.transport); err == nil {
		props.AuthSessionsLoaded = v
	} else {
		tpm.logger.Debug("failed to query authSessionsLoaded", slog.String("error", err.Error()))
	}

	if v, err := authSessionsLoadedAvail(tpm.transport); err == nil {
		props.AuthSessionsLoadedAvail = v
	} else {
		tpm.logger.Debug("failed to query authSessionsLoadedAvail", slog.String("error", err.Error()))
	}

	if v, err := authSessionsActive(tpm.transport); err == nil {
		props.AuthSessionsActive = v
	} else {
		tpm.logger.Debug("failed to query authSessionsActive", slog.String("error", err.Error()))
	}

	if v, err := authSessionsActiveAvail(tpm.transport); err == nil {
		props.AuthSessionsActiveAvail = v
	} else {
		tpm.logger.Debug("failed to query authSessionsActiveAvail", slog.String("error", err.Error()))
	}

	if v, err := family(tpm.transport); err == nil {
		props.Family = v
	} else {
		tpm.logger.Debug("failed to query family", slog.String("error", err.Error()))
	}

	if v, err := tpm.IsFIPS140_2(); err == nil {
		props.Fips1402 = v
	} else {
		tpm.logger.Debug("failed to query FIPS 140-2 mode", slog.String("error", err.Error()))
	}

	if fwMajor, fwMinor, err := firmware(tpm.transport); err == nil {
		props.FwMajor = fwMajor
		props.FwMinor = fwMinor
	} else {
		tpm.logger.Debug("failed to query firmware version", slog.String("error", err.Error()))
	}

	if v, err := level(tpm.transport); err == nil {
		props.Level = v
	} else {
		tpm.logger.Debug("failed to query level", slog.String("error", err.Error()))
	}

	if v, err := loadedCurves(tpm.transport); err == nil {
		props.LoadedCurves = v
	} else {
		tpm.logger.Debug("failed to query loadedCurves", slog.String("error", err.Error()))
	}

	if v, err := lockoutCounter(tpm.transport); err == nil {
		props.LockoutCounter = v
	} else {
		tpm.logger.Debug("failed to query lockoutCounter", slog.String("error", err.Error()))
	}

	if v, err := lockoutInterval(tpm.transport); err == nil {
		props.LockoutInterval = v
	} else {
		tpm.logger.Debug("failed to query lockoutInterval", slog.String("error", err.Error()))
	}

	if v, err := lockoutRecovery(tpm.transport); err == nil {
		props.LockoutRecovery = v
	} else {
		tpm.logger.Debug("failed to query lockoutRecovery", slog.String("error", err.Error()))
	}

	if v, err := manufacturer(tpm.transport); err == nil {
		props.Manufacturer = v
	} else {
		tpm.logger.Debug("failed to query manufacturer", slog.String("error", err.Error()))
	}

	if v, err := maxAuthFail(tpm.transport); err == nil {
		props.MaxAuthFail = v
	} else {
		tpm.logger.Debug("failed to query maxAuthFail", slog.String("error", err.Error()))
	}

	if v, err := model(tpm.transport); err == nil {
		props.Model = v
	} else {
		tpm.logger.Debug("failed to query model", slog.String("error", err.Error()))
	}

	if v, err := nvBufferMax(tpm.transport); err == nil {
		props.NVBufferMax = v
	} else {
		tpm.logger.Debug("failed to query nvBufferMax", slog.String("error", err.Error()))
	}

	if v, err := nvIndexesDefined(tpm.transport); err == nil {
		props.NVIndexesDefined = v
	} else {
		tpm.logger.Debug("failed to query nvIndexesDefined", slog.String("error", err.Error()))
	}

	if v, err := nvWriteRecovery(tpm.transport); err == nil {
		props.NVWriteRecovery = v
	} else {
		tpm.logger.Debug("failed to query nvWriteRecovery", slog.String("error", err.Error()))
	}

	if v, err := nvIndexesMax(tpm.transport); err == nil {
		props.NVIndexesMax = v
	} else {
		tpm.logger.Debug("failed to query nvIndexesMax", slog.String("error", err.Error()))
	}

	if v, err := memory(tpm.transport); err == nil {
		props.Memory = v
	} else {
		tpm.logger.Debug("failed to query memory", slog.String("error", err.Error()))
	}

	if v, err := revision(tpm.transport); err == nil {
		props.Revision = v
	} else {
		tpm.logger.Debug("failed to query revision", slog.String("error", err.Error()))
	}

	if v, err := vendorID(tpm.transport); err == nil {
		props.VendorID = v
	} else {
		tpm.logger.Debug("failed to query vendorID", slog.String("error", err.Error()))
	}

	if v, err := inputBufferMax(tpm.transport); err == nil {
		props.InputBufferMax = v
	} else {
		tpm.logger.Debug("failed to query inputBufferMax", slog.String("error", err.Error()))
	}

	if v, err := maxDigestSize(tpm.transport); err == nil {
		props.MaxDigestSize = v
	} else {
		tpm.logger.Debug("failed to query maxDigestSize", slog.String("error", err.Error()))
	}

	if v, err := maxObjectContext(tpm.transport); err == nil {
		props.MaxObjectContext = v
	} else {
		tpm.logger.Debug("failed to query maxObjectContext", slog.String("error", err.Error()))
	}

	// Batch-query remaining fixed properties (0x100 range) and variable
	// properties (0x200 range) to populate the new struct fields efficiently.
	if batch, err := queryPropertyBatch(tpm.transport, tpm2.TPMPTFamilyIndicator, 100); err == nil {
		if v, ok := batch[tpm2.TPMPTDayofYear]; ok {
			props.DayOfYear = v
		}
		if v, ok := batch[tpm2.TPMPTYear]; ok {
			props.Year = v
		}
		if v, ok := batch[tpm2.TPMPTPCRCount]; ok {
			props.PCRCount = v
		}
		if v, ok := batch[tpm2.TPMPTPCRSelectMin]; ok {
			props.PCRSelectMin = v
		}
		if v, ok := batch[tpm2.TPMPTContextGapMax]; ok {
			props.ContextGapMax = v
		}
		if v, ok := batch[tpm2.TPMPTNVCountersMax]; ok {
			props.NVCountersMax = v
		}
		if v, ok := batch[tpm2.TPMPTClockUpdate]; ok {
			props.ClockUpdate = v
		}
		if v, ok := batch[tpm2.TPMPTContextHash]; ok {
			props.ContextHash = v
		}
		if v, ok := batch[tpm2.TPMPTContextSym]; ok {
			props.ContextSym = v
		}
		if v, ok := batch[tpm2.TPMPTContextSymSize]; ok {
			props.ContextSymSize = v
		}
		if v, ok := batch[tpm2.TPMPTOrderlyCount]; ok {
			props.OrderlyCount = v
		}
		if v, ok := batch[tpm2.TPMPTMaxCommandSize]; ok {
			props.MaxCommandSize = v
		}
		if v, ok := batch[tpm2.TPMPTMaxResponseSize]; ok {
			props.MaxResponseSize = v
		}
		if v, ok := batch[tpm2.TPMPTMaxSessionContext]; ok {
			props.MaxSessionContext = v
		}
		if v, ok := batch[tpm2.TPMPTPSFamilyIndicator]; ok {
			props.PSFamilyIndicator = v
		}
		if v, ok := batch[tpm2.TPMPTPSLevel]; ok {
			props.PSLevel = v
		}
		if v, ok := batch[tpm2.TPMPTPSRevision]; ok {
			props.PSRevision = v
		}
		if v, ok := batch[tpm2.TPMPTPSDayOfYear]; ok {
			props.PSDayOfYear = v
		}
		if v, ok := batch[tpm2.TPMPTPSYear]; ok {
			props.PSYear = v
		}
		if v, ok := batch[tpm2.TPMPTSplitMax]; ok {
			props.SplitMax = v
		}
		if v, ok := batch[tpm2.TPMPTTotalCommands]; ok {
			props.TotalCommands = v
		}
		if v, ok := batch[tpm2.TPMPTLibraryCommands]; ok {
			props.LibraryCommands = v
		}
		if v, ok := batch[tpm2.TPMPTVendorCommands]; ok {
			props.VendorCommands = v
		}
		if v, ok := batch[tpm2.TPMPTMaxCapBuffer]; ok {
			props.MaxCapBuffer = v
		}
		if v, ok := batch[tpm2.TPMPTHRLoadedMin]; ok {
			props.HRLoadedMin = v
		}
	} else {
		tpm.logger.Debug("failed to batch-query fixed properties", slog.String("error", err.Error()))
	}

	// Batch-query variable properties (0x200 range)
	if batch, err := queryPropertyBatch(tpm.transport, tpm2.TPMPTPermanent, 100); err == nil {
		if v, ok := batch[tpm2.TPMPTPermanent]; ok {
			props.Permanent = v
		}
		if v, ok := batch[tpm2.TPMPTStartupClear]; ok {
			props.StartupClear = v
		}
		if v, ok := batch[tpm2.TPMPTNVCounters]; ok {
			props.NVCounters = v
		}
		if v, ok := batch[tpm2.TPMPTNVCountersAvail]; ok {
			props.NVCountersAvail = v
		}
		if v, ok := batch[tpm2.TPMPTAlgorithmSet]; ok {
			props.AlgorithmSet = v
		}
		if v, ok := batch[tpm2.TPMPTAuditCounter0]; ok {
			props.AuditCounter0 = v
		}
		if v, ok := batch[tpm2.TPMPTAuditCounter1]; ok {
			props.AuditCounter1 = v
		}
	} else {
		tpm.logger.Debug("failed to batch-query variable properties", slog.String("error", err.Error()))
	}

	// Query supported algorithms and derive max key sizes
	if algs, err := tpm.SupportedAlgorithms(); err == nil {
		props.SupportedAlgorithms = algs

		for _, alg := range algs {
			if alg == "RSA" {
				props.MaxRSAKeyBits = 2048
			}
			if alg == "ECC" {
				// Default to P-256; upgrade based on loaded curves
				props.MaxECCKeyBits = 256
				if props.LoadedCurves >= 3 {
					props.MaxECCKeyBits = 521
				} else if props.LoadedCurves >= 2 {
					props.MaxECCKeyBits = 384
				}
			}
		}
	} else {
		tpm.logger.Debug("failed to query supported algorithms", slog.String("error", err.Error()))
	}

	// Enumerate handles and NV indexes
	if v, err := persistentHandles(tpm.transport); err == nil {
		props.PersistentHandles = v
	} else {
		tpm.logger.Debug("failed to query persistent handles", slog.String("error", err.Error()))
	}

	if v, err := transientHandles(tpm.transport); err == nil {
		props.TransientHandles = v
	} else {
		tpm.logger.Debug("failed to query transient handles", slog.String("error", err.Error()))
	}

	if v, err := nvIndexes(tpm.transport, tpm.logger); err == nil {
		props.NVIndexes = v
	} else {
		tpm.logger.Debug("failed to query NV indexes", slog.String("error", err.Error()))
	}
	return props, nil
}

// AllFixedProperties queries all fixed TPM properties (0x100 range) and returns
// them as a sorted slice of TPMProperty values with canonical names, raw hex
// values, and human-readable formatted values for special properties.
func (tpm *TPM2) AllFixedProperties() ([]TPMProperty, error) {
	batch, err := queryPropertyBatch(tpm.transport, tpm2.TPMPTFamilyIndicator, 100)
	if err != nil {
		return nil, err
	}

	result := make([]TPMProperty, 0, len(batch))
	for prop, value := range batch {
		name, ok := tpmPTNames[prop]
		if !ok {
			name = fmt.Sprintf("TPM2_PT_0x%04X", uint32(prop))
		}

		raw := fmt.Sprintf("0x%X", value)
		formatted := formatFixedProperty(prop, value)

		result = append(result, TPMProperty{
			Name:  name,
			Raw:   raw,
			Value: formatted,
		})
	}

	slices.SortFunc(result, func(a, b TPMProperty) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})

	return result, nil
}

// AllVariableProperties queries all variable TPM properties (0x200 range) and
// returns them as a sorted slice of TPMProperty values with canonical names,
// raw hex values, and human-readable formatted values for special properties.
func (tpm *TPM2) AllVariableProperties() ([]TPMProperty, error) {
	batch, err := queryPropertyBatch(tpm.transport, tpm2.TPMPTPermanent, 100)
	if err != nil {
		return nil, err
	}

	result := make([]TPMProperty, 0, len(batch))
	for prop, value := range batch {
		name, ok := tpmPTNames[prop]
		if !ok {
			name = fmt.Sprintf("TPM2_PT_0x%04X", uint32(prop))
		}

		raw := fmt.Sprintf("0x%X", value)
		formatted := formatVariableProperty(prop, value)

		result = append(result, TPMProperty{
			Name:  name,
			Raw:   raw,
			Value: formatted,
		})
	}

	slices.SortFunc(result, func(a, b TPMProperty) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})

	return result, nil
}

// formatFixedProperty returns a human-readable formatted string for special
// fixed properties. Returns empty string for properties where the raw hex
// value is sufficient.
func formatFixedProperty(prop tpm2.TPMPT, value uint32) string {
	switch prop {
	case tpm2.TPMPTFamilyIndicator:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, value)
		return cleanTPMString(string(buf))

	case tpm2.TPMPTRevision:
		major := value / 100
		minor := value % 100
		return fmt.Sprintf("%d.%d", major, minor)

	case tpm2.TPMPTManufacturer:
		vendor := TCGVendorID(value)
		name := vendor.String()
		if name != "" {
			return name
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, value)
		ascii := cleanTPMString(string(buf))
		if ascii != "" && isPrintable(ascii) {
			return ascii
		}
		return ""

	case tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, value)
		return cleanTPMString(string(buf))

	case tpm2.TPMPTModes:
		if value&1 != 0 {
			return "TPMA_MODES_FIPS_140_2"
		}
		return ""

	default:
		return ""
	}
}

// formatVariableProperty returns a human-readable formatted string for special
// variable properties. Returns empty string for properties where the raw hex
// value is sufficient.
func formatVariableProperty(prop tpm2.TPMPT, value uint32) string {
	switch prop {
	case tpm2.TPMPTPermanent:
		return formatPermanentFlags(value)

	case tpm2.TPMPTStartupClear:
		return formatStartupClearFlags(value)

	default:
		return ""
	}
}

// formatPermanentFlags decodes the TPMA_PERMANENT bitmask into a
// human-readable comma-separated list of set flags.
func formatPermanentFlags(value uint32) string {
	type flagDef struct {
		bit  uint32
		name string
	}
	flags := []flagDef{
		{0x00000001, "ownerAuthSet"},
		{0x00000002, "endorsementAuthSet"},
		{0x00000004, "lockoutAuthSet"},
		{0x00000100, "disableClear"},
		{0x00000200, "inLockout"},
		{0x00000400, "tpmGeneratedEPS"},
	}
	var set []string
	for _, f := range flags {
		if value&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	return strings.Join(set, ", ")
}

// formatStartupClearFlags decodes the TPMA_STARTUP_CLEAR bitmask into a
// human-readable comma-separated list of set flags.
func formatStartupClearFlags(value uint32) string {
	type flagDef struct {
		bit  uint32
		name string
	}
	flags := []flagDef{
		{0x00000001, "phEnable"},
		{0x00000002, "shEnable"},
		{0x00000004, "ehEnable"},
		{0x00000008, "phEnableNV"},
		{0x80000000, "orderly"},
	}
	var set []string
	for _, f := range flags {
		if value&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	return strings.Join(set, ", ")
}

// algNames maps all TPMAlgID constants defined in TCG TPM 2.0 Part 2:
// Structures, section 6.3 to human-readable names. The map covers all 60
// algorithm identifiers defined in go-tpm v0.9.7.
var algNames = map[tpm2.TPMAlgID]string{
	tpm2.TPMAlgRSA:          "RSA",
	tpm2.TPMAlgTDES:         "TDES",
	tpm2.TPMAlgSHA1:         "SHA-1",
	tpm2.TPMAlgHMAC:         "HMAC",
	tpm2.TPMAlgAES:          "AES",
	tpm2.TPMAlgMGF1:         "MGF1",
	tpm2.TPMAlgKeyedHash:    "KeyedHash",
	tpm2.TPMAlgXOR:          "XOR",
	tpm2.TPMAlgSHA256:       "SHA-256",
	tpm2.TPMAlgSHA384:       "SHA-384",
	tpm2.TPMAlgSHA512:       "SHA-512",
	tpm2.TPMAlgSHA256192:    "SHA-256/192",
	tpm2.TPMAlgNull:         "NULL",
	tpm2.TPMAlgSM3256:       "SM3-256",
	tpm2.TPMAlgSM4:          "SM4",
	tpm2.TPMAlgRSASSA:       "RSASSA",
	tpm2.TPMAlgRSAES:        "RSAES",
	tpm2.TPMAlgRSAPSS:       "RSAPSS",
	tpm2.TPMAlgOAEP:         "OAEP",
	tpm2.TPMAlgECDSA:        "ECDSA",
	tpm2.TPMAlgECDH:         "ECDH",
	tpm2.TPMAlgECDAA:        "ECDAA",
	tpm2.TPMAlgSM2:          "SM2",
	tpm2.TPMAlgECSchnorr:    "EC-Schnorr",
	tpm2.TPMAlgECMQV:        "ECMQV",
	tpm2.TPMAlgKDF1SP80056A: "KDF1-SP800-56A",
	tpm2.TPMAlgKDF2:         "KDF2",
	tpm2.TPMAlgKDF1SP800108: "KDF1-SP800-108",
	tpm2.TPMAlgECC:          "ECC",
	tpm2.TPMAlgSymCipher:    "SymCipher",
	tpm2.TPMAlgCamellia:     "Camellia",
	tpm2.TPMAlgSHA3256:      "SHA3-256",
	tpm2.TPMAlgSHA3384:      "SHA3-384",
	tpm2.TPMAlgSHA3512:      "SHA3-512",
	tpm2.TPMAlgSHAKE128:     "SHAKE128",
	tpm2.TPMAlgSHAKE256:     "SHAKE256",
	tpm2.TPMAlgSHAKE256192:  "SHAKE256/192",
	tpm2.TPMAlgSHAKE256256:  "SHAKE256/256",
	tpm2.TPMAlgSHAKE256512:  "SHAKE256/512",
	tpm2.TPMAlgCMAC:         "CMAC",
	tpm2.TPMAlgCTR:          "CTR",
	tpm2.TPMAlgOFB:          "OFB",
	tpm2.TPMAlgCBC:          "CBC",
	tpm2.TPMAlgCFB:          "CFB",
	tpm2.TPMAlgECB:          "ECB",
	tpm2.TPMAlgCCM:          "CCM",
	tpm2.TPMAlgGCM:          "GCM",
	tpm2.TPMAlgKW:           "KW",
	tpm2.TPMAlgKWP:          "KWP",
	tpm2.TPMAlgEAX:          "EAX",
	tpm2.TPMAlgEDDSA:        "EdDSA",
	tpm2.TPMAlgEDDSAPH:      "EdDSA-PH",
	tpm2.TPMAlgLMS:          "LMS",
	tpm2.TPMAlgXMSS:         "XMSS",
	tpm2.TPMAlgKEYEDXOF:     "KeyedXOF",
	tpm2.TPMAlgKMACXOF128:   "KMAC-XOF-128",
	tpm2.TPMAlgKMACXOF256:   "KMAC-XOF-256",
	tpm2.TPMAlgKMAC128:      "KMAC-128",
	tpm2.TPMAlgKMAC256:      "KMAC-256",
}

// commandNames maps all TPMCC constants defined in TCG TPM 2.0 Part 3:
// Commands to their official TPM2_CC_* command names. The map covers all 118
// command codes defined in go-tpm v0.9.7.
var commandNames = map[tpm2.TPMCC]string{
	tpm2.TPMCCNVUndefineSpaceSpecial:     "TPM2_CC_NV_UndefineSpaceSpecial",
	tpm2.TPMCCEvictControl:               "TPM2_CC_EvictControl",
	tpm2.TPMCCHierarchyControl:           "TPM2_CC_HierarchyControl",
	tpm2.TPMCCNVUndefineSpace:            "TPM2_CC_NV_UndefineSpace",
	tpm2.TPMCCChangeEPS:                  "TPM2_CC_ChangeEPS",
	tpm2.TPMCCChangePPS:                  "TPM2_CC_ChangePPS",
	tpm2.TPMCCClear:                      "TPM2_CC_Clear",
	tpm2.TPMCCClearControl:               "TPM2_CC_ClearControl",
	tpm2.TPMCCClockSet:                   "TPM2_CC_ClockSet",
	tpm2.TPMCCHierarchyChanegAuth:        "TPM2_CC_HierarchyChangeAuth",
	tpm2.TPMCCNVDefineSpace:              "TPM2_CC_NV_DefineSpace",
	tpm2.TPMCCPCRAllocate:                "TPM2_CC_PCR_Allocate",
	tpm2.TPMCCPCRSetAuthPolicy:           "TPM2_CC_PCR_SetAuthPolicy",
	tpm2.TPMCCPPCommands:                 "TPM2_CC_PP_Commands",
	tpm2.TPMCCSetPrimaryPolicy:           "TPM2_CC_SetPrimaryPolicy",
	tpm2.TPMCCFieldUpgradeStart:          "TPM2_CC_FieldUpgradeStart",
	tpm2.TPMCCClockRateAdjust:            "TPM2_CC_ClockRateAdjust",
	tpm2.TPMCCCreatePrimary:              "TPM2_CC_CreatePrimary",
	tpm2.TPMCCNVGlobalWriteLock:          "TPM2_CC_NV_GlobalWriteLock",
	tpm2.TPMCCGetCommandAuditDigest:      "TPM2_CC_GetCommandAuditDigest",
	tpm2.TPMCCNVIncrement:                "TPM2_CC_NV_Increment",
	tpm2.TPMCCNVSetBits:                  "TPM2_CC_NV_SetBits",
	tpm2.TPMCCNVExtend:                   "TPM2_CC_NV_Extend",
	tpm2.TPMCCNVWrite:                    "TPM2_CC_NV_Write",
	tpm2.TPMCCNVWriteLock:                "TPM2_CC_NV_WriteLock",
	tpm2.TPMCCDictionaryAttackLockReset:  "TPM2_CC_DictionaryAttackLockReset",
	tpm2.TPMCCDictionaryAttackParameters: "TPM2_CC_DictionaryAttackParameters",
	tpm2.TPMCCNVChangeAuth:               "TPM2_CC_NV_ChangeAuth",
	tpm2.TPMCCPCREvent:                   "TPM2_CC_PCR_Event",
	tpm2.TPMCCPCRReset:                   "TPM2_CC_PCR_Reset",
	tpm2.TPMCCSequenceComplete:           "TPM2_CC_SequenceComplete",
	tpm2.TPMCCSetAlgorithmSet:            "TPM2_CC_SetAlgorithmSet",
	tpm2.TPMCCSetCommandCodeAuditStatus:  "TPM2_CC_SetCommandCodeAuditStatus",
	tpm2.TPMCCFieldUpgradeData:           "TPM2_CC_FieldUpgradeData",
	tpm2.TPMCCIncrementalSelfTest:        "TPM2_CC_IncrementalSelfTest",
	tpm2.TPMCCSelfTest:                   "TPM2_CC_SelfTest",
	tpm2.TPMCCStartup:                    "TPM2_CC_Startup",
	tpm2.TPMCCShutdown:                   "TPM2_CC_Shutdown",
	tpm2.TPMCCStirRandom:                 "TPM2_CC_StirRandom",
	tpm2.TPMCCActivateCredential:         "TPM2_CC_ActivateCredential",
	tpm2.TPMCCCertify:                    "TPM2_CC_Certify",
	tpm2.TPMCCPolicyNV:                   "TPM2_CC_PolicyNV",
	tpm2.TPMCCCertifyCreation:            "TPM2_CC_CertifyCreation",
	tpm2.TPMCCDuplicate:                  "TPM2_CC_Duplicate",
	tpm2.TPMCCGetTime:                    "TPM2_CC_GetTime",
	tpm2.TPMCCGetSessionAuditDigest:      "TPM2_CC_GetSessionAuditDigest",
	tpm2.TPMCCNVRead:                     "TPM2_CC_NV_Read",
	tpm2.TPMCCNVReadLock:                 "TPM2_CC_NV_ReadLock",
	tpm2.TPMCCObjectChangeAuth:           "TPM2_CC_ObjectChangeAuth",
	tpm2.TPMCCPolicySecret:               "TPM2_CC_PolicySecret",
	tpm2.TPMCCRewrap:                     "TPM2_CC_Rewrap",
	tpm2.TPMCCCreate:                     "TPM2_CC_Create",
	tpm2.TPMCCECDHZGen:                   "TPM2_CC_ECDH_ZGen",
	tpm2.TPMCCMAC:                        "TPM2_CC_MAC",
	tpm2.TPMCCImport:                     "TPM2_CC_Import",
	tpm2.TPMCCLoad:                       "TPM2_CC_Load",
	tpm2.TPMCCQuote:                      "TPM2_CC_Quote",
	tpm2.TPMCCRSADecrypt:                 "TPM2_CC_RSA_Decrypt",
	tpm2.TPMCCMACStart:                   "TPM2_CC_MAC_Start",
	tpm2.TPMCCSequenceUpdate:             "TPM2_CC_SequenceUpdate",
	tpm2.TPMCCSign:                       "TPM2_CC_Sign",
	tpm2.TPMCCUnseal:                     "TPM2_CC_Unseal",
	tpm2.TPMCCPolicySigned:               "TPM2_CC_PolicySigned",
	tpm2.TPMCCContextLoad:                "TPM2_CC_ContextLoad",
	tpm2.TPMCCContextSave:                "TPM2_CC_ContextSave",
	tpm2.TPMCCECDHKeyGen:                 "TPM2_CC_ECDH_KeyGen",
	tpm2.TPMCCEncryptDecrypt:             "TPM2_CC_EncryptDecrypt",
	tpm2.TPMCCFlushContext:               "TPM2_CC_FlushContext",
	tpm2.TPMCCLoadExternal:               "TPM2_CC_LoadExternal",
	tpm2.TPMCCMakeCredential:             "TPM2_CC_MakeCredential",
	tpm2.TPMCCNVReadPublic:               "TPM2_CC_NV_ReadPublic",
	tpm2.TPMCCPolicyAuthorize:            "TPM2_CC_PolicyAuthorize",
	tpm2.TPMCCPolicyAuthValue:            "TPM2_CC_PolicyAuthValue",
	tpm2.TPMCCPolicyCommandCode:          "TPM2_CC_PolicyCommandCode",
	tpm2.TPMCCPolicyCounterTimer:         "TPM2_CC_PolicyCounterTimer",
	tpm2.TPMCCPolicyCpHash:               "TPM2_CC_PolicyCpHash",
	tpm2.TPMCCPolicyLocality:             "TPM2_CC_PolicyLocality",
	tpm2.TPMCCPolicyNameHash:             "TPM2_CC_PolicyNameHash",
	tpm2.TPMCCPolicyOR:                   "TPM2_CC_PolicyOR",
	tpm2.TPMCCPolicyTicket:               "TPM2_CC_PolicyTicket",
	tpm2.TPMCCReadPublic:                 "TPM2_CC_ReadPublic",
	tpm2.TPMCCRSAEncrypt:                 "TPM2_CC_RSA_Encrypt",
	tpm2.TPMCCStartAuthSession:           "TPM2_CC_StartAuthSession",
	tpm2.TPMCCVerifySignature:            "TPM2_CC_VerifySignature",
	tpm2.TPMCCECCParameters:              "TPM2_CC_ECC_Parameters",
	tpm2.TPMCCFirmwareRead:               "TPM2_CC_FirmwareRead",
	tpm2.TPMCCGetCapability:              "TPM2_CC_GetCapability",
	tpm2.TPMCCGetRandom:                  "TPM2_CC_GetRandom",
	tpm2.TPMCCGetTestResult:              "TPM2_CC_GetTestResult",
	tpm2.TPMCCHash:                       "TPM2_CC_Hash",
	tpm2.TPMCCPCRRead:                    "TPM2_CC_PCR_Read",
	tpm2.TPMCCPolicyPCR:                  "TPM2_CC_PolicyPCR",
	tpm2.TPMCCPolicyRestart:              "TPM2_CC_PolicyRestart",
	tpm2.TPMCCReadClock:                  "TPM2_CC_ReadClock",
	tpm2.TPMCCPCRExtend:                  "TPM2_CC_PCR_Extend",
	tpm2.TPMCCPCRSetAuthValue:            "TPM2_CC_PCR_SetAuthValue",
	tpm2.TPMCCNVCertify:                  "TPM2_CC_NV_Certify",
	tpm2.TPMCCEventSequenceComplete:      "TPM2_CC_EventSequenceComplete",
	tpm2.TPMCCHashSequenceStart:          "TPM2_CC_HashSequenceStart",
	tpm2.TPMCCPolicyPhysicalPresence:     "TPM2_CC_PolicyPhysicalPresence",
	tpm2.TPMCCPolicyDuplicationSelect:    "TPM2_CC_PolicyDuplicationSelect",
	tpm2.TPMCCPolicyGetDigest:            "TPM2_CC_PolicyGetDigest",
	tpm2.TPMCCTestParms:                  "TPM2_CC_TestParms",
	tpm2.TPMCCCommit:                     "TPM2_CC_Commit",
	tpm2.TPMCCPolicyPassword:             "TPM2_CC_PolicyPassword",
	tpm2.TPMCCZGen2Phase:                 "TPM2_CC_ZGen_2Phase",
	tpm2.TPMCCECEphemeral:                "TPM2_CC_EC_Ephemeral",
	tpm2.TPMCCPolicyNvWritten:            "TPM2_CC_PolicyNvWritten",
	tpm2.TPMCCPolicyTemplate:             "TPM2_CC_PolicyTemplate",
	tpm2.TPMCCCreateLoaded:               "TPM2_CC_CreateLoaded",
	tpm2.TPMCCPolicyAuthorizeNV:          "TPM2_CC_PolicyAuthorizeNV",
	tpm2.TPMCCEncryptDecrypt2:            "TPM2_CC_EncryptDecrypt2",
	tpm2.TPMCCACGetCapability:            "TPM2_CC_AC_GetCapability",
	tpm2.TPMCCACSend:                     "TPM2_CC_AC_Send",
	tpm2.TPMCCPolicyACSendSelect:         "TPM2_CC_PolicyACSendSelect",
	tpm2.TPMCCCertifyX509:                "TPM2_CC_CertifyX509",
	tpm2.TPMCCACTSetTimeout:              "TPM2_CC_ACT_SetTimeout",
}

// commandDescriptions maps TPMCC constants to short descriptions from
// TCG TPM 2.0 Part 3: Commands.
var commandDescriptions = map[tpm2.TPMCC]string{
	tpm2.TPMCCNVUndefineSpaceSpecial:     "Remove an NV index that requires platform authorization",
	tpm2.TPMCCEvictControl:               "Make a transient object persistent or evict a persistent object",
	tpm2.TPMCCHierarchyControl:           "Enable or disable use of a hierarchy and its associated NV storage",
	tpm2.TPMCCNVUndefineSpace:            "Remove an NV index from the TPM",
	tpm2.TPMCCChangeEPS:                  "Replace the endorsement primary seed with a new random value",
	tpm2.TPMCCChangePPS:                  "Replace the platform primary seed with a new random value",
	tpm2.TPMCCClear:                      "Remove all TPM context associated with a specific owner",
	tpm2.TPMCCClearControl:               "Disable or enable the execution of TPM2_Clear",
	tpm2.TPMCCClockSet:                   "Set the TPM clock to a specific value",
	tpm2.TPMCCHierarchyChanegAuth:        "Change the authorization value for a hierarchy or lockout",
	tpm2.TPMCCNVDefineSpace:              "Define an NV index with given attributes and authorization policy",
	tpm2.TPMCCPCRAllocate:                "Set the allocation of PCR banks for the next TPM reset",
	tpm2.TPMCCPCRSetAuthPolicy:           "Change the authorization policy for a PCR",
	tpm2.TPMCCPPCommands:                 "Indicate commands that require physical presence for authorization",
	tpm2.TPMCCSetPrimaryPolicy:           "Set the authorization policy for a hierarchy",
	tpm2.TPMCCFieldUpgradeStart:          "Begin a field upgrade sequence for TPM firmware",
	tpm2.TPMCCClockRateAdjust:            "Adjust the rate of advance of the TPM clock",
	tpm2.TPMCCCreatePrimary:              "Create a primary object under a specified hierarchy",
	tpm2.TPMCCNVGlobalWriteLock:          "Set the global NV write lock for all NV indices with GLOBALLOCK set",
	tpm2.TPMCCGetCommandAuditDigest:      "Get a signed digest of the command audit log and reset it",
	tpm2.TPMCCNVIncrement:                "Increment the value of an NV counter index",
	tpm2.TPMCCNVSetBits:                  "Set bits in an NV index of type bit field",
	tpm2.TPMCCNVExtend:                   "Extend a hash value into an NV index of type extend",
	tpm2.TPMCCNVWrite:                    "Write a value to an NV index",
	tpm2.TPMCCNVWriteLock:                "Set the write lock on an NV index",
	tpm2.TPMCCDictionaryAttackLockReset:  "Reset the dictionary attack lockout counter to zero",
	tpm2.TPMCCDictionaryAttackParameters: "Set the dictionary attack lockout parameters",
	tpm2.TPMCCNVChangeAuth:               "Change the authorization value for an NV index",
	tpm2.TPMCCPCREvent:                   "Extend a PCR in all allocated banks using an event data input",
	tpm2.TPMCCPCRReset:                   "Reset a resettable PCR to its default value",
	tpm2.TPMCCSequenceComplete:           "Complete a hash or HMAC sequence and return the result",
	tpm2.TPMCCSetAlgorithmSet:            "Set the algorithm set selection for the TPM",
	tpm2.TPMCCSetCommandCodeAuditStatus:  "Add or remove commands from the command audit list",
	tpm2.TPMCCFieldUpgradeData:           "Provide field upgrade data to the TPM",
	tpm2.TPMCCIncrementalSelfTest:        "Run self-tests on selected algorithms not yet tested",
	tpm2.TPMCCSelfTest:                   "Run a full or incremental self-test of TPM functions",
	tpm2.TPMCCStartup:                    "Initialize the TPM after a power cycle or reset",
	tpm2.TPMCCShutdown:                   "Prepare the TPM for a power cycle or reset",
	tpm2.TPMCCStirRandom:                 "Add entropy to the TPM random number generator state",
	tpm2.TPMCCActivateCredential:         "Decrypt a credential blob bound to a specific object name",
	tpm2.TPMCCCertify:                    "Prove that an object is loaded in the TPM and provide its properties",
	tpm2.TPMCCPolicyNV:                   "Include an NV index value comparison in a policy evaluation",
	tpm2.TPMCCCertifyCreation:            "Prove the association between an object and its creation data",
	tpm2.TPMCCDuplicate:                  "Duplicate a loaded object for use in a different hierarchy",
	tpm2.TPMCCGetTime:                    "Get a signed attestation of the current time and clock values",
	tpm2.TPMCCGetSessionAuditDigest:      "Get a signed digest of the audit session log",
	tpm2.TPMCCNVRead:                     "Read a value from an NV index",
	tpm2.TPMCCNVReadLock:                 "Set the read lock on an NV index",
	tpm2.TPMCCObjectChangeAuth:           "Change the authorization value for a loaded object",
	tpm2.TPMCCPolicySecret:               "Include a secret-based authorization in a policy evaluation",
	tpm2.TPMCCRewrap:                     "Change the parent of an object without revealing the sensitive area",
	tpm2.TPMCCCreate:                     "Create a child object under a specified parent key",
	tpm2.TPMCCECDHZGen:                   "Perform ECDH key agreement using a loaded private key",
	tpm2.TPMCCMAC:                        "Compute a MAC on a data buffer using a loaded MAC key",
	tpm2.TPMCCImport:                     "Import an external key blob into the TPM under a parent key",
	tpm2.TPMCCLoad:                       "Load a wrapped key object into the TPM",
	tpm2.TPMCCQuote:                      "Generate a signed attestation of selected PCR values",
	tpm2.TPMCCRSADecrypt:                 "Decrypt a ciphertext using a loaded RSA private key",
	tpm2.TPMCCMACStart:                   "Start a MAC sequence for incremental MAC computation",
	tpm2.TPMCCSequenceUpdate:             "Add data to a hash, HMAC, or MAC sequence",
	tpm2.TPMCCSign:                       "Sign a digest using a loaded private key",
	tpm2.TPMCCUnseal:                     "Return the sealed data blob associated with a loaded sealed object",
	tpm2.TPMCCPolicySigned:               "Include a signed authorization in a policy evaluation",
	tpm2.TPMCCContextLoad:                "Load a saved object or session context back into the TPM",
	tpm2.TPMCCContextSave:                "Save an object or session context for later loading",
	tpm2.TPMCCECDHKeyGen:                 "Generate an ephemeral ECC key pair for ECDH key agreement",
	tpm2.TPMCCEncryptDecrypt:             "Perform symmetric encryption or decryption using a loaded key",
	tpm2.TPMCCFlushContext:               "Remove a loaded object, session, or sequence from TPM memory",
	tpm2.TPMCCLoadExternal:               "Load an external object (public or public+sensitive) into the TPM",
	tpm2.TPMCCMakeCredential:             "Create a credential blob bound to a specific object name",
	tpm2.TPMCCNVReadPublic:               "Read the public attributes of an NV index",
	tpm2.TPMCCPolicyAuthorize:            "Approve a policy by verifying a signature over its digest",
	tpm2.TPMCCPolicyAuthValue:            "Include the object auth value in the policy HMAC key",
	tpm2.TPMCCPolicyCommandCode:          "Restrict a policy to a single command code",
	tpm2.TPMCCPolicyCounterTimer:         "Include a counter or timer comparison in a policy evaluation",
	tpm2.TPMCCPolicyCpHash:               "Bind a policy to a specific command parameter hash",
	tpm2.TPMCCPolicyLocality:             "Restrict a policy to specific TPM localities",
	tpm2.TPMCCPolicyNameHash:             "Bind a policy to a specific set of TPM object names",
	tpm2.TPMCCPolicyOR:                   "Combine multiple policy branches using logical OR",
	tpm2.TPMCCPolicyTicket:               "Include a previously obtained authorization ticket in a policy",
	tpm2.TPMCCReadPublic:                 "Read the public area of a loaded object",
	tpm2.TPMCCRSAEncrypt:                 "Encrypt a message using a loaded RSA public key",
	tpm2.TPMCCStartAuthSession:           "Start an authorization session (HMAC, policy, or trial)",
	tpm2.TPMCCVerifySignature:            "Verify a signature against a loaded public key",
	tpm2.TPMCCECCParameters:              "Return the parameters of an ECC curve",
	tpm2.TPMCCFirmwareRead:               "Read TPM firmware data for field upgrade or diagnostics",
	tpm2.TPMCCGetCapability:              "Query TPM properties, algorithms, commands, or handles",
	tpm2.TPMCCGetRandom:                  "Get random bytes from the TPM random number generator",
	tpm2.TPMCCGetTestResult:              "Get the results of the last self-test",
	tpm2.TPMCCHash:                       "Compute a hash of a data buffer and optionally extend into a PCR",
	tpm2.TPMCCPCRRead:                    "Read the current values of selected PCRs",
	tpm2.TPMCCPolicyPCR:                  "Bind a policy to the current values of selected PCRs",
	tpm2.TPMCCPolicyRestart:              "Reset a policy session to its initial state",
	tpm2.TPMCCReadClock:                  "Read the current TPM clock, time, and reset count values",
	tpm2.TPMCCPCRExtend:                  "Extend a digest value into one or more PCR banks",
	tpm2.TPMCCPCRSetAuthValue:            "Change the authorization value for a PCR",
	tpm2.TPMCCNVCertify:                  "Certify the contents of an NV index with a signing key",
	tpm2.TPMCCEventSequenceComplete:      "Complete an event sequence and extend the result into PCRs",
	tpm2.TPMCCHashSequenceStart:          "Start a hash or event sequence for incremental hashing",
	tpm2.TPMCCPolicyPhysicalPresence:     "Require physical presence assertion for policy satisfaction",
	tpm2.TPMCCPolicyDuplicationSelect:    "Restrict a policy to allow duplication only to a specific parent",
	tpm2.TPMCCPolicyGetDigest:            "Return the current policy digest of a policy session",
	tpm2.TPMCCTestParms:                  "Test whether the TPM supports a given algorithm combination",
	tpm2.TPMCCCommit:                     "Perform an ECC commit operation for anonymous attestation (DAA)",
	tpm2.TPMCCPolicyPassword:             "Include the object password in policy session authorization",
	tpm2.TPMCCZGen2Phase:                 "Perform the second phase of a two-phase ECC key exchange",
	tpm2.TPMCCECEphemeral:                "Generate an ephemeral ECC key pair and return the commit counter",
	tpm2.TPMCCPolicyNvWritten:            "Include the NV index written state in a policy evaluation",
	tpm2.TPMCCPolicyTemplate:             "Bind a policy to a specific object template hash",
	tpm2.TPMCCCreateLoaded:               "Create and load a key object in a single command",
	tpm2.TPMCCPolicyAuthorizeNV:          "Use an NV index to store an approved policy for authorization",
	tpm2.TPMCCEncryptDecrypt2:            "Perform symmetric encrypt or decrypt with the data parameter encrypted",
	tpm2.TPMCCACGetCapability:            "Get the capabilities of an attached component",
	tpm2.TPMCCACSend:                     "Send a command to an attached component",
	tpm2.TPMCCPolicyACSendSelect:         "Include attached component selection in a policy evaluation",
	tpm2.TPMCCCertifyX509:                "Generate an X.509 certificate for a loaded key signed by the TPM",
	tpm2.TPMCCACTSetTimeout:              "Set the timeout for an authenticated countdown timer",
}

// curveNames maps TPMECCCurve constants defined in TCG TPM 2.0 Part 2:
// Structures, section 6.4 to human-readable curve names. TPMECCNone is
// excluded because it represents the absence of a curve.
var curveNames = map[tpm2.TPMECCCurve]string{
	tpm2.TPMECCNistP192:        "NIST P-192",
	tpm2.TPMECCNistP224:        "NIST P-224",
	tpm2.TPMECCNistP256:        "NIST P-256",
	tpm2.TPMECCNistP384:        "NIST P-384",
	tpm2.TPMECCNistP521:        "NIST P-521",
	tpm2.TPMECCBNP256:          "BN P-256",
	tpm2.TPMECCBNP638:          "BN P-638",
	tpm2.TPMECCSM2P256:         "SM2 P-256",
	tpm2.TPMECCBrainpoolP256R1: "Brainpool P-256r1",
	tpm2.TPMECCBrainpoolP384R1: "Brainpool P-384r1",
	tpm2.TPMECCBrainpoolP512R1: "Brainpool P-512r1",
	tpm2.TPMECCCurve25519:      "Curve25519",
	tpm2.TPMECCCurve448:        "Curve448",
}

// SupportedAlgorithms returns the list of algorithm names supported by this TPM.
func (tpm *TPM2) SupportedAlgorithms() ([]string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapAlgs,
		Property:      0,
		PropertyCount: 100,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	algProps, err := response.CapabilityData.Data.Algorithms()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, ap := range algProps.AlgProperties {
		if name, ok := algNames[ap.Alg]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("0x%04X", ap.Alg))
		}
	}
	return result, nil
}

// SupportedCommands returns the list of command names supported by this TPM.
func (tpm *TPM2) SupportedCommands() ([]string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapCommands,
		Property:      uint32(tpm2.TPMCCNVUndefineSpaceSpecial),
		PropertyCount: 256,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	cmdAttrs, err := response.CapabilityData.Data.Command()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, attr := range cmdAttrs.CommandAttributes {
		cc := tpm2.TPMCC(attr.CommandIndex)
		if name, ok := commandNames[cc]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("0x%04X", attr.CommandIndex))
		}
	}
	return result, nil
}

// SupportedCommandsInfo returns detailed information about each supported TPM
// command, including hex code, name, and description. For unknown commands
// (vendor-specific or not in go-tpm), the name is "Vendor Command (0xNNNN)"
// and a generic description is provided.
func (tpm *TPM2) SupportedCommandsInfo() ([]CommandInfo, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapCommands,
		Property:      uint32(tpm2.TPMCCNVUndefineSpaceSpecial),
		PropertyCount: 256,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	cmdAttrs, err := response.CapabilityData.Data.Command()
	if err != nil {
		return nil, err
	}

	result := make([]CommandInfo, 0, len(cmdAttrs.CommandAttributes))
	for _, attr := range cmdAttrs.CommandAttributes {
		cc := tpm2.TPMCC(attr.CommandIndex)
		code := fmt.Sprintf("0x%04X", attr.CommandIndex)

		name, nameOK := commandNames[cc]
		if !nameOK {
			name = fmt.Sprintf("Vendor Command (%s)", code)
		}

		desc, descOK := commandDescriptions[cc]
		if !descOK {
			if nameOK {
				desc = "TPM 2.0 command"
			} else {
				desc = "Vendor-specific or implementation-defined TPM command"
			}
		}

		result = append(result, CommandInfo{
			Code:        code,
			Name:        name,
			Description: desc,
		})
	}
	return result, nil
}

// SupportedECCCurves returns the list of ECC curve names supported by this TPM.
func (tpm *TPM2) SupportedECCCurves() ([]string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapECCCurves,
		Property:      0,
		PropertyCount: 100,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	eccCurves, err := response.CapabilityData.Data.ECCCurves()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, curve := range eccCurves.ECCCurves {
		if name, ok := curveNames[curve]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("0x%04X", curve))
		}
	}
	return result, nil
}

func memory(transport transport.TPM) (uint32, error) {
	memoryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMemory),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	memory, err := memoryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return memory.TPMProperty[0].Value, nil
}

func persistentLoaded(transport transport.TPM) (uint32, error) {
	persistentLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistent),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	persistentLoaded, err := persistentLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentLoaded.TPMProperty[0].Value, nil
}

func persistentAvail(transport transport.TPM) (uint32, error) {
	persistentAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistentAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	persistentAvail, err := persistentAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentAvail.TPMProperty[0].Value, nil
}

func persistentMin(transport transport.TPM) (uint32, error) {
	persistentMinResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRPersistentMin),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	persistentMin, err := persistentMinResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return persistentMin.TPMProperty[0].Value, nil
}

func transientMin(transport transport.TPM) (uint32, error) {
	transientLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRTransientMin),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	transientLoaded, err := transientLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return transientLoaded.TPMProperty[0].Value, nil
}

func transientAvail(transport transport.TPM) (uint32, error) {
	transientAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRTransientAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	transientAvail, err := transientAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return transientAvail.TPMProperty[0].Value, nil
}

func activeSessionsMax(transport transport.TPM) (uint32, error) {
	activeSessionsMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTActiveSessionsMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	activeSessionsMax, err := activeSessionsMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return activeSessionsMax.TPMProperty[0].Value, nil
}

func authSessionsActive(transport transport.TPM) (uint32, error) {
	authSessionsActiveResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRActive),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsActive, err := authSessionsActiveResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsActive.TPMProperty[0].Value, nil
}

func authSessionsActiveAvail(transport transport.TPM) (uint32, error) {
	authSessionsActiveAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRActiveAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsActiveAvail, err := authSessionsActiveAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsActiveAvail.TPMProperty[0].Value, nil
}

func authSessionsLoaded(transport transport.TPM) (uint32, error) {
	authSessionsLoadedResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRLoaded),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsLoaded, err := authSessionsLoadedResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsLoaded.TPMProperty[0].Value, nil
}

func authSessionsLoadedAvail(transport transport.TPM) (uint32, error) {
	authSessionsLoadedAvailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRLoadedAvail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	authSessionsAvail, err := authSessionsLoadedAvailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return authSessionsAvail.TPMProperty[0].Value, nil
}

func family(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFamilyIndicator),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	family, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, family.TPMProperty[0].Value)
	return cleanTPMString(string(buf)), nil
}

func firmware(transport transport.TPM) (int64, int64, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtFwVersion1,
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, 0, err
	}
	firmware, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, 0, err
	}
	fw := firmware.TPMProperty[0].Value
	var fwMajor = int64((fw & 0xffff0000) >> 16)
	var fwMinor = int64(fw & 0x0000ffff)
	return fwMajor, fwMinor, nil
}

func level(transport transport.TPM) (uint32, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLevel),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	props, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return props.TPMProperty[0].Value, nil
}

func loadedCurves(transport transport.TPM) (uint32, error) {
	loadedCurvesResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLoadedCurves),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	loadedCurves, err := loadedCurvesResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return loadedCurves.TPMProperty[0].Value, nil
}

func lockoutCounter(transport transport.TPM) (uint32, error) {
	lockoutCounterResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutCounter),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	lockoutCounter, err := lockoutCounterResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutCounter.TPMProperty[0].Value, nil
}

func lockoutRecovery(transport transport.TPM) (uint32, error) {
	lockoutRecoveryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutRecovery),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	lockoutRecovery, err := lockoutRecoveryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutRecovery.TPMProperty[0].Value, nil
}

func lockoutInterval(transport transport.TPM) (uint32, error) {
	lockoutIntervalResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutInterval),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	lockoutInterval, err := lockoutIntervalResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return lockoutInterval.TPMProperty[0].Value, nil
}

func manufacturer(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      tpmPtManufacturer,
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	mfgProps, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	val := mfgProps.TPMProperty[0].Value

	// Try the TCG vendor ID lookup first.
	vendor := TCGVendorID(val)
	name := vendor.String()
	if name != "" {
		return name, nil
	}

	// Fallback: hex representation. The ASCII conversion of the 4-byte
	// manufacturer code produces short codes like "IFX" that look like
	// garbage for unknown vendors, so skip it entirely.
	return fmt.Sprintf("0x%08X", val), nil
}

func model(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTVendorTPMType),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	modelProps, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	val := modelProps.TPMProperty[0].Value

	// Try ASCII conversion first.
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	ascii := cleanTPMString(string(buf))
	if ascii != "" && isPrintable(ascii) {
		return ascii, nil
	}

	// Fallback: return the numeric value.
	return fmt.Sprintf("%d", val), nil
}

func maxAuthFail(transport transport.TPM) (uint32, error) {
	maxAuthFailResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMaxAuthFail),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	maxAuthFail, err := maxAuthFailResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return maxAuthFail.TPMProperty[0].Value, nil
}

func nvIndexesDefined(transport transport.TPM) (uint32, error) {
	nvIndexResponse, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTHRNVIndex),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvIndex, err := nvIndexResponse.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvIndex.TPMProperty[0].Value, nil
}

func nvIndexesMax(transport transport.TPM) (uint32, error) {
	nvIndexesMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvIndexesMax, err := nvIndexesMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvIndexesMax.TPMProperty[0].Value, nil
}

func nvBufferMax(transport transport.TPM) (uint32, error) {
	nvBufferMaxResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvBufferMax, err := nvBufferMaxResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvBufferMax.TPMProperty[0].Value, nil
}

func inputBufferMax(transport transport.TPM) (uint32, error) {
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTInputBuffer),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return props.TPMProperty[0].Value, nil
}

func maxDigestSize(transport transport.TPM) (uint32, error) {
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMaxDigest),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return props.TPMProperty[0].Value, nil
}

func maxObjectContext(transport transport.TPM) (uint32, error) {
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTMaxObjectContext),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return props.TPMProperty[0].Value, nil
}

func nvWriteRecovery(transport transport.TPM) (uint32, error) {
	nvWriteRecoveryResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVWriteRecovery),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return 0, err
	}
	nvWriteRecovery, err := nvWriteRecoveryResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	return nvWriteRecovery.TPMProperty[0].Value, nil
}

func revision(transport transport.TPM) (string, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTRevision),
		PropertyCount: 1,
	}.Execute(transport)
	if err != nil {
		return "", err
	}
	revision, err := response.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	rev := fmt.Sprintf("%04d", revision.TPMProperty[0].Value)
	major := strings.TrimLeft(rev[:2], "0")
	minor := rev[2:]
	return fmt.Sprintf("%s.%s", major, minor), nil
}

func vendorID(transport transport.TPM) (string, error) {
	var vendorString string
	props := []tpm2.TPMPT{
		tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4}

	for _, prop := range props {
		vendorResp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}.Execute(transport)
		if err != nil {
			return "", err
		}
		vendorStr, err := vendorResp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return "", err
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, vendorStr.TPMProperty[0].Value)
		vendorString += string(buf)
	}
	return cleanTPMString(vendorString), nil
}

// persistentHandles queries the TPM for all persistent handles in the
// range 0x81000000-0x81FFFFFF using TPM2_GetCapability with TPM_CAP_HANDLES.
func persistentHandles(t transport.TPM) ([]tpm2.TPMHandle, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(0x81000000),
		PropertyCount: 255,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListPersistentHandles, err)
	}

	handles, err := response.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListPersistentHandles, err)
	}

	return handles.Handle, nil
}

// transientHandles queries the TPM for all currently loaded transient
// handles in the range 0x80000000-0x80FFFFFF using TPM2_GetCapability
// with TPM_CAP_HANDLES.
func transientHandles(t transport.TPM) ([]tpm2.TPMHandle, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(0x80000000),
		PropertyCount: 255,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListTransientHandles, err)
	}

	handles, err := response.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListTransientHandles, err)
	}

	return handles.Handle, nil
}

// nvIndexes queries the TPM for all defined NV indexes using
// TPM2_GetCapability with TPM_CAP_HANDLES, then reads the NV public
// area for each index to determine type, size, and attributes.
func nvIndexes(t transport.TPM, logger *slog.Logger) ([]NVIndexInfo, error) {
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(0x01000000),
		PropertyCount: 255,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListNVIndexes, err)
	}

	handles, err := response.CapabilityData.Data.Handles()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListNVIndexes, err)
	}

	var indexes []NVIndexInfo
	for _, handle := range handles.Handle {
		nvPub, err := tpm2.NVReadPublic{
			NVIndex: handle,
		}.Execute(t)
		if err != nil {
			logger.Debug("unable to read NV public",
				slog.String("handle", fmt.Sprintf("0x%08X", handle)),
				slog.String("error", err.Error()))
			continue
		}

		pub, err := nvPub.NVPublic.Contents()
		if err != nil {
			logger.Debug("unable to get NV public contents",
				slog.String("handle", fmt.Sprintf("0x%08X", handle)),
				slog.String("error", err.Error()))
			continue
		}

		var nvType string
		switch pub.Attributes.NT {
		case tpm2.TPMNTCounter:
			nvType = "counter"
		case tpm2.TPMNTExtend:
			nvType = "extend"
		default:
			nvType = "ordinary"
		}

		indexes = append(indexes, NVIndexInfo{
			Handle:    handle,
			Type:      nvType,
			Size:      pub.DataSize,
			AuthRead:  pub.Attributes.AuthRead,
			AuthWrite: pub.Attributes.AuthWrite,
		})
	}

	return indexes, nil
}

func (tpm *TPM2) Info() (string, error) {
	caps, err := tpm.FixedProperties()
	if err != nil {
		return "", err
	}

	var sb strings.Builder

	sb.WriteString("TPM Information\n")
	fmt.Fprintf(&sb, "Manufacturer: %s\n", caps.Manufacturer)
	fmt.Fprintf(&sb, "Vendor ID:    %s\n", caps.VendorID)
	fmt.Fprintf(&sb, "Family:       %s\n", caps.Family)
	fmt.Fprintf(&sb, "Level:        %d\n", caps.Level)
	fmt.Fprintf(&sb, "Revision:     %s\n", caps.Revision)
	fmt.Fprintf(&sb, "Firmware:     %d.%d\n", caps.FwMajor, caps.FwMinor)
	fmt.Fprintf(&sb, "Memory:       %d\n", caps.PersistentLoaded)
	fmt.Fprintf(&sb, "Model:        %s\n", caps.Model)
	fmt.Fprintf(&sb, "FIPS 140-2:   %t\n", caps.Fips1402)
	sb.WriteString("\n")

	fmt.Fprintf(&sb, "Max Auth Failures: %d\n", caps.MaxAuthFail)
	fmt.Fprintf(&sb, "Loaded Curves:     %d\n", caps.LoadedCurves)
	fmt.Fprintf(&sb, "Max RSA Key Bits:  %d\n", caps.MaxRSAKeyBits)
	fmt.Fprintf(&sb, "Max ECC Key Bits:  %d\n", caps.MaxECCKeyBits)
	sb.WriteString("\n")

	if len(caps.SupportedAlgorithms) > 0 {
		fmt.Fprintf(&sb, "Supported Algorithms: %s\n", strings.Join(caps.SupportedAlgorithms, ", "))
		sb.WriteString("\n")
	}

	fmt.Fprintf(&sb, "Authorization Sessions Active:           %d\n", caps.AuthSessionsActive)
	fmt.Fprintf(&sb, "Authorization Sessions Active Available: %d\n", caps.AuthSessionsActiveAvail)

	fmt.Fprintf(&sb, "Authorization Sessions Used:             %d\n", caps.AuthSessionsLoaded)
	fmt.Fprintf(&sb, "Authorization Sessions Loaded Available: %d\n", caps.AuthSessionsLoadedAvail)

	fmt.Fprintf(&sb, "Lockout Counter:  %d\n", caps.LockoutCounter)
	fmt.Fprintf(&sb, "Lockout Interval: %d\n", caps.LockoutInterval)
	fmt.Fprintf(&sb, "Lockout Recovery: %d\n", caps.LockoutRecovery)

	fmt.Fprintf(&sb, "NV Buffer Max:      %d\n", caps.NVBufferMax)
	fmt.Fprintf(&sb, "NV Indexes Defined: %d\n", caps.NVIndexesDefined)
	fmt.Fprintf(&sb, "NV Indexes Max:     %d\n", caps.NVIndexesMax)
	fmt.Fprintf(&sb, "NV Write Recovery:  %d\n", caps.NVWriteRecovery)

	fmt.Fprintf(&sb, "Persistent Used:      %d\n", caps.PersistentLoaded)
	fmt.Fprintf(&sb, "Persistent Available: %d\n", caps.PersistentAvail)

	fmt.Fprintf(&sb, "Transient Min:       %d\n", caps.TransientMin)
	fmt.Fprintf(&sb, "Transient Available: %d\n", caps.TransientAvail)
	sb.WriteString("\n")

	return sb.String(), nil
}
