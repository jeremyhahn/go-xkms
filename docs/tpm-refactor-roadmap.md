# TPM2 Package Refactoring Roadmap

## Phase 1A: Move Generic Private Functions (COMPLETED)

Moved 5 generic private functions out of `cert_idevid.go` to their proper homes:
- `bytesToUint32`, `parseNVIndex`, `uint32ToBytes` -> `nvram.go`
- `parseOID`, `parseRDNSequence` -> `cert_convert.go`

## Phase 1B: Rename Certificate Methods (COMPLETED)

Renamed methods to match EK naming convention across 16 files:
- `ReadIDevIDCertificate` -> `IDevIDCertificate`
- `WriteIDevIDCertificate` -> `ProvisionIDevIDCert`
- `ReadIAKCertificate` -> `IAKCertificate`
- `WriteIAKCertificate` -> `ProvisionIAKCert`
- `ReadEKCertificate` -> `EKCertificate`

## Phase 1C: Test File Consolidation (COMPLETED)

### Goal
Consolidate test files to follow 1:1 source-to-test mapping. Started at ~72 test files, target ~38.

### Final State
- 29 test files, 36 source files
- 27 paired source-test files
- 2 intentional orphans kept separate (`idevid_csr_simulator_test.go`, `idevid_csr_verify_integration_test.go`) due to `//go:build tpm_simulator` tag

### Consolidation Summary

| Orphan File | Merged Into | Status |
|---|---|---|
| `base_test.go` | `tpm_test.go` | Merged + deleted |
| `coverage_simulator_test.go` | `tpm_simulator_test.go` | Merged + deleted |
| `coverage_tcg_csr_test.go` | `tpm_simulator_test.go` | Merged + deleted |
| `csr_test.go` | `idevid_csr_test.go` | Merged + deleted |
| `csrunit_test.go` | `idevid_csr_test.go` | Merged + deleted |
| `data_structures_test.go` | `types_test.go` | Merged + deleted |
| `idevid_csr_coverage_test.go` | `idevid_csr_test.go` | Merged + deleted |
| `idevid_csr_serialization_test.go` | `idevid_csr_test.go` | Merged + deleted |
| `idevid_csr_simulator_test.go` | Kept separate | `tpm_simulator` build tag |
| `idevid_csr_unit_test.go` | `idevid_csr_test.go` | Merged + deleted |
| `idevid_csr_verify_extended_test.go` | `idevid_csr_test.go` | Merged + deleted |
| `idevid_csr_verify_integration_test.go` | Kept separate | `tpm_simulator` build tag |
| `mock_tpm_test.go` | `tpm_test.go` | Merged + deleted |
| `priority_coverage_test.go` | Various (idevid_csr, tcg_csr_serverside, key, types, ecdsa, config) | Distributed + deleted |
| `test_common_test.go` | `tpm_test.go` | Merged + deleted |
| `zero_coverage_test.go` | `tpm_simulator_test.go` | Merged + deleted |

---

## Wave 2: PCR Policy Comparison + Event Log Replay

### Phase 2A: ReplayEventLog Method

**File**: `xkey/pkg/gui/services/tpm_service.go`

Add `ReplayEventLog()` method that:
1. Calls `tpmAccessor.ParsedEventLog()` to get events
2. Calls `tpm2.CalculatePCRs(events)` to compute expected PCR values
3. Calls `tpmAccessor.ReadPCRs()` to get actual PCR values
4. Compares computed vs actual, accounting for algorithm name case mismatch:
   - `CalculatePCRs` returns lowercase: "sha256"
   - `ReadPCRs` returns uppercase: "SHA256"
   - Use `strings.EqualFold` for comparison
5. Returns structured result with match/mismatch details

**Return type**:
```go
type EventLogReplayResult struct {
    Matched    bool                    `json:"matched"`
    Banks      []EventLogBankResult    `json:"banks"`
    EventCount int                     `json:"event_count"`
    Error      string                  `json:"error,omitempty"`
}

type EventLogBankResult struct {
    Algorithm string                  `json:"algorithm"`
    PCRs      []EventLogPCRResult     `json:"pcrs"`
    AllMatch  bool                    `json:"all_match"`
}

type EventLogPCRResult struct {
    Index    int    `json:"index"`
    Expected string `json:"expected"`
    Actual   string `json:"actual"`
    Match    bool   `json:"match"`
}
```

### Phase 2B: ComparePolicyPCRs Method

**File**: `xkey/pkg/gui/services/tpm_service.go`

Add `ComparePolicyPCRs(policyName string)` method that:
1. Loads saved PCR policy by name
2. Reads current PCR values via `readPCRDigests`
3. Compares saved digests against current values
4. Returns structured comparison result

Also enhance `RefreshPolicyPCRs` to return comparison results before overwriting.

**Return type**:
```go
type PolicyComparisonResult struct {
    PolicyName string                  `json:"policy_name"`
    Matched    bool                    `json:"matched"`
    Digests    []DigestComparison      `json:"digests"`
    Timestamp  string                  `json:"timestamp"`
}

type DigestComparison struct {
    Bank     string `json:"bank"`
    Index    int    `json:"index"`
    Saved    string `json:"saved"`
    Current  string `json:"current"`
    Match    bool   `json:"match"`
}
```

### Phase 2C: EventLogViewer.svelte Frontend

**File**: `xkey/frontend/src/lib/components/EventLogViewer.svelte`

Add replay verification panel:
- "Verify Event Log" button that calls `ReplayEventLog`
- Display PCR comparison results per bank
- Color-coded match/mismatch indicators

### Phase 2D: TPM.svelte Policy Section

**File**: `xkey/frontend/src/views/TPM.svelte`

Add policy comparison UI:
- "Compare Policy" button next to each saved policy
- Display comparison results inline
- Show drift warnings for mismatches

### Phase 2E: Tests

**File**: `xkey/pkg/gui/services/tpm_service_test.go`

Tests for:
- `TestReplayEventLog_Success` - matching PCRs
- `TestReplayEventLog_Mismatch` - divergent PCR values
- `TestReplayEventLog_NoTPM` - TPM not available
- `TestReplayEventLog_NoEventLog` - event log not found
- `TestComparePolicyPCRs_Success` - policy matches current state
- `TestComparePolicyPCRs_Drift` - policy differs from current
- `TestComparePolicyPCRs_PolicyNotFound` - invalid policy name
- `TestComparePolicyPCRs_NoTPM` - TPM not available

### Key Technical Notes

- `ReadPCRs` returns `Algorithm` as uppercase ("SHA256"), `CalculatePCRs` uses lowercase ("sha256")
- `readPCRDigests` already handles this with `strings.EqualFold`
- `PCRDigests` map uses "bank:index" -> hex digest format
- `mockTPM` has `parsedEvents`/`parsedEventsErr` and `pcrBanks`/`pcrBanksErr` fields for testing
- `validPCRBanks` map at line 86: "sha1", "sha256", "sha384", "sha512"
