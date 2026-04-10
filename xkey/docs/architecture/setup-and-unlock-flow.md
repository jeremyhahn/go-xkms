<!-- Copyright (c) 2025 Jeremy Hahn -->
<!-- Copyright (c) 2025 Automate The Things, LLC -->

# Setup Wizard and Unlock Flow

This document describes the backend execution flow of the setup wizard, the returning user startup/unlock process, and the component architecture that ties them together.

## Setup Wizard Backend Execution (ApplySetup)

The `SetupWizardService.ApplySetup()` method executes 10 sequential steps. Each step delegates to a dedicated service. Failures in non-critical steps are recorded as warnings; critical failures abort the wizard.

```mermaid
flowchart TD
    START([ApplySetup]) --> S1

    subgraph S1["Step 1: Create Encrypted Storage"]
        S1A{LUKS selected?}
        S1A -->|Yes| S1B[StorageService.CreateVolume]
        S1A -->|No| S1C[Skip]
    end

    subgraph S2["Step 2: Configure PINs"]
        S2A[PINService.SetSOPIN] --> S2B[PINService.SetUserPIN]
        S2B --> S2C{PINManager ready?}
        S2C -->|Yes| S2D[Apply immediately]
        S2C -->|No| S2E[Defer to Step 7]
    end

    subgraph S3["Step 3: Provision TPM Keys"]
        S3A[TPMService.Install] --> S3B[Create EK + Shared SRK + IAK + IDevID]
        S3B --> S3C{SetHierarchyAuth?}
        S3C -->|Yes| S3D[Set owner/endorsement/lockout auth]
        S3C -->|No| S3E[Skip hierarchy auth]
    end

    subgraph S4["Step 4: Initialize Platform Key Store"]
        S4A[TPMService.InitializePlatformKeyStore] --> S4B[Create Platform SRK with userPIN auth]
        S4B --> S4C{SRK already exists?}
        S4C -->|Yes| S4D[ensureSRKAuth: verify or evict+recreate]
        S4C -->|No| S4E[CreateSRK + SetUserPIN]
    end

    subgraph S5["Step 5: Apply Platform Policy"]
        S5A[PlatformPolicyService.CreatePolicy]
        S5A --> S5B["PCRs 0, 7, 9 / SHA-256"]
    end

    subgraph S6["Step 6: Initialize Barrier"]
        S6A{UseUserPinAsMaster?}
        S6A -->|Yes| S6B[barrierPassword = userPIN]
        S6A -->|No| S6C[Use explicit barrier password]
        S6B & S6C --> S6D[BarrierService.Initialize]
        S6D --> S6E{Best strategy}
        S6E -->|TPM2| S6F[TPM2 strategy — auto-unseal]
        S6E -->|Software| S6G[Software AES-256-GCM]
    end

    subgraph S7["Step 7: Initialize Data Directory"]
        S7A["Create ~/.xkey/data/"] --> S7B[postDataDirStartup]
        S7B --> S7C[initPINService — TPM2Backend or SoftwareBackend]
        S7C --> S7D{PIN deferred from Step 2?}
        S7D -->|Yes| S7E[Retry SetSOPIN + SetUserPIN]
        S7D -->|No| S7F[Skip]
    end

    subgraph S8["Step 8: Password Protection"]
        S8A{Mode?}
        S8A -->|aes_software| S8B[Argon2id key derivation]
        S8A -->|tpm_sealed| S8C[TPM sealed master key]
    end

    subgraph S9["Step 9: Auto-Unseal"]
        S9A[SealService.SealData with PolicyTypePlatformPolicy]
        S9A --> S9B[Seal barrier or LUKS password to TPM]
    end

    subgraph S10["Step 10: Save Config"]
        S10A[SetupComplete = true]
    end

    S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9 --> S10
    S10 --> DONE([Setup Complete])
```

### Step 4 Detail: Platform SRK Provisioning

The Platform SRK (at handle `0x81000002`) is the sole key used for PIN verification. The `ensureSRKAuth` method handles the case where the SRK already exists from a prior installation:

```mermaid
flowchart TD
    ENTRY([ensureSRKAuth]) --> V[VerifyAuth: does SRK auth match userPIN?]

    V -->|Yes| REG[SetUserPIN — register PIN in backend]
    REG --> OK([Success])

    V -->|No — auth mismatch| EVICT[DeleteKey: evict old SRK via EvictControl]
    EVICT -->|Success| CREATE[CreateSRK with userPIN as auth]
    CREATE --> REG2[SetUserPIN]
    REG2 --> OK

    EVICT -->|TPM_RC_BAD_AUTH| FAIL([ErrPlatformKeyStoreEvictSRK])
```

If eviction fails because the TPM owner hierarchy has auth from a prior installation, `Initialize` returns `ErrPlatformKeyStoreEvictSRK` with a message directing the user to clear the TPM or provide the correct SO PIN. There is no fallback to the Shared SRK — the Platform SRK is the only key used for PIN management.

## Returning User Startup Flow

```mermaid
flowchart TD
    START([App Starts]) --> D1{Auto-unseal configured?}

    D1 -->|Yes| AU[PasswordProtectionService.AutoUnlockTPM]
    AU --> AUR{PCR policy match?}
    AUR -->|Yes| AUTO([App Unlocked — no interaction])
    AUR -->|No| PROMPT

    D1 -->|No| D2{Barrier sealed?}
    D2 -->|Yes| PROMPT
    D2 -->|No| PROMPT2

    PROMPT[Unlock prompt] --> PIN1[User enters PIN]
    PIN1 --> UNSEAL[BarrierService.Unseal — PIN as password]
    UNSEAL --> HOOK[Post-unseal hook]
    HOOK --> POST[postDataDirStartup]
    POST --> INIT[Initialize PIN, FIDO2, IPC services]
    INIT --> DONE1([App Unlocked])

    PROMPT2[Unlock prompt] --> PIN2[User enters PIN]
    PIN2 --> VERIFY[PINService.VerifyUserPIN]
    VERIFY -->|Success| DONE2([App Unlocked])
    VERIFY -->|Fail| ERR([ErrAuthFailed])
```

### PIN Verification Chain

```mermaid
flowchart TD
    A[AppLockService.Unlock] --> B[PINService.VerifyUserPIN]
    B --> C[pin.Service.VerifyUserPIN]
    C --> D{Backend type?}

    D -->|TPM2| E[pin.TPM2Backend.VerifyUserPIN]
    E --> F[PlatformKeyStore.VerifyAuth]
    F --> G["tpm.VerifyAuth(srkHandle, pin)\nTPM2_Create as parent auth check"]
    G -->|Success| OK([Verified])
    G -->|Fail| FAIL([ErrAuthFailed])

    D -->|Software| H[pin.SoftwareBackend.VerifyUserPIN]
    H --> I[Argon2id hash comparison]
    I -->|Match| OK
    I -->|No match| FAIL
```

## Component Architecture

```mermaid
flowchart TB
    subgraph GUI["GUI / Service Layer"]
        SWS[SetupWizardService]
        ALS[AppLockService]
        PSG[PINService]
        BS[BarrierService]
        SS[SealService]
        TS[TPMService]
        PPS[PasswordProtectionService]
    end

    subgraph CORE["Core Layer"]
        PS[pin.Service]
        SB[seal.Barrier]
        T2B[pin.TPM2Backend]
        SWB[pin.SoftwareBackend]
    end

    subgraph TPM["TPM Layer"]
        PKS[PlatformKeyStore]
        TPMI["TPM2 Interface"]
    end

    subgraph HW["TPM Hardware"]
        EK["EK\n0x81010001"]
        SSRK["Shared SRK\n0x81000001\nauth=nil"]
        PSRK["Platform SRK\n0x81000002\nauth=userPIN"]
    end

    SWS & ALS & PSG --> PS
    SWS & BS --> SB
    SWS & TS --> PKS
    PSG --> T2B & SWB
    T2B --> PKS
    PKS --> TPMI
    TPMI --> EK & SSRK & PSRK
```

### TPM Handle Assignments

| Handle | Name | Auth | Purpose |
|--------|------|------|---------|
| `0x81010001` | Endorsement Key (EK) | Hierarchy-controlled | Platform identity, credential activation |
| `0x81000001` | Shared SRK (SSRK) | nil (empty) | TCG-standard parent for sealed objects (barrier, seal service) |
| `0x81000002` | Platform SRK | userPIN | PIN verification via password auth |

The Shared SRK is provisioned during `TPMService.Install()` and is used **only** as a parent key for sealed objects created by the barrier and seal services. The Platform SRK is provisioned during `TPMService.InitializePlatformKeyStore()` and is the sole key used for PIN verification. These two keys serve distinct purposes and must not be conflated.
