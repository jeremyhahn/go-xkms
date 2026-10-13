<!-- Copyright (c) 2025 Jeremy Hahn -->
<!-- Copyright (c) 2025 Automate The Things, LLC -->

# Setup Wizard and Unlock Flow

> **Status: REFERENCE** · Last verified: 2026-10-13
> Backend sequence of setup, startup unlock and app lock; the [setup-wizard](../setup-wizard/) feature folder is normative for setup.

This document describes the backend execution flow of the setup wizard, the returning user startup/unlock process, and the component architecture that ties them together.

## Setup Wizard Backend Execution (ApplySetup)

The `SetupWizardService.ApplySetup()` method executes 9 sequential steps (`setupTotalSteps`, `xkey/pkg/gui/services/setup_wizard_service.go:464`). Each step delegates to a dedicated service. Failures in non-critical steps are recorded as warnings; critical failures abort the wizard.

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
        S2C -->|No| S2E[Defer to Step 6]
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

    subgraph S5["Step 5: Initialize Barrier"]
        S5A{UseUserPinAsMaster?}
        S5A -->|Yes| S5B[barrierPassword = userPIN]
        S5A -->|No| S5C[Use explicit barrier password]
        S5B & S5C --> S5D[BarrierService.Initialize]
        S5D --> S5E{SealerBackend: chosen, else BestSealer, else passphrase}
        S5E -->|tpm2| S5F[TPM2 strategy — auto-unseal]
        S5E -->|passphrase| S5G[Passphrase strategy]
    end

    subgraph S6["Step 6: Initialize Data Directory"]
        S6A["Create ~/.xkey/data/"] --> S6B[initPINService — ResolvePINBackend picks the PIN strategy]
        S6B --> S6C[initializeAuthenticator — PINVerifier wired, already populated]
        S6C --> S6G[postDataDirStartup]
        S6G --> S6D{PIN deferred from Step 2?}
        S6D -->|Yes| S6E[Retry SetSOPIN + SetUserPIN]
        S6D -->|No| S6F[Skip]
    end

    subgraph S7["Step 7: Password Protection"]
        S7A{Mode?}
        S7A -->|aes_software| S7B[Argon2id key derivation]
        S7A -->|tpm_sealed| S7C[TPM sealed master key]
    end

    subgraph S8["Step 8: Auto-Unseal"]
        S8A[TPMPolicyService: create named policy auto-unseal over PCRs 0, 7, 9]
        S8A --> S8B[BarrierAutoUnsealService.EnableAutoUnseal: seal barrier password under it]
        S8B --> S8C[LUKS passphrase sealed under the built-in platform policy]
    end

    subgraph S9["Step 9: Save Config"]
        S9A[SetupComplete = true]
    end

    S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
    S9 --> DONE([Setup Complete])
```

### Step 4 Detail: Platform SRK Provisioning

The Platform SRK (at handle `0x81000002`) is the sole key used for PIN verification. The `ensureSRKAuth` method (`pkg/tpm2/platform_keystore.go:345`) handles the case where the SRK already exists from a prior installation:

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

If eviction fails because the TPM owner hierarchy has auth from a prior installation, `Initialize` returns `ErrPlatformKeyStoreEvictSRK` (`platform_keystore.go:77`) with a message directing the user to clear the TPM or provide the correct SO PIN. There is no fallback to the Shared SRK — the Platform SRK is the only key used for PIN management.

## Returning User Startup Flow

```mermaid
flowchart TD
    START([App Starts]) --> D1{Auto-unseal configured?}

    D1 -->|Yes| AU[BarrierAutoUnsealService.TryAutoUnseal]
    AU --> AUR{TPM releases the password under the auto-unseal policy?}
    AUR -->|Yes| AUTO([App Unlocked — no interaction])
    AUR -->|No| PROMPT

    D1 -->|No| D2{Barrier sealed?}
    D2 -->|Yes| PROMPT
    D2 -->|No| PROMPT2

    PROMPT[Unlock prompt] --> PIN1[User enters PIN]
    PIN1 --> UNSEAL[BarrierService.Unseal — PIN as password]
    UNSEAL --> HOOK[Post-unseal hook]
    HOOK --> IDD[initializeDataDir: initPINService, then initializeAuthenticator]
    IDD --> POST[postDataDirStartup: FIDO2 device, IPC, etc.]
    POST --> DONE1([App Unlocked])

    PROMPT2[Unlock prompt] --> PIN2[User enters PIN]
    PIN2 --> VERIFY[PINService.VerifyUserPIN]
    VERIFY -->|Success| DONE2([App Unlocked])
    VERIFY -->|Fail| ERR([ErrAuthFailed])
```

`initPINService` always runs inside `initializeDataDir`, immediately before
`initializeAuthenticator` — the authenticator publishes the `PINService` as
its `PINVerifier` the moment it is constructed, so the PIN backend must
already be populated by then, or a correct PIN presented to the FIDO2
authenticator during that window would be rejected (go-xkms#640).

The right-hand branch — barrier already unsealed, so verify through
`PINService` — is reached only by an installation that has no barrier at all.
An installation with a barrier is always sealed when the app is locked,
because locking seals it. See [App Lock and Inactivity](#app-lock-and-inactivity).

## App Lock and Inactivity

`AppLockService.Lock` seals the barrier, and every route into the lock goes
through it: the inactivity timer, the lock button, and the OS screen-lock
signal. A lock that only blanked the interface would leave the barrier's data
encryption key resident in the process, so it protected nothing against
anything with access to the machine.

Sealing on lock also settles which credential the lock screen checks. The
screen prompts for one secret and sends one value, while `Unlock` chooses its
verifier from the barrier's seal state: the barrier credential while the
barrier is sealed, the PIN service's credential once it is not. Those are two
independent credential stores whose values nothing binds together — a
`passphrase` barrier alongside a `tpm2` PIN strategy is two different secrets
— so a lock that left the barrier open sent the unlock to a verifier the user
was never prompted for. With the barrier sealed on every lock, each unlock
takes the same route the startup unlock takes.

This matters beyond the failed unlock. The `tpm2` PIN backend verifies against
the PlatformSRK's auth value, and every failed attempt spends one of the TPM's
dictionary-attack retries — three on typical hardware, after which the TPM
enters a lockout that blocks all SRK-auth operations until the recovery
interval elapses or `TPM2_DictionaryAttackLockReset` is run.

The app is locked whether or not the barrier could be sealed: refusing to lock
because the key could not be zeroed would leave the interface open, which is
worse. A seal failure is reported as `ErrAppLockBarrierSealFailed` rather than
being swallowed, so a lock weaker than it claims to be is visible.

Unlocking after an in-process lock reopens the existing barrier rather than
building a replacement. The post-unseal hook wires every barrier-backed store
once per process and hands each one a backend wrapping the live barrier; a
replacement would leave all of them bound to the sealed object with no route
back, so the app would unlock while every encrypted store stayed unreadable
until restart.

### PIN Verification Chain

```mermaid
flowchart TD
    A[AppLockService.Unlock] --> B[PINService.VerifyUserPIN]
    B --> C[qrdbsdk.PINService.VerifyUserPIN]
    C --> D{Backend type?}

    D -->|TPM2| E[pintpm2.TPM2Backend.VerifyUserPIN]
    E --> F[PlatformKeyStore.VerifyAuth]
    F --> G["tpm.VerifyAuth(srkHandle, pin)\nTPM2_Create as parent auth check"]
    G -->|Success| OK([Verified])
    G -->|Fail| FAIL([ErrAuthFailed])

    D -->|Software| H[go-qrdb software PIN backend]
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
        PS[qrdbsdk.PINService]
        SB[seal.Barrier]
        T2B[pintpm2.TPM2Backend]
        SWB[software PIN backend]
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
