package tpm2

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Clears the TPM as described in TCG Part 3: Commands - Section 24.6 - TPM2_Clear
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
// This command clears Owner, Endorsement, and Lockout hierarchy auth values.
// Authorization must be provided using either the Lockout or Platform hierarchy.
// A successful clear drops the cached hierarchy attributes (see
// dropHierarchyCache); a refused one leaves them, since the TPM is unchanged.
func (tpm *TPM2) Clear(lockoutAuth []byte) error {
	err := tpm.withHierarchyAuth(tpm2.TPMRHLockout, lockoutAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		_, err := tpm2.Clear{AuthHandle: authHandle}.Execute(tpm.transport)
		return err
	})
	if err != nil {
		return err
	}
	tpm.dropHierarchyCache()
	return nil
}

// dropHierarchyCache drops every cached value that describes an object under
// the Owner or Endorsement hierarchy: the EK, IAK, IDevID, LAK, SSRK and
// Platform SRK attributes and the EK public keys. TPM2_Clear (TCG TPM 2.0
// Part 3, section 24.6) flushes those hierarchies' objects and resets their
// authorizations, so each accessor re-derives its value on the next call.
func (tpm *TPM2) dropHierarchyCache() {
	tpm.ekAttrs = nil
	tpm.ekECCPubKey = nil
	tpm.ekRSAPubKey = nil
	tpm.iakAttrs = nil
	tpm.idevidAttrs = nil
	tpm.lakAttrs = nil
	tpm.platformSRKAttrs = nil
	tpm.ssrkAttrs = nil
}

// ppiRequestWriter is the seam through which ForceClear performs its single
// sysfs write. Production leaves it at its default (os.WriteFile); tests
// substitute a func that records the call without touching the host --
// CI runs the test suite as root, so a permission-bit trick can't stand in
// for "the write did not happen" the way it would for an unprivileged user.
var ppiRequestWriter = os.WriteFile

// ForceClear schedules a TPM clear via the UEFI Physical Presence Interface (PPI).
// This bypasses Dictionary Attack lockout because the clear is performed by the
// firmware during POST with physical presence assertion. The system must be
// rebooted for the clear to take effect.
// PPI request code 5 = "Clear" per TCG Physical Presence Interface Specification.
func (tpm *TPM2) ForceClear() error {
	deviceName := filepath.Base(tpm.config.Device)
	// Map tpmrm0 -> tpm0 for sysfs PPI access
	if deviceName == "tpmrm0" {
		deviceName = "tpm0"
	}
	ppiPath := fmt.Sprintf("/sys/class/tpm/%s/ppi/request", deviceName)

	if err := ppiRequestWriter(ppiPath, []byte("5"), 0644); err != nil { // #nosec G306 - existing sysfs node, not a created file
		return &errs.Detail{Err: ErrForceClear, Detail: fmt.Sprintf("%v", err)}
	}

	tpm.logger.Info("TPM clear scheduled via UEFI Physical Presence Interface",
		slog.String("ppi_path", ppiPath),
		slog.String("request_code", "5"))

	return nil
}

// clearViaPlatform performs TPM2_Clear authorized by the PLATFORM hierarchy
// with empty auth. TPM2_Clear accepts LOCKOUT or PLATFORM authorization
// (TCG TPM 2.0 Part 3, section 24.6); the PLATFORM path succeeds only when
// firmware has left the platform hierarchy's auth empty at the point this
// runs -- true on U-Boot and Raspberry Pi UEFI, neither of which implements
// the PPI ClearForReprovision falls back to -- and refused by firmware that
// locks the platform hierarchy during POST. A successful clear drops the
// cached hierarchy attributes, as Clear does.
func (tpm *TPM2) clearViaPlatform() error {
	_, err := tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHPlatform,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}
	tpm.dropHierarchyCache()
	return nil
}

// ClearForReprovision returns the TPM to factory-fresh hierarchy state so a
// new provisioning pass can start clean. It tries three paths in order and
// stops at the first that succeeds:
//
//  1. TPM2_Clear via the LOCKOUT hierarchy with empty auth (Clear). This is
//     immediate and succeeds whenever lockout auth is still empty -- the
//     common case for a TPM that was never fully provisioned, or whose
//     provisioning failed before SetHierarchyAuth ran.
//  2. TPM2_Clear via the PLATFORM hierarchy with empty auth (clearViaPlatform),
//     when firmware leaves it open (U-Boot, Raspberry Pi UEFI; neither
//     implements the PPI). Also immediate.
//  3. The UEFI Physical Presence Interface ForceClear request, which
//     firmware services during the next POST with physical presence
//     asserted. rebootRequired is true only for this path.
//
// Each refused path is logged with its own typed error (ErrClearLockoutRefused,
// ErrClearPlatformRefused) so the reason the next path was attempted is
// visible; if ForceClear itself fails, its own error is returned directly,
// since it is the last path attempted.
func (tpm *TPM2) ClearForReprovision() (rebootRequired bool, err error) {
	lockoutErr := tpm.Clear(nil)
	if lockoutErr == nil {
		tpm.logger.Info("tpm: cleared for reprovisioning via LOCKOUT hierarchy")
		return false, nil
	}
	tpm.logger.Debug("tpm: TPM2_Clear via LOCKOUT hierarchy refused, trying PLATFORM hierarchy",
		slog.String("error", (&errs.Detail{Err: ErrClearLockoutRefused, Detail: lockoutErr.Error()}).Error()))

	platformErr := tpm.clearViaPlatform()
	if platformErr == nil {
		tpm.logger.Info("tpm: cleared for reprovisioning via PLATFORM hierarchy")
		return false, nil
	}
	tpm.logger.Debug("tpm: TPM2_Clear via PLATFORM hierarchy refused, scheduling ForceClear via PPI",
		slog.String("error", (&errs.Detail{Err: ErrClearPlatformRefused, Detail: platformErr.Error()}).Error()))

	if forceErr := tpm.ForceClear(); forceErr != nil {
		return false, forceErr
	}
	tpm.logger.Info("tpm: TPM clear scheduled via PPI; a reboot is required for it to take effect")
	return true, nil
}

// FactoryReset returns the TPM to a manufacturer-like state by evicting all
// provisioned persistent handles (SRK, IAK, IDevID) and undefining their
// associated NV indexes (certificates, policy indices). The manufacturer
// Endorsement Key (EK) at handle 0x81010001 is preserved. This operation
// requires Owner hierarchy authorization.
//
// FactoryReset DOES NOT call TPM2_Clear. TPM2_Clear is destructive (it
// resets owner/endorsement/lockout auths AND wipes all persistent objects
// in those hierarchies) and must be an explicit operator opt-in, not a
// silent side effect of a method named "FactoryReset". For the destructive
// pre-pass-then-evict workflow needed when the previous run set an
// unknown owner auth, use FactoryResetWithClear which is gated behind a
// caller-supplied opt-in.
//
// The reset is best-effort: each handle and NV index is processed
// independently, and the first error encountered is returned after all
// operations complete.
func (tpm *TPM2) FactoryReset(ownerAuth []byte) error {
	return tpm.factoryResetInternal(ownerAuth, false)
}

// FactoryResetWithClear is FactoryReset preceded by a TPM2_Clear via the
// LOCKOUT hierarchy with EMPTY auth. This is the destructive recovery
// path for the case where a previous failed provisioning run set the
// OWNER hierarchy auth to a value that the current process doesn't know.
//
// TPM2_Clear is authorized via the LOCKOUT or PLATFORM hierarchy. On most
// fresh TPMs and TPMs after platform reset, LOCKOUT auth is still empty
// even when OWNER auth has been set by previous code. TPM2_Clear with
// empty lockout resets ALL three hierarchy auths (Owner, Endorsement,
// Lockout) to empty AND wipes all persistent objects in those hierarchies
// in one shot. Manufacturer EK certificates in the Platform hierarchy are
// preserved.
//
// **Callers MUST treat this as a destructive operation.** Do NOT call
// FactoryResetWithClear unconditionally — it must be gated behind an
// explicit operator opt-in (a config flag, an interactive confirmation,
// or both). The trusted-platform reference templates default this to true
// during initial install, but the Go library default is OFF and the
// firstboot strategy reads the flag from the operator-supplied installer
// config before invoking it.
//
// If the lockout auth is also set, the Clear pre-pass fails and we fall
// through to the regular EvictControl pass, which then succeeds or fails
// per the supplied ownerAuth — exactly as plain FactoryReset would.
func (tpm *TPM2) FactoryResetWithClear(ownerAuth []byte) error {
	return tpm.factoryResetInternal(ownerAuth, true)
}

// factoryResetInternal is the shared implementation. attemptClear gates
// the destructive TPM2_Clear pre-pass.
// ownedPersistentHandles returns the persistent handles this package's own
// configuration places keys at: the IAK, IDevID and Platform SRK. Unset
// handles are omitted.
func (tpm *TPM2) ownedPersistentHandles() []tpm2.TPMHandle {
	var owned []tpm2.TPMHandle
	add := func(h uint32) {
		if h != 0 {
			owned = append(owned, tpm2.TPMHandle(h))
		}
	}
	if tpm.config.IAK != nil {
		add(tpm.config.IAK.Handle)
	}
	if tpm.config.IDevID != nil {
		add(tpm.config.IDevID.Handle)
	}
	if tpm.config.PlatformSRK != nil {
		add(tpm.config.PlatformSRK.SRKHandle)
	}
	return owned
}

func (tpm *TPM2) factoryResetInternal(ownerAuth []byte, attemptClear bool) error {

	tpm.logger.Info("Factory resetting TPM to manufacturer state",
		slog.Bool("attempt_clear", attemptClear))
	tpm.logger.Info("Preserving all EK keys and certificates per TCG specifications")

	if attemptClear {
		// PRE-PASS: TPM2_Clear via empty lockout. Best-effort. Caller
		// has explicitly opted into the destructive recovery path.
		tpm.logger.Info("FactoryResetWithClear: attempting TPM2_Clear via empty lockout hierarchy (DESTRUCTIVE — caller opted in)")
		if clearErr := tpm.Clear(nil); clearErr != nil {
			tpm.logger.Warn("TPM2_Clear via empty lockout failed (continuing with EvictControl pass)",
				slog.String("error", clearErr.Error()))
		} else {
			tpm.logger.Info("TPM2_Clear via empty lockout succeeded — owner/endorsement/lockout auths reset")
			// After a successful Clear, ownerAuth is empty. Override the
			// caller-supplied ownerAuth so the eviction loop below doesn't
			// keep trying a stale value.
			ownerAuth = nil
		}
	}

	var firstErr error

	// Manufacturer-provisioned EKs must be preserved: they are the persistent
	// objects FactoryReset did not create and cannot recreate, and the TPM
	// provisioning rules keep EKs untouched. TCG reserves 0x81010001 for the
	// RSA EK and 0x81010002 for the ECC EK (TCG TPM 2.0 Provisioning Guidance,
	// Section 7.8, Table 2), and the configured EK handle is preserved too.
	//
	// This package's default IAK handle is also 0x81010002 (IAKConfig.Handle),
	// so a TCG address is released for eviction only when it is one of the
	// handles this package's own configuration places a key at: the IAK,
	// IDevID or Platform SRK. A foreign object at a TCG EK address -- a
	// manufacturer ECC EK beside a configured RSA EK -- stays (go-xkms#798).
	preserveHandles := map[tpm2.TPMHandle]bool{
		0x81010001: true, // TCG EK RSA
		0x81010002: true, // TCG EK ECC
	}
	for _, owned := range tpm.ownedPersistentHandles() {
		delete(preserveHandles, owned)
	}
	if tpm.config.EK != nil && tpm.config.EK.Handle != 0 {
		preserveHandles[tpm2.TPMHandle(tpm.config.EK.Handle)] = true
	}

	// TCG-standard EK certificate NV indices that MUST be preserved.
	// These contain the manufacturer's EK certificates and are critical
	// for device identity and attestation.
	preserveNVIndices := map[tpm2.TPMHandle]bool{
		0x01C00002: true, // EK RSA 2048 certificate
		0x01C0000A: true, // EK ECC P-256 certificate
		0x01C00016: true, // EK ECC P-384 certificate
		0x01C00018: true, // EK ECC P-521 certificate
		0x01C00001: true, // Endorsement hierarchy certificate (platform manufacturer)
	}

	// 1. Enumerate ALL persistent handles and evict everything except EKs
	handles, err := persistentHandles(tpm.transport)
	if err != nil {
		tpm.logger.Warn("Failed to enumerate persistent handles", slog.String("error", err.Error()))
	} else {
		for _, handle := range handles {
			if preserveHandles[handle] {
				tpm.logger.Info("Preserving EK handle",
					slog.String("handle", fmt.Sprintf("0x%08X", handle)))
				continue
			}

			name, _, err := tpm.ReadHandle(handle)
			if err != nil {
				tpm.logger.Debug("Cannot read handle, skipping",
					slog.String("handle", fmt.Sprintf("0x%08X", handle)))
				continue
			}

			err = tpm.evictControl(tpm2.TPMRHOwner, ownerAuth, tpm2.NamedHandle{
				Handle: handle,
				Name:   name,
			}, handle)
			if err != nil {
				tpm.logger.Error("Failed to evict handle",
					slog.String("handle", fmt.Sprintf("0x%08X", handle)),
					slog.String("error", err.Error()))
				if firstErr == nil {
					firstErr = &errs.Detail{Err: ErrFactoryReset, Detail: fmt.Sprintf("evict handle 0x%08X: %v", handle, err)}
				}
			} else {
				tpm.logger.Info("Evicted persistent handle",
					slog.String("handle", fmt.Sprintf("0x%08X", handle)))
			}
		}
	}

	// 2. Undefine platform-provisioned NV indexes, preserving all EK certificates.
	// Only undefine NV indices that were created by the platform (IDevID, IAK),
	// NEVER touch manufacturer EK certificate indices.
	platformNVIndices := []tpm2.TPMHandle{
		tpm2.TPMHandle(iakCert),       // 0x01C90001
		tpm2.TPMHandle(idevIDCert),    // 0x01C90000
		tpm2.TPMHandle(idevIDNVIndex), // 0x01C90020
		tpm2.TPMHandle(iakNVIndex),    // 0x01C90021
	}

	for _, nvIndex := range platformNVIndices {
		if preserveNVIndices[nvIndex] {
			tpm.logger.Info("Preserving EK certificate NV index",
				slog.String("index", fmt.Sprintf("0x%08X", nvIndex)))
			continue
		}

		readPubRsp, err := tpm2.NVReadPublic{
			NVIndex: nvIndex,
		}.Execute(tpm.transport)
		if err != nil {
			continue // NV index doesn't exist, skip
		}

		err = tpm.withHierarchyAuth(tpm2.TPMRHOwner, ownerAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
			_, err := tpm2.NVUndefineSpace{
				AuthHandle: authHandle,
				NVIndex: tpm2.NamedHandle{
					Handle: nvIndex,
					Name:   readPubRsp.NVName,
				},
			}.Execute(tpm.transport)
			return err
		})
		if err != nil {
			tpm.logger.Error("Failed to undefine NV index",
				slog.String("index", fmt.Sprintf("0x%08X", nvIndex)),
				slog.String("error", err.Error()))
			if firstErr == nil {
				firstErr = &errs.Detail{Err: ErrFactoryReset, Detail: fmt.Sprintf("undefine NV 0x%08X: %v", nvIndex, err)}
			}
		} else {
			tpm.logger.Info("Undefined NV index",
				slog.String("index", fmt.Sprintf("0x%08X", nvIndex)))
		}
	}

	// 4. Clear cached attributes
	tpm.dropHierarchyCache()

	return firstErr
}

// InstallOptions controls which provisioning steps Install() performs.
// When nil is passed to Install(), DefaultInstallOptions() is used.
type InstallOptions struct {
	EK             bool // Ensure EK exists at configured handle
	SSRK           bool // Ensure SSRK exists at configured handle
	PlatformPolicy bool // Compute the platform policy over the platform PCR set
	IAK            bool // Ensure IAK exists
	IDevID         bool // Ensure IDevID exists
}

// DefaultInstallOptions returns options that provision everything.
func DefaultInstallOptions() *InstallOptions {
	return &InstallOptions{
		EK:             true,
		SSRK:           true,
		PlatformPolicy: true,
		IAK:            true,
		IDevID:         true,
	}
}

// MinimalInstallOptions returns options for TCG minimum provisioning (EK + SSRK only).
// Use this for early boot (firstboot/LUKS sealing) when PCR values aren't stable yet.
func MinimalInstallOptions() *InstallOptions {
	return &InstallOptions{
		EK:   true,
		SSRK: true,
	}
}

// Install performs a safe, modified version of the TCG recommended provisioning
// guidance intended for platforms that have already been minimally provisioned
// by the TPM Manufacturer or Owner. Instead of clearing the hierarchies,
// setting hierarchy authorizations and provisioning new keys and certificates
// from scratch, this method will use pre-existing EK and SRK keys and
// certificates if they already exist. The provided soPIN parameter is used
// as the new Endorsement and Storage hierarchy authorizations during installation.
// If the config's EK.HierarchyAuth is set, it is used as the current authorization;
// otherwise, empty auth is assumed for fresh TPMs. This allows Install to work
// on both fresh TPMs and already-provisioned TPMs.
// When opts is nil, DefaultInstallOptions() is used, provisioning everything.
func (tpm *TPM2) Install(soPIN types.Password, opts *InstallOptions) error {

	if tpm.transport == nil {
		return ErrInstallTransportNotInitialized
	}

	if opts == nil {
		opts = DefaultInstallOptions()
	}

	tpm.logger.Info("Installing Platform")

	// Only change hierarchy authorizations when an SO PIN is provided.
	// When soPIN is nil, skip auth changes and just provision keys using
	// the existing (possibly empty) hierarchy auth.
	if soPIN != nil {
		// Backup existing EK certificates before hierarchy auth changes
		tpm.BackupEKCertificates()

		// Use the config's HierarchyAuth as the current auth if set,
		// otherwise assume empty auth for fresh TPMs.
		var currentAuth types.Password
		if tpm.config.EK != nil {
			hierarchyAuthBytes, err := types.SecretValueBytes(context.Background(), tpm.config.EK.HierarchyAuth)
			if err != nil {
				return err
			}
			// store.NewPassword copies into its own enclave and leaves the
			// source alone.
			defer secure.Wipe(hierarchyAuthBytes)
			if len(hierarchyAuthBytes) > 0 {
				auth, err := store.NewPassword(hierarchyAuthBytes)
				secure.Wipe(hierarchyAuthBytes)
				if err != nil {
					return err
				}
				// SetHierarchyAuth only reads the current auth, so its
				// enclave is released once provisioning returns.
				defer auth.Clear()
				currentAuth = auth
			}
		}

		if err := tpm.SetHierarchyAuth(currentAuth, soPIN, nil); err != nil {
			return err
		}
	}

	// Create EK if it doesnt exist
	if opts.EK {
		ekAttrs, err := tpm.EKAttributes()
		if err != nil {
			if errors.Is(err, tpmRCHandle) {
				// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
				tpm.logger.Info("Creating Endorsement Key")
				policyDigest, pdErr := tpm.PlatformPolicyDigest()
				if pdErr != nil {
					return pdErr
				}
				ekAttrs, err = EKAttributesFromConfig(*tpm.config.EK, &policyDigest, tpm.config.IDevID)
				if err != nil {
					return err
				}
				replaceHierarchyAuth(ekAttrs, soPIN)
				if err := tpm.CreateEK(ekAttrs); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			replaceHierarchyAuth(ekAttrs, soPIN)
		}
	}

	// Create SSRK if it doesnt exist
	if opts.SSRK {
		var ssrkAttrs *types.KeyAttributes
		ekAttrs, ekErr := tpm.EKAttributes()
		if ekErr != nil {
			return ekErr
		}
		replaceHierarchyAuth(ekAttrs, soPIN)
		_, err := tpm.SSRKAttributes()
		if err != nil {
			if errors.Is(err, tpmRCHandle) {
				tpm.logger.Info("Creating Shared SRK")
				// No platform policy digest is read here: the Shared SRK never
				// carries one. The policy this SRK would have been given is
				// created below, by CreatePlatformPolicy, so it could only ever
				// have described a PCR state that this key outlives.
				ssrkAttrs, err = SRKAttributesFromConfig(*tpm.config.SSRK)
				if err != nil {
					return err
				}
				ssrkAttrs.Parent = ekAttrs
				emptyAuth, authErr := store.NewPassword(nil)
				if authErr != nil {
					return authErr
				}
				ssrkAttrs.Password = emptyAuth
				replaceHierarchyAuth(ssrkAttrs, soPIN)
				if err := tpm.CreateSRK(ssrkAttrs); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	// Capture platform measurements and create the policy digest
	if opts.PlatformPolicy {
		if err := tpm.CreatePlatformPolicy(); err != nil {
			return err
		}
	}

	// Create IAK if it doesnt exist
	if opts.IAK {
		ekAttrs, ekErr := tpm.EKAttributes()
		if ekErr != nil {
			return ekErr
		}
		replaceHierarchyAuth(ekAttrs, soPIN)
		if err := tpm.installIAK(ekAttrs); err != nil {
			return err
		}
	}

	// Create IDevID if it doesnt exist and is configured
	if opts.IDevID && tpm.config.IDevID != nil {
		if err := tpm.installIDevID(); err != nil {
			return err
		}
	}

	// Retrieve the EK certificate or log warning if not available
	if opts.EK {
		if _, err := tpm.EKCertificate(); err != nil {
			tpm.logger.Warn("EK certificate not available", slog.String("error", err.Error()))
		}
	}

	// Platform is provisioned
	return nil
}

// tpmRCHandle is TPM_RC_HANDLE for handle 1: the handle is not correct for
// the use. Reading the public area of an unpopulated persistent handle answers
// with it, so on the provisioning path it means "absent, create it".
const tpmRCHandle = tpm2.TPMRC(0x18b)

// installIAK ensures the Initial Attestation Key exists at its persistent
// handle, creating it when the TPM reports the handle empty (TCG "TPM 2.0 Keys
// for Device Identity and Attestation" v1.00 r12, section 6.1.2 step 1).
//
// The ceremony either completes or the device has no identity: any lookup
// answer other than TPM_RC_HANDLE, and any creation failure, is returned as a
// typed error and provisioning stops.
func (tpm *TPM2) installIAK(ekAttrs *types.KeyAttributes) error {
	if _, err := tpm.IAKAttributes(); err == nil {
		return nil
	} else if !errors.Is(err, tpmRCHandle) {
		return &errs.Joined{Lead: ErrDevIDProvisionLookup, Detail: "IAK", Cause: err}
	}
	tpm.logger.Info("Creating Initial Attestation Key")
	if _, err := tpm.CreateIAK(ekAttrs, nil); err != nil {
		return &errs.Joined{Lead: ErrDevIDProvisionIAK, Cause: err}
	}
	return nil
}

// installIDevID ensures the Initial Device Identity key exists at its
// persistent handle, creating it when the TPM reports the handle empty
// (section 6.2.2 step 2).
//
// The EK certificate is mandatory: the TCG-CSR-IDEVID carries it (section
// 6.2.2 step 4b) and the CA verifies it before issuing (step 6b). A platform
// without one cannot complete the ceremony, so provisioning refuses with
// ErrDevIDProvisionEKCert rather than minting a key it can never enroll --
// previously the certificate lookup error was discarded and a failed IDevID
// creation was logged and skipped, leaving the device without an identity
// while Install reported success.
func (tpm *TPM2) installIDevID() error {
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return &errs.Joined{Lead: ErrDevIDProvisionLookup, Detail: "IAK", Cause: err}
	}
	if _, err := tpm.IDevIDAttributes(); err == nil {
		return nil
	} else if !errors.Is(err, tpmRCHandle) {
		return &errs.Joined{Lead: ErrDevIDProvisionLookup, Detail: "IDevID", Cause: err}
	}
	tpm.logger.Info("Creating Initial Device Identity Key")
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		return &errs.Joined{Lead: ErrDevIDProvisionEKCert, Cause: err}
	}
	if _, _, err := tpm.CreateIDevID(iakAttrs, ekCert, nil); err != nil {
		return &errs.Joined{Lead: ErrDevIDProvisionIDevID, Cause: err}
	}
	return nil
}

// Provision the TPM as outlined in the TCG Provisioning Guidance -
// Section 11.1 - Provisioning the TPM.
// - Clear the TPM
// - Set Endorsement, Owner and Lockout authorizations
// - Create, verify & persist EK
// - Create, verify & persist IDevID
// - Create Initial Device Identity for touch-free provisioning
// - Create, & persist Shared SRK
// - Establish baseline PCRs
// - Capture Golden Integrity Measurements
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
//
// This operation requires hierarchy authorization to perform the TPM2_Clear
// command as the first step outlined in the TCG Provisioning Guidance, and
// assumes the auth parameter for these hierarchies to be set to an empty store.
// The TPM2_ChangeAuth command may be used prior to invoking this operation to set
// the hierarchy passwords to an empty value so this operation may complete.
// After this operation clears the TPM, the provided Security Officer PIN is used
// to set new Lockout, Endorsement and Owner authorization values. When this
// operation completes, the Lockout, Endorsement and Owner hierarchies are all
// owned by the Security Officer, the TPM is fully provisioned and ready for use.
// The hierarchy authorization values assigned during this operation may be safely
// modified to use authorization passwords and/or policies to align the platform
// with Enterprise or Platform Administrator requirements following this provisioning
// process.
func (tpm *TPM2) Provision(soPIN types.Password) error {

	tpm.logger.Info("Provisioning New Platform")

	tpm.logger.Info("Clearing TPM hierarchies")
	// Clear all hierarchies using lockout authorization
	// TPM2_Clear clears Owner, Endorsement, and Lockout hierarchy auth values
	if err := tpm.Clear(nil); err != nil {
		tpm.logger.Warn("tpm: failed to clear TPM hierarchies")
		tpm.logger.Error("tpm clear failed", slog.String("error", err.Error()))
		// When the clear fails because the TPM is in DA lockout (prior
		// install left hierarchy auth set + accumulated bad-auth counter),
		// neither TPM2_Clear nor TPM2_HierarchyChangeAuth can recover
		// locally. Schedule a UEFI PPI ForceClear and reboot — firmware
		// runs the clear during POST with physical presence asserted,
		// bypassing DA. If the caller has already set up the PPI path
		// and rebooted once, we won't land here a second time because
		// the TPM will be clean. Returning the original error lets the
		// caller's downstream provisioning see a clean failure instead
		// of a cryptic TPM_RC_LOCKOUT later during SetHierarchyAuth.
		errStr := err.Error()
		if strings.Contains(errStr, "TPM_RC_LOCKOUT") || strings.Contains(errStr, "TPM_RC_AUTH_FAIL") {
			tpm.logger.Warn("tpm: clear blocked by DA lockout — scheduling UEFI PPI ForceClear and rebooting",
				slog.String("original_error", errStr))
			if fcErr := tpm.ForceClear(); fcErr != nil {
				tpm.logger.Error("tpm: PPI ForceClear failed", slog.String("error", fcErr.Error()))
				return err
			}
			tpm.logger.Warn("tpm: PPI ForceClear scheduled — issuing warm reset via SysRq-b so firmware services the clear at next POST")
			hardResetViaSysRq(tpm.logger)
			return err
		}
		// Non-lockout clear failure: continue anyway, the TPM might
		// already be in the expected state.
	}

	tpm.logger.Info("Setting new Lockout, Endorsement and Owner Hierarchy Authorizations")
	lockoutHierarchy := tpm2.TPMRHLockout
	err := tpm.SetHierarchyAuth(nil, soPIN, &lockoutHierarchy)
	if err != nil {
		return err
	}
	endorsementHierarchy := tpm2.TPMRHEndorsement
	err = tpm.SetHierarchyAuth(nil, soPIN, &endorsementHierarchy)
	if err != nil {
		return err
	}
	ownerHierarchy := tpm2.TPMRHOwner
	err = tpm.SetHierarchyAuth(nil, soPIN, &ownerHierarchy)
	if err != nil {
		return err
	}

	// Provision Owner hierarchy with new EK and SRK
	srkAttrs, err := tpm.ProvisionOwner(soPIN)
	if err != nil {
		if errors.Is(err, tpmRCNVDefined) {
			// TPM_RC_NV_DEFINED: NV Index or persistent object already defined
			return store.ErrAlreadyInitialized
		}
		return err
	}

	// Create platform policy digest
	if err := tpm.CreatePlatformPolicy(); err != nil {
		return err
	}

	// Provision Initial Attestation Key (IAK)
	if _, err := tpm.CreateIAK(srkAttrs.Parent, nil); err != nil {
		return err
	}

	return nil
}

// replaceHierarchyAuth sets attrs' hierarchy authorization to auth, clearing
// the enclave it replaces so the locked memory behind it is released.
func replaceHierarchyAuth(attrs *types.KeyAttributes, auth types.Password) {
	if old := attrs.TPMAttributes.HierarchyAuth; old != nil && old != auth {
		old.Clear()
	}
	attrs.TPMAttributes.HierarchyAuth = auth
}

// Provisions a new Endorsement and Storage Root Key according to TCG
// Provisioning Guidance. The Endorsement Key (EK) is created and evicted
// to it's recommended persistent handle and a new Shared Storage Root Key
// (SRK) is created and evicted to it's recommended persistent handle.
func (tpm *TPM2) ProvisionOwner(
	soPIN types.Password) (*types.KeyAttributes, error) {

	tpm.logger.Info("Provisioning Owner Hierarchy")

	// Create EK
	ekAttrs, err := EKAttributesFromConfig(*tpm.config.EK, &tpm.policyDigest, tpm.config.IDevID)
	if err != nil {
		return nil, err
	}
	replaceHierarchyAuth(ekAttrs, soPIN)
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return nil, err
	}

	// Create Shared SRK. It takes no platform policy: the Shared SRK
	// outlives every platform PCR state, and the Platform SRK is the
	// platform-bound storage parent.
	srkAttrs, err := SRKAttributesFromConfig(*tpm.config.SSRK)
	if err != nil {
		return nil, err
	}
	srkAttrs.Parent = ekAttrs
	replaceHierarchyAuth(srkAttrs, soPIN)
	if err := tpm.CreateSRK(srkAttrs); err != nil {
		return nil, err
	}

	return srkAttrs, nil
}

// ProvisionEKCert writes an Endorsement Certificate to the NV index named
// by the configured EK cert-handle. When that index is already defined it
// returns ErrEKCertExists and leaves the stored certificate untouched;
// ReplaceEKCert overwrites it.
//
// If an EK cert-handle is not configured, the certificate is saved to
// the x509 certificate store instead of writing to NV RAM, which lets a
// user conserve NV RAM in a real TPM.
func (tpm *TPM2) ProvisionEKCert(hierarchyAuth, ekCertDER []byte) error {

	tpm.logger.Info("Provisioning Endorsement Key Certificate - EK Credential Profile")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return err
	}

	if tpm.config.EK.CertHandle == 0 {
		if tpm.certStore == nil {
			return ErrCertStoreNotInitialized
		}
		// Import certificate using PEM-encoded bytes
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ekCertDER,
		})
		_, err = tpm.certStore.ImportCertificate(ekAttrs, certPEM)
		if err != nil {
			return err
		}
		return nil
	}

	nvIndex, err := tpm.checkEKCertForNV(ekAttrs, ekCertDER)
	if err != nil {
		return err
	}
	return tpm.writeEKCertToNV(nvIndex, hierarchyAuth, ekCertDER)
}

// checkEKCertForNV validates ekCertDER for the NV index the configured EK
// cert-handle names for ekAttrs' key type (see ekCertIndex) and returns that
// index. It sends no command that changes the TPM: the cert-handle must lie
// in the NV index range, and the certificate must be a parseable X.509
// certificate that fits an NV index.
func (tpm *TPM2) checkEKCertForNV(ekAttrs *types.KeyAttributes, ekCertDER []byte) (tpm2.TPMHandle, error) {
	configured := tpm2.TPMHandle(tpm.config.EK.CertHandle)
	if configured>>24 != tpm2.TPMHandle(tpm2.TPMHTNVIndex) {
		tpm.logger.Error("EK cert-handle is not an NV index",
			slog.String("index", fmt.Sprintf("0x%08X", configured)))
		return 0, ErrEKCertIndexInvalid
	}
	nvIndex, err := ekCertIndex(configured, ekAttrs)
	if err != nil {
		tpm.logger.Error("EK key type has no TCG EK certificate index",
			slog.String("key_algorithm", ekAttrs.KeyAlgorithm.String()))
		return 0, err
	}
	if err := tpm.checkCertFitsNV(ekCertDER); err != nil {
		return 0, err
	}
	if _, err := x509.ParseCertificate(ekCertDER); err != nil {
		return 0, &errs.Joined{Lead: ErrInvalidEKCertFormat, Cause: err}
	}
	return nvIndex, nil
}

// ekCertIndexByCurve maps an ECC EK's curve to its EK certificate NV index
// (TCG EK Credential Profile v2.1 §2.2.1.4).
var ekCertIndexByCurve = map[elliptic.Curve]tpm2.TPMHandle{
	elliptic.P256(): ekCertIndexECCP256,
	elliptic.P384(): ekCertIndexECCP384,
	elliptic.P521(): ekCertIndexECCP521,
}

// ekCertIndex returns the NV index the EK certificate is written to. A
// configured cert-handle that is a TCG EK certificate index stands for the
// index the TCG EK Credential Profile v2.1 §2.2.1.4 assigns the EK's key
// type: 0x01C00002 for an RSA 2048 EK, 0x01C0000A for an ECC NIST P-256 EK,
// 0x01C00016 for P-384 and 0x01C00018 for P-521. So the RSA default
// cert-handle never receives an ECC EK's certificate. Any other configured
// index is used as configured. An EK key type the profile gives no index is
// ErrEKCertKeyType.
func ekCertIndex(configured tpm2.TPMHandle, ekAttrs *types.KeyAttributes) (tpm2.TPMHandle, error) {
	// Only the RSA 2048 default is resolved by key type; any other index,
	// the ECC ones included, is an explicit operator choice and kept.
	if configured != ekCertIndexRSA2048 {
		return configured, nil
	}
	switch ekAttrs.KeyAlgorithm {
	case x509.RSA:
		if ekAttrs.RSAAttributes != nil && ekAttrs.RSAAttributes.KeySize == 2048 {
			return ekCertIndexRSA2048, nil
		}
	case x509.ECDSA:
		if ekAttrs.ECCAttributes != nil {
			if index, ok := ekCertIndexByCurve[ekAttrs.ECCAttributes.Curve]; ok {
				return index, nil
			}
		}
	}
	return 0, ErrEKCertKeyType
}

// configuredEKCertIndex returns the NV index at which to look for the EK
// certificate the EK config names before the EK itself exists. It resolves
// the configured cert-handle by the configured key type with ekCertIndex, as
// the write path does, so an ECC EK's certificate is found at its TCG index
// (TCG EK Credential Profile v2.1 §2.2.1.4). A config whose key type has no
// TCG index, or does not parse, keeps the configured index: a manufacturer
// may still have provisioned a certificate there, and the bad key type is
// reported where the EK attributes are built (EKAttributesFromConfig).
func configuredEKCertIndex(config EKConfig) tpm2.TPMHandle {
	configured := tpm2.TPMHandle(config.CertHandle)
	keyType, err := ekKeyType(config)
	if err != nil {
		return configured
	}
	index, err := ekCertIndex(configured, keyType)
	if err != nil {
		return configured
	}
	return index
}

// isECCEKCertIndex reports whether index is one of the ECC EK certificate
// indices of ekCertIndexByCurve.
// writeEKCertToNV defines nvIndex under hierarchy and writes ekCertDER to
// it. An index that is already defined is refused with ErrEKCertExists.
func (tpm *TPM2) writeEKCertToNV(nvIndex tpm2.TPMHandle, hierarchyAuth, ekCertDER []byte) error {
	tpm.logger.Debug("NVDefineSpace: EK Certificate",
		slog.String("index", fmt.Sprintf("0x%08X", nvIndex)),
		slog.Int("size", len(ekCertDER)))

	// TPM 2.0 Part 3 §31.3.1: NV_DefineSpace takes TPM_RH_OWNER or
	// TPM_RH_PLATFORM, never the endorsement hierarchy the EK belongs to,
	// so the EK certificate index is owner-created like every other
	// certificate index.
	err := tpm.defineAndWriteCert(nvIndex, ekCertDER, tpm.hierarchyAuthorizer(tpm2.TPMRHOwner, hierarchyAuth))
	if errors.Is(err, tpmRCNVDefined) {
		return &errs.Joined{Lead: ErrEKCertExists, Cause: err}
	}
	return nvCertAuthError(err)
}

// ReplaceEKCert writes an Endorsement Certificate like ProvisionEKCert, but
// first undefines the NV index named by the configured EK cert-handle -- the
// one index ProvisionEKCert writes -- when it is already defined, so a stored
// certificate is replaced completely and a repeated call behaves like the
// first. Only that index is replaced: the EK and every other index are never
// touched. The index is undefined and redefined under the owner hierarchy,
// whichever hierarchy the EK belongs to, so hierarchyAuth is the owner
// authorization. The cert-handle, the certificate's encoding and size, and
// the index's type and creator are validated before anything is undefined:
// a platform-created index is refused with ErrEKCertPlatformIndex. The
// undefine itself proves the owner authorization, so a rejected call leaves
// the stored certificate in place.
//
// WARNING: This is a destructive operation that overwrites a TPM
// manufacturer or OEM certificate if one exists!
func (tpm *TPM2) ReplaceEKCert(hierarchyAuth, ekCertDER []byte) error {
	// Without an EK cert-handle the certificate lives in the certificate
	// store, whose import already overwrites.
	if tpm.config.EK.CertHandle == 0 {
		return tpm.ProvisionEKCert(hierarchyAuth, ekCertDER)
	}

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return err
	}
	nvIndex, err := tpm.checkEKCertForNV(ekAttrs, ekCertDER)
	if err != nil {
		return err
	}
	stored, err := tpm.readEKCertIndex(nvIndex)
	if err != nil {
		return err
	}

	// The index is owner-created (readEKCertIndex refuses a platform-created
	// one), so it is undefined and redefined under the owner hierarchy,
	// whichever hierarchy the EK itself belongs to.
	if stored != nil {
		if err := tpm.undefineEKCertIndex(stored, hierarchyAuth); err != nil {
			return err
		}
	}
	return tpm.writeEKCertToNV(nvIndex, hierarchyAuth, ekCertDER)
}

// undefineEKCertIndex undefines the EK certificate NV index whose public
// area readEKCertIndex returned, under the owner hierarchy authorized by
// hierarchyAuth. A wrong authorization fails the undefine and leaves the
// index in place.
func (tpm *TPM2) undefineEKCertIndex(stored *tpm2.NVReadPublicResponse, hierarchyAuth []byte) error {
	pub, err := stored.NVPublic.Contents()
	if err != nil {
		return err
	}
	tpm.logger.Info("Undefining EK certificate NV index",
		slog.String("index", fmt.Sprintf("0x%08X", pub.NVIndex)))
	return tpm.withHierarchyAuth(tpm2.TPMRHOwner, hierarchyAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: authHandle,
			NVIndex: tpm2.NamedHandle{
				Handle: pub.NVIndex,
				Name:   stored.NVName,
			},
		}.Execute(tpm.transport)
		return err
	})
}

// readEKCertIndex reads the public area of the EK certificate NV index,
// returning nil when the index is not defined. It refuses an index that
// cannot hold a certificate and one the platform hierarchy created, whose
// undefine needs platform authorization the caller does not hold.
func (tpm *TPM2) readEKCertIndex(nvIndex tpm2.TPMHandle) (*tpm2.NVReadPublicResponse, error) {
	readPubRsp, err := tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpm.transport)
	if err != nil {
		if errors.Is(err, tpmRCHandle) {
			return nil, nil
		}
		return nil, err
	}
	pub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	if pub.Attributes.NT != tpm2.TPMNTOrdinary {
		tpm.logger.Error("EK cert-handle names an NV index that cannot hold a certificate",
			slog.String("index", fmt.Sprintf("0x%08X", nvIndex)))
		return nil, ErrEKCertIndexInvalid
	}
	if pub.Attributes.PlatformCreate {
		tpm.logger.Error("EK certificate NV index is platform-created",
			slog.String("index", fmt.Sprintf("0x%08X", nvIndex)))
		return nil, ErrEKCertPlatformIndex
	}
	return readPubRsp, nil
}

// WriteEKCert writes the Endorsement Key certificate to the TPM.
// If CertHandle is 0, writes to the certificate store.
// If CertHandle is set, writes to NVRAM at that handle.
func (tpm *TPM2) WriteEKCert(ekCert []byte) error {
	return tpm.ProvisionEKCert(nil, ekCert)
}

// ParseEKCertificate parses a DER-encoded Endorsement Key certificate.
func (tpm *TPM2) ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse EK certificate", Err: err}
	}
	return cert, nil
}

// Captures platform Golden Integrity Measurements as described
// in TCG TPM 2.0 Provisioning Guidance - Section 7.6 - Golden
// Measurements.
//
// Performs a sum across all PCR banks and their associated
// values using the hash function defined in the TPM section
// of the platform configuration file. Any errors encountered
// are treated as FatalError.
//
// TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
func (tpm *TPM2) GoldenMeasurements() ([]byte, error) {
	tpm.logger.Info("Calculating Platform Golden Measurement")
	var gold, extend []byte
	hash, err := ParsePCRBankCryptoHash(tpm.config.PlatformPCRBank)
	if err != nil {
		tpm.logger.Error("failed to parse PCR bank crypto hash", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrGoldenMeasurements, Detail: fmt.Sprintf("%v", err)}
	}
	digest := hash.New()
	digest.Reset()

	banks, err := tpm.ReadPCRs(tpm.config.GoldenPCRs)
	if err != nil {
		tpm.logger.Error("failed to read PCRs", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrGoldenMeasurements, Detail: fmt.Sprintf("%v", err)}
	}

	// Create golden PCR that stores the final sum of
	// configured PCR values across all banks.
	for _, bank := range banks {
		tpm.logger.Info("tpm: processing PCR bank", slog.String("algorithm", bank.Algorithm))
		for _, pcr := range bank.PCRs {
			tpm.logger.Info("tpm: PCR value",
				slog.Int("id", int(pcr.ID)),
				slog.String("value", fmt.Sprintf("%x", pcr.Value)))
			extend = append(extend, pcr.Value...)
			digest.Write(extend)
			gold = digest.Sum(nil)
			extend = gold
			digest.Reset()
		}
	}
	tpm.logger.Info("tpm: golden measurement calculated",
		slog.String("pcrs", fmt.Sprintf("%v", tpm.config.GoldenPCRs)),
		slog.String("measurement", fmt.Sprintf("%x", gold)))

	return gold, nil
}

// PlatformPolicyDigestHash reads the current values of the platform PCR set
// and returns their digest in the PCR bank's own algorithm: the pcrDigest a
// TPM2_PolicyPCR session in that algorithm is checked against.
func (tpm *TPM2) PlatformPolicyDigestHash() ([]byte, error) {

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, err
	}
	return tpm.platformPCRDigest(hashAlgID)
}

// platformPCRDigest reads the platform PCR set from the configured bank and
// digests its values with hashAlg. TPM2_PolicyPCR compares against a digest
// in the session's hash algorithm, which is the bank algorithm for the
// platform policy and the key's nameAlg for a DevID platform delegation, so
// the algorithm is the caller's choice and the PCR read is not.
func (tpm *TPM2) platformPCRDigest(hashAlg tpm2.TPMAlgID) ([]byte, error) {

	bank, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, err
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	// TPM2_PolicyPCR hashes the selected PCR values concatenated in
	// ascending index order. A PCRRead response carries at most eight
	// digests, lowest index first, and names the PCRs it read in
	// pcrSelectionOut, so the rest of the set is read again until every
	// PCR is hashed.
	hash := cryptoHashAlg.New()
	remaining := tpm.config.PlatformPCRs.Sorted()
	for len(remaining) > 0 {
		pcrReadRsp, err := tpm2.PCRRead{
			PCRSelectionIn: PolicyPCRSelection(bank, remaining...),
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("PCRRead failed", slog.String("error", err.Error()))
			return nil, err
		}
		read := pcrSetFromSelection(pcrReadRsp.PCRSelectionOut, bank)
		if len(read) == 0 || len(read) > len(remaining) ||
			len(read) != len(pcrReadRsp.PCRValues.Digests) ||
			!slices.Equal(read, remaining[:len(read)]) {
			return nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute,
				Detail: fmt.Sprintf("PCR %d is not present in bank 0x%04x", remaining[0], uint16(bank))}
		}
		for _, digest := range pcrReadRsp.PCRValues.Digests {
			hash.Write(digest.Buffer)
		}
		remaining = remaining[len(read):]
	}

	return hash.Sum(nil), nil
}

// pcrSetFromSelection returns, in ascending order, the PCRs sel selects in
// bank.
func pcrSetFromSelection(sel tpm2.TPMLPCRSelection, bank tpm2.TPMAlgID) PCRSet {
	var mask uint32
	for _, s := range sel.PCRSelections {
		if s.Hash != bank {
			continue
		}
		for i, b := range s.PCRSelect {
			if i < 4 {
				mask |= uint32(b) << (8 * i)
			}
		}
	}
	return PCRSetFromMask(mask)
}

// CreatePlatformPolicy computes, in a trial session, the TPM2_PolicyPCR
// digest over the platform PCR set as it reads now and caches it as the
// platform policy digest.
func (tpm *TPM2) CreatePlatformPolicy() error {

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return err
	}

	// Digest of the platform PCR set as firmware and the OS measured it.
	// xkms never extends these PCRs.
	hash, err := tpm.PlatformPolicyDigestHash()
	if err != nil {
		return err
	}

	// Create a trial session to calculate the policy digest
	trialSession, closer, err := tpm2.PolicySession(
		tpm.transport, hashAlgID, 16, tpm2.Trial())
	if err != nil {
		tpm.logger.Error("PolicySession failed", slog.String("error", err.Error()))
		return err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close policy session", slog.String("error", err.Error()))
		}
	}()

	_, err = tpm2.PolicyPCR{
		PolicySession: trialSession.Handle(),
		Pcrs:          platformPolicyPCRSelection(hashAlgID, tpm.config.PlatformPCRs),
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: hash,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("PolicyPCR failed", slog.String("error", err.Error()))
		return err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}

	tpm.logger.Info("tpm: CreatePlatformPolicy - policy digest",
		slog.String("digest", fmt.Sprintf("%x", pgd.PolicyDigest.Buffer)))
	tpm.logger.Info("tpm: CreatePlatformPolicy - PCR hash",
		slog.Any("pcrs", tpm.config.PlatformPCRs),
		slog.String("hash", fmt.Sprintf("%x", hash)))

	tpm.policyDigest = pgd.PolicyDigest

	return nil
}

// BackupEKCertificates reads EK certificates from standard NV indices
// (RSA 0x01C00002, ECC 0x01C0000A) and saves them to the cert store as
// PEM-encoded backups. Best-effort: errors are logged as warnings and
// do not block provisioning.
func (tpm *TPM2) BackupEKCertificates() {
	indices := []struct {
		handle tpm2.TPMHandle
		label  string
	}{
		{tpm2.TPMHandle(ekCertIndexRSA2048), "ek-cert-rsa-backup"},
		{tpm2.TPMHandle(ekCertIndexECCP256), "ek-cert-ecc-backup"},
	}
	for _, idx := range indices {
		cert, err := tpm.readEKCertFromNV(idx.handle)
		if err != nil {
			continue
		}
		if tpm.certStore == nil {
			tpm.logger.Warn("no cert store available for EK backup")
			return
		}
		backupAttrs := &types.KeyAttributes{
			CN:        idx.label,
			StoreType: types.StoreTPM2,
		}
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if _, err := tpm.certStore.ImportCertificate(backupAttrs, certPEM); err != nil {
			tpm.logger.Warn("failed to backup EK certificate",
				slog.String("label", idx.label),
				slog.String("error", err.Error()))
		} else {
			tpm.logger.Info("backed up EK certificate",
				slog.String("label", idx.label),
				slog.String("subject", cert.Subject.String()))
		}
	}
}

// hardResetViaSysRq forces an immediate warm reboot of the system.
// Used after scheduling a UEFI PPI TPM ForceClear so firmware services
// the clear request during the next POST.
//
// On some platforms (Supermicro X10 observed) the userspace `reboot -f`
// is translated by firmware into an ACPI S5 shutdown rather than a warm
// reset, which leaves the system off and the PPI request unserviced
// until manual power-on. The Linux kernel's SysRq interface lets us
// issue the CPU reset vector directly, bypassing init, shutdown
// scripts, and ACPI entirely.
//
// Order: SysRq 'b' (reboot) first, then SysRq 'c' (crash — triggers
// panic-on-oops reset on most kernels), then busybox `reboot -f` as a
// final fallback. The function does not return on success; the CPU
// resets before the later fallbacks run.
func hardResetViaSysRq(logger *slog.Logger) {
	warn := func(msg string, err error) {
		if logger != nil && err != nil {
			logger.Warn(msg, slog.String("error", err.Error()))
		}
	}

	// Flush in-flight writes.
	warn("hardReset: sync failed", exec.Command("sync").Run())
	time.Sleep(100 * time.Millisecond)

	// Ensure SysRq mask allows reboot + crash (1 = all enabled).
	warn("hardReset: SysRq mask write failed",
		os.WriteFile("/proc/sys/kernel/sysrq", []byte("1"), 0o644)) // #nosec G306 - existing kernel sysctl node, not a created file

	// SysRq 'b' — immediate CPU reset, skips init/ACPI entirely.
	warn("hardReset: SysRq-b write failed", os.WriteFile("/proc/sysrq-trigger", []byte("b"), 0o200))
	time.Sleep(2 * time.Second)

	// SysRq 'c' — crash → panic → reset (panic=1 cmdline or default).
	warn("hardReset: SysRq-c write failed", os.WriteFile("/proc/sysrq-trigger", []byte("c"), 0o200))
	time.Sleep(2 * time.Second)

	// Final fallback: busybox/openrc reboot. Some platforms translate
	// this to ACPI S5, which is why SysRq was tried first.
	warn("hardReset: reboot -f failed", exec.Command("reboot", "-f").Run())
	time.Sleep(2 * time.Second)
	warn("hardReset: reboot failed", exec.Command("reboot").Run())
}
