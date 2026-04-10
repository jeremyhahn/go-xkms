package tpm2

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Clears the TPM as described in TCG Part 3: Commands - Section 24.6 - TPM2_Clear
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
// This command clears Owner, Endorsement, and Lockout hierarchy auth values.
// Authorization must be provided using either the Lockout or Platform hierarchy.
func (tpm *TPM2) Clear(lockoutAuth []byte) error {
	_, err := tpm2.Clear{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHLockout,
			Auth:   tpm2.PasswordAuth(lockoutAuth),
		},
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}
	return nil
}

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

	if err := os.WriteFile(ppiPath, []byte("5"), 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrForceClear, err)
	}

	tpm.logger.Info("TPM clear scheduled via UEFI Physical Presence Interface",
		slog.String("ppi_path", ppiPath),
		slog.String("request_code", "5"))

	return nil
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

	// TCG-standard EK persistent key handles that MUST be preserved.
	// These are defined by the Trusted Computing Group and contain
	// manufacturer-provisioned Endorsement Keys and their certificates.
	// Reference: TCG TPM 2.0 Provisioning Guidance, Section 7.8, Table 2
	preserveHandles := map[tpm2.TPMHandle]bool{
		0x81010001: true, // EK RSA 2048 (TCG default)
		0x81010002: true, // EK ECC P-256 (TCG default)
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

			_, err = tpm2.EvictControl{
				Auth: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(ownerAuth),
				},
				ObjectHandle: &tpm2.NamedHandle{
					Handle: handle,
					Name:   name,
				},
				PersistentHandle: handle,
			}.Execute(tpm.transport)
			if err != nil {
				tpm.logger.Error("Failed to evict handle",
					slog.String("handle", fmt.Sprintf("0x%08X", handle)),
					slog.String("error", err.Error()))
				if firstErr == nil {
					firstErr = fmt.Errorf("%w: evict handle 0x%08X: %v", ErrFactoryReset, handle, err)
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

		_, err = tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(ownerAuth),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   readPubRsp.NVName,
			},
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("Failed to undefine NV index",
				slog.String("index", fmt.Sprintf("0x%08X", nvIndex)),
				slog.String("error", err.Error()))
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: undefine NV 0x%08X: %v", ErrFactoryReset, nvIndex, err)
			}
		} else {
			tpm.logger.Info("Undefined NV index",
				slog.String("index", fmt.Sprintf("0x%08X", nvIndex)))
		}
	}

	// 4. Clear cached attributes
	tpm.iakAttrs = nil
	tpm.idevidAttrs = nil
	tpm.ssrkAttrs = nil

	return firstErr
}

// InstallOptions controls which provisioning steps Install() performs.
// When nil is passed to Install(), DefaultInstallOptions() is used.
type InstallOptions struct {
	EK             bool // Ensure EK exists at configured handle
	SSRK           bool // Ensure SSRK exists at configured handle
	PlatformPolicy bool // Extend PCR 23 with golden measurements
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
		if tpm.config.EK != nil && tpm.config.EK.HierarchyAuth != "" {
			currentAuth = store.NewPassword([]byte(tpm.config.EK.HierarchyAuth))
		}

		if err := tpm.SetHierarchyAuth(currentAuth, soPIN, nil); err != nil {
			return err
		}
	}

	// Create EK if it doesnt exist
	if opts.EK {
		ekAttrs, err := tpm.EKAttributes()
		if err != nil {
			if err == tpm2.TPMRC(0x18b) {
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
				ekAttrs.TPMAttributes.HierarchyAuth = soPIN
				if err := tpm.CreateEK(ekAttrs); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			ekAttrs.TPMAttributes.HierarchyAuth = soPIN
		}
	}

	// Create SSRK if it doesnt exist
	if opts.SSRK {
		var ssrkAttrs *types.KeyAttributes
		ekAttrs, ekErr := tpm.EKAttributes()
		if ekErr != nil {
			return ekErr
		}
		ekAttrs.TPMAttributes.HierarchyAuth = soPIN
		_, err := tpm.SSRKAttributes()
		if err != nil {
			if err == tpm2.TPMRC(0x18b) {
				tpm.logger.Info("Creating Shared SRK")
				policyDigest, pdErr := tpm.PlatformPolicyDigest()
				if pdErr != nil {
					return pdErr
				}
				ssrkAttrs, err = SRKAttributesFromConfig(*tpm.config.SSRK, &policyDigest)
				if err != nil {
					return err
				}
				ssrkAttrs.Parent = ekAttrs
				ssrkAttrs.Password = store.NewPassword(nil)
				ssrkAttrs.TPMAttributes.HierarchyAuth = soPIN
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
		ekAttrs.TPMAttributes.HierarchyAuth = soPIN
		var iakAttrs *types.KeyAttributes
		iakAttrs, err := tpm.IAKAttributes()
		if err != nil {
			if err == tpm2.TPMRC(0x18b) {
				// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
				// This means the IAK doesn't exist yet - create it
				tpm.logger.Info("Creating Initial Attestation Key")
				iakAttrs, err = tpm.CreateIAK(ekAttrs, nil)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}
		_ = iakAttrs
	}

	// Create IDevID if it doesnt exist and is configured
	if opts.IDevID {
		if tpm.config.IDevID != nil {
			iakAttrs, iakErr := tpm.IAKAttributes()
			if iakErr != nil {
				return iakErr
			}
			if _, err := tpm.IDevIDAttributes(); err != nil {
				if err == tpm2.TPMRC(0x18b) {
					// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
					// This means the IDevID doesn't exist yet - create it
					tpm.logger.Info("Creating Initial Device Identity Key")
					// Get EK certificate for IDevID CSR (optional, may not exist)
					ekCert, _ := tpm.EKCertificate()
					if _, _, err := tpm.CreateIDevID(iakAttrs, ekCert, nil); err != nil {
						return err
					}
				}
				// Ignore other errors - IDevID creation is optional
			}
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
		// Continue anyway - the TPM might already be in the expected state
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

	if tpm.debugSecrets {
		var soPinBytes []byte
		if soPIN != nil {
			soPinBytes = soPIN.Bytes()
		}
		tpm.logger.Debug("tpm: hierarchy authorization set",
			slog.String("authorization", string(soPinBytes)))
	}

	// Provision Owner hierarchy with new EK and SRK
	srkAttrs, err := tpm.ProvisionOwner(soPIN)
	if err != nil {
		if err == tpm2.TPMRC(0x14c) {
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
	ekAttrs.TPMAttributes.HierarchyAuth = soPIN
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return nil, err
	}

	// Create Shared SRK
	srkAttrs, err := SRKAttributesFromConfig(*tpm.config.SSRK, &tpm.policyDigest)
	if err != nil {
		return nil, err
	}
	srkAttrs.Parent = ekAttrs
	srkAttrs.TPMAttributes.HierarchyAuth = soPIN
	if err := tpm.CreateSRK(srkAttrs); err != nil {
		return nil, err
	}

	return srkAttrs, nil
}

// Writes an Endorsement Certificate to TPM NVRAM.
//
// WARNING: This is a potentially destructive operation that will overwrite
// a TPM manufacturer or OEM certificate if it exists!
//
// If an EK cert-handle is not configured, the certificate is saved to
// the x509 certificate store instead of writing to NV RAM.
// This provides a workaround for the 1024 byte limitation in the
// simulator and/or allows a user to conserve NV RAM in a real TPM.
func (tpm *TPM2) ProvisionEKCert(hierarchyAuth, ekCertDER []byte) error {

	tpm.logger.Info("Provisioning Endorsement Key Certificate - EK Credential Profile")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return err
	}

	ekCertHandle := tpm2.TPMHandle(ekCertIndex)

	if tpm.config.EK.CertHandle == 0 {
		if tpm.certStore == nil {
			return errors.New("certificate store not initialized")
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

	tpm.logger.Debug("NVDefineSpace: EK Certificate",
		slog.Int("size", len(ekCertDER)))

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: ekAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: ekCertHandle,
				NameAlg: tpm.algID,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					AuthWrite:  true,
					OwnerRead:  true,
					AuthRead:   true,
					NoDA:       true,
					NT:         tpm2.TPMNT(0x01),
				},
				DataSize: uint16(len(ekCertDER)),
			}),
	}
	_, err = defs.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVDefineSpace failed", slog.String("error", err.Error()))
		return err
	}

	//  NV index type 4 = TPM_NT_ORDINARY

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public info contents", slog.String("error", err.Error()))
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error("failed to get NV name", slog.String("error", err.Error()))
		return err
	}

	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: ekAttrs.TPMAttributes.Hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: ekCertDER,
		},
		Offset: 0,
	}
	if _, err := write.Execute(tpm.transport); err != nil {
		tpm.logger.Error("NVWrite failed", slog.String("error", err.Error()))
		return err
	}

	return nil
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
		return nil, fmt.Errorf("failed to parse EK certificate: %w", err)
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
		return nil, fmt.Errorf("%w: %v", ErrGoldenMeasurements, err)
	}
	digest := hash.New()
	digest.Reset()

	banks, err := tpm.ReadPCRs(tpm.config.GoldenPCRs)
	if err != nil {
		tpm.logger.Error("failed to read PCRs", slog.String("error", err.Error()))
		return nil, fmt.Errorf("%w: %v", ErrGoldenMeasurements, err)
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

// Reads the current PCR value and returns it's digest buffer
func (tpm *TPM2) PlatformPolicyDigestHash() ([]byte, error) {

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, err
	}

	cryptoHashAlg, err := hashAlgID.Hash()
	if err != nil {
		return nil, err
	}

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      hashAlgID,
				PCRSelect: tpm2.PCClientCompatible.PCRs(uint(tpm.config.PlatformPCR)),
			},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("PCRRead failed", slog.String("error", err.Error()))
		return nil, err
	}
	buffer := pcrReadRsp.PCRValues.Digests[0].Buffer

	// Create digest of the golden PCR
	hash := cryptoHashAlg.New()
	hash.Reset()
	hash.Write(buffer)
	digest := hash.Sum(nil)

	// tpm.logger.Debug("PlatformPolicyDigest: PCRRead buffer", slog.String("buffer", fmt.Sprintf("%x", buffer)))
	// tpm.logger.Debug("PlatformPolicyDigest: PCRRead digest", slog.String("digest", fmt.Sprintf("%x", digest)))

	return digest, nil
}

// Returns the Golden Integrity Measurement and Policy Digest ready
// to be attached to a key.
func (tpm *TPM2) CreatePlatformPolicy() error {

	// Capture platform measurements and extend the Golden
	// Integrity Measurement into the platform selected PCR
	// specified in the platform configuration file
	measurement, err := tpm.GoldenMeasurements()
	if err != nil {
		return err
	}

	// If no golden PCRs are configured, skip PCR extension
	if len(measurement) == 0 {
		tpm.logger.Info("tpm: no golden PCRs configured, skipping platform policy")
		return nil
	}

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return err
	}

	tpm.logger.Info("tpm: CreatePlatformPolicy - extending golden measurement",
		slog.String("measurement", fmt.Sprintf("%x", measurement)),
		slog.String("bank", tpm.config.PlatformPCRBank),
		slog.Uint64("pcr", uint64(tpm.config.PlatformPCR)))

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(tpm.config.PlatformPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: hashAlgID,
					Digest:  measurement,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("PCRExtend failed", slog.String("error", err.Error()))
		return err
	}

	// Get a digest of the current PCR value
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

	// Create PCR selection using "platform-pcr" defined in the platform
	// configuration file TPM section.
	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      hashAlgID,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
			},
		},
	}

	// Create policy digest for the selected PCR
	_, err = tpm2.PolicyPCR{
		PolicySession: trialSession.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
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

	tpm.logger.Info("tpm: CreatePlatformPolicy - golden measurement",
		slog.String("measurement", fmt.Sprintf("%x", measurement)))
	tpm.logger.Info("tpm: CreatePlatformPolicy - policy digest",
		slog.String("digest", fmt.Sprintf("%x", pgd.PolicyDigest.Buffer)))
	tpm.logger.Info("tpm: CreatePlatformPolicy - PCR hash",
		slog.Uint64("pcr", uint64(tpm.config.PlatformPCR)),
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
