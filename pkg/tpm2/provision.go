package tpm2

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
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
func (tpm *TPM2) Install(soPIN types.Password) error {

	tpm.logger.Info("Installing Platform")

	// Use the config's HierarchyAuth as the current auth if set,
	// otherwise assume empty auth for fresh TPMs.
	// This allows Install to work on both fresh TPMs and already-provisioned TPMs.
	var currentAuth types.Password
	if tpm.config.EK != nil && tpm.config.EK.HierarchyAuth != "" {
		currentAuth = store.NewClearPassword([]byte(tpm.config.EK.HierarchyAuth))
	}

	// Set new hierarchy authorizations
	if err := tpm.SetHierarchyAuth(currentAuth, soPIN, nil); err != nil {
		return err
	}

	// Create EK if it doesnt exist
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		if err == tpm2.TPMRC(0x18b) {
			// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
			tpm.logger.Info("Creating Endorsement Key")
			policyDigest := tpm.PlatformPolicyDigest()
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

	// Create SSRK if it doesnt exist
	var ssrkAttrs *types.KeyAttributes
	_, err = tpm.SSRKAttributes()
	if err != nil {
		if err == tpm2.TPMRC(0x18b) {
			tpm.logger.Info("Creating Shared SRK")
			policyDigest := tpm.PlatformPolicyDigest()
			ssrkAttrs, err = SRKAttributesFromConfig(*tpm.config.SSRK, &policyDigest)
			if err != nil {
				return err
			}
			ssrkAttrs.Parent = ekAttrs
			ssrkAttrs.Password = store.NewClearPassword(nil)
			ssrkAttrs.TPMAttributes.HierarchyAuth = soPIN
			if err := tpm.CreateSRK(ssrkAttrs); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Capture platform measurements and create the policy digest
	if err := tpm.CreatePlatformPolicy(); err != nil {
		return err
	}

	// Create IAK if it doesnt exist
	if _, err = tpm.IAKAttributes(); err == ErrNotInitialized {
		tpm.logger.Info("Creating Initial Attesation Key")
		if _, err := tpm.CreateIAK(ekAttrs, nil); err != nil {
			return err
		}
	}

	// Retrieve the EK certificate or return an error
	if _, err := tpm.EKCertificate(); err != nil {
		return err
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
		tpm.logger.MaybeError(err)
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
		tpm.logger.Debugf("tpm: Lockout, Endorsement & Storage Hierarchy authorization: %s", soPinBytes)
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

	tpm.logger.Debugf("NVDefineSpace: EK Certificate size: %d", len(ekCertDER))

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
		tpm.logger.Error(err)
		return err
	}

	//  NV index type 4 = TPM_NT_ORDINARY

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error(err)
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
		tpm.logger.Error(err)
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
func (tpm *TPM2) GoldenMeasurements() []byte {
	tpm.logger.Info("Calculating Platform Golden Measurement")
	var gold, extend []byte
	hash, err := ParsePCRBankCryptoHash(tpm.config.PlatformPCRBank)
	if err != nil {
		tpm.logger.FatalError(err)
	}
	digest := hash.New()
	digest.Reset()

	banks, err := tpm.ReadPCRs(tpm.config.GoldenPCRs)
	if err != nil {
		tpm.logger.FatalError(err)
	}

	// Create golden PCR that stores the final sum of
	// configured PCR values across all banks.
	for _, bank := range banks {
		tpm.logger.Infof("tpm: processing PCR bank: %s", bank.Algorithm)
		for _, pcr := range bank.PCRs {
			tpm.logger.Infof("tpm: PCR[%d] = %x", pcr.ID, pcr.Value)
			extend = append(extend, pcr.Value...)
			digest.Write(extend)
			gold = digest.Sum(nil)
			extend = gold
			digest.Reset()
		}
	}
	tpm.logger.Infof("tpm: golden measurement from PCRs %v = %x", tpm.config.GoldenPCRs, gold)

	return gold
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
		tpm.logger.Error(err)
		return nil, err
	}
	buffer := pcrReadRsp.PCRValues.Digests[0].Buffer

	// Create digest of the golden PCR
	hash := cryptoHashAlg.New()
	hash.Reset()
	hash.Write(buffer)
	digest := hash.Sum(nil)

	// tpm.logger.Debugf("PlatformPolicyDigest: PCRRead buffer: %x", buffer)
	// tpm.logger.Debugf("PlatformPolicyDigest: PCRRead digest: %x", digest)

	return digest, nil
}

// Returns the Golden Integrity Measurement and Policy Digest ready
// to be attached to a key.
func (tpm *TPM2) CreatePlatformPolicy() error {

	// Capture platform measurements and extend the Golden
	// Integrity Measurement into the platform selected PCR
	// specified in the platform configuration file
	measurement := tpm.GoldenMeasurements()

	// If no golden PCRs are configured, skip PCR extension
	if len(measurement) == 0 {
		tpm.logger.Info("tpm: no golden PCRs configured, skipping platform policy")
		return nil
	}

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return err
	}

	tpm.logger.Infof(
		"tpm: CreatePlatformPolicy - extending golden measurement %x to PCR %s:%d",
		measurement, tpm.config.PlatformPCRBank, tpm.config.PlatformPCR)

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
		tpm.logger.Error(err)
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
		tpm.logger.Error(err)
		return err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error(err)
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
		tpm.logger.Error(err)
		return err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}

	tpm.logger.Infof("tpm: CreatePlatformPolicy - golden measurement: %x", measurement)
	tpm.logger.Infof("tpm: CreatePlatformPolicy - policy digest: %x", pgd.PolicyDigest.Buffer)
	tpm.logger.Infof("tpm: CreatePlatformPolicy - PCR %d hash: %x", tpm.config.PlatformPCR, hash)

	tpm.policyDigest = pgd.PolicyDigest

	return nil
}
