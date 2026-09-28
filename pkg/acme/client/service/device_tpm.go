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

package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// deviceTPM wraps client.NewXKMSTPMAdapter's result to also release the
// on-disk key/blob store the TPM was opened against when the module is
// closed, so a device with no configured KeyDir (ephemeral, simulator-only
// storage) does not leak a temporary directory per Enroll/Attest call.
type deviceTPM struct {
	*client.XKMSTPMAdapter
	factory *xkmssdk.TPMStorageFactory
}

// Close releases the TPM handle and its key/blob store factory. Both are
// attempted; the TPM's error takes precedence when both fail.
func (d *deviceTPM) Close() error {
	tpmErr := d.XKMSTPMAdapter.Close()
	factoryErr := d.factory.Close()
	if tpmErr != nil {
		return tpmErr
	}
	return factoryErr
}

// openDeviceTPM opens the TPM 2.0 module spec.TPM describes for the named
// device and adapts it to the client.TPMModule interface EnrollDevice and
// DeviceAttest consume. The caller owns the returned module's lifecycle and
// must Close it when done.
//
// A device whose TPM configuration selects the in-process simulator (or
// leaves TPM nil, which defaults to xkmssdk.DefaultTPMConfig — also
// simulator-backed) is provisioned on first use: its EK, SSRK, IAK and
// Platform SRK are created if absent, a throwaway Endorsement Key certificate
// is minted if none is configured or already present, and a throwaway IAK
// certificate is minted into an in-memory certificate store so the
// device-attest-01 statement has an x5c. This is development and testing
// tooling only. Real hardware is never auto-provisioned: an unprovisioned
// physical TPM is refused with ErrDeviceTPMNotProvisioned naming the
// operator action, exactly as pkg/backend/tpm2.NewBackend refuses it.
func openDeviceTPM(name string, spec *DeviceSpec, logger *slog.Logger) (client.TPMModule, error) {
	dev := spec.TPM
	simulator := dev.useSimulator()
	tpmCfg := dev.resolvedConfig()

	factory, err := xkmssdk.NewTPMStorageFactory(logger, dev.keyDir())
	if err != nil {
		return nil, ErrDeviceTPMOpenFailed{Name: name, Err: err}
	}

	params := &xkmssdk.TPMParams{
		Config:    tpmCfg,
		Backend:   factory.KeyBackend(),
		BlobStore: factory.BlobStore(),
		Logger:    logger,
	}
	if simulator {
		params.CertStore = store.NewMemoryCertStore(logger)
	}
	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil {
		if errors.Is(err, xkmssdk.ErrTPMNotInitialized) && simulator && tpm != nil {
			if perr := provisionSimulatorIdentity(name, tpm, tpmCfg); perr != nil {
				return nil, errors.Join(perr, tpm.Close(), factory.Close())
			}
		} else {
			var closeErrs []error
			if tpm != nil {
				closeErrs = append(closeErrs, tpm.Close())
			}
			closeErrs = append(closeErrs, factory.Close())
			if errors.Is(err, xkmssdk.ErrTPMNotInitialized) {
				return nil, errors.Join(append([]error{ErrDeviceTPMNotProvisioned{Name: name}}, closeErrs...)...)
			}
			return nil, errors.Join(append([]error{ErrDeviceTPMOpenFailed{Name: name, Err: err}}, closeErrs...)...)
		}
	}

	module := &deviceTPM{
		XKMSTPMAdapter: client.NewXKMSTPMAdapter(tpm, factory.KeyBackend()),
		factory:        factory,
	}

	if err := ensureEKCertificate(name, module, dev, simulator); err != nil {
		return nil, errors.Join(err, module.Close())
	}
	if simulator {
		if err := provisionSimulatorIAKCertificate(name, tpm); err != nil {
			return nil, errors.Join(err, module.Close())
		}
	}

	return module, nil
}

// provisionSimulatorIdentity creates the EK, SSRK, IAK and Platform SRK the
// in-process TPM simulator needs for enrollment and attestation. It never runs against real
// hardware (openDeviceTPM gates it on simulator == true) and never performs
// the destructive TPM2_Clear a first-boot ceremony (TrustedPlatformModule.
// Provision) does — it only creates the four keys, mirroring
// pkg/backend/tpm2.NewBackend's own simulator provisioning. The Platform SRK
// is the parent of the device-attest-01 certificate key.
func provisionSimulatorIdentity(name string, tpm xkmssdk.TrustedPlatformModule, cfg *xkmssdk.TPMConfig) error {
	if cfg.EK == nil || cfg.SSRK == nil || cfg.PlatformSRK == nil {
		return ErrDeviceTPMConfigIncomplete{Name: name, Reason: "ek, ssrk and platform-srk configuration are required to provision the simulator"}
	}

	ekAttrs, err := xkmssdk.EKAttributesFromConfig(*cfg.EK, nil, nil)
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	// A configured EK.HierarchyAuth names the auth a prior TCG provisioning
	// ceremony (TrustedPlatformModule.Provision) set on the Endorsement
	// hierarchy — it is not itself applied by that ceremony's CreateEK step,
	// which authorizes with the SO PIN passed to Provision (see
	// pkg/tpm2/provision.go ProvisionOwner and installIAK). This path never
	// runs that ceremony, so the simulator's Endorsement hierarchy auth is
	// still its fresh, empty default; authorizing with a configured
	// hierarchy auth here would be TPM_RC_BAD_AUTH against that empty auth.
	ekAttrs.TPMAttributes.HierarchyAuth = nil
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	// CreateEK only mutates the ekAttrs it was given; it does not populate
	// the TrustedPlatformModule's own EK cache. EK(), EKCertificate() and
	// CreateIDevID all read that cache, so force it to populate now by
	// re-reading the EK from its persistent handle — exactly what the first
	// call to EKAttributes() after a real provisioning ceremony would do.
	if _, err := tpm.EKAttributes(); err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}

	srkAttrs, err := xkmssdk.SRKAttributesFromConfig(*cfg.SSRK)
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	srkAttrs.Parent = ekAttrs
	if err := tpm.CreateSRK(srkAttrs); err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}

	if _, err := tpm.CreateIAK(ekAttrs, nil); err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}

	psrkAttrs, err := pkgtpm2.PlatformSRKAttributesFromConfig(cfg)
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	psrkAttrs.Parent = ekAttrs
	if err := tpm.CreateSRK(psrkAttrs); err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}

	return nil
}

// provisionSimulatorIAKCertificate installs a throwaway IAK certificate on
// the simulator, in the WebAuthn Level 2 section 8.3.1 shape a "tpm"
// attestation statement's x5c[0] must have: an empty subject, a
// subjectAltName naming the TPM's manufacturer, model and version,
// tcg-kp-AIKCertificate, and not a CA. It is signed by an unrelated one-off
// key, as the simulator's EK certificate is (selfSignedSimulatorEKCert), and
// stands in for the certificate an attestation CA issues a real device. It is
// development and testing tooling only -- see openDeviceTPM's simulator gate.
func provisionSimulatorIAKCertificate(name string, tpm xkmssdk.TrustedPlatformModule) error {
	iak, err := tpm.IAK()
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	props, err := tpm.FixedProperties()
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	san, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil, nil, []pkix.Name{{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: props.ManufacturerCode},
			{Type: ca.OIDTCGAttributeTPMModel, Value: "xkms-simulator"},
			{Type: ca.OIDTCGAttributeTPMVersion, Value: fmt.Sprintf("id:%04X%04X", props.FwMajor, props.FwMinor)},
		},
	}})
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ca.OIDTCGKpAIKCertificate},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{san},
	}
	issuer := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "xkms-simulator-aik-ca"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, iak, signer)
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	if err := tpm.ProvisionIAKCert(cert); err != nil {
		return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
	}
	return nil
}

// ensureEKCertificate makes sure module has an Endorsement Key certificate
// available before enrollment or attestation needs one: a configured
// EKCertificatePEM is provisioned verbatim; otherwise, for the simulator, a
// throwaway certificate naming the simulator's real EK public key is minted
// and provisioned unconditionally (development and testing only — a fresh
// simulator never has one); otherwise (real hardware) an existing
// certificate (manufacturer-issued or previously provisioned) is required —
// TrustedPlatformModule.EKCertificate's own manufacturer-download fallback
// is given the chance to supply one, and a device with neither is refused.
//
// The simulator branch never calls module.EKCertificate() to "check first":
// that call's manufacturer-download fallback (TPM2.EKCertificate) makes an
// unbounded, untimeoutable HTTPS request that a simulator — which can never
// have a manufacturer certificate — would only ever reach and pay for
// needlessly, including inside tests that must stay hermetic.
func ensureEKCertificate(name string, module client.TPMModule, dev *DeviceTPMConfig, simulator bool) error {
	if dev != nil && dev.EKCertificatePEM != "" {
		block, _ := pem.Decode([]byte(dev.EKCertificatePEM))
		if block == nil {
			return ErrInvalidEKCertificatePEM{Name: name}
		}
		return module.ProvisionEKCert(block.Bytes)
	}

	if simulator {
		certDER, err := selfSignedSimulatorEKCert(module.EK())
		if err != nil {
			return ErrDeviceTPMProvisionFailed{Name: name, Err: err}
		}
		return module.ProvisionEKCert(certDER)
	}

	if _, err := module.EKCertificate(); err != nil {
		return ErrDeviceEKCertificateRequired{Name: name, Err: err}
	}
	return nil
}

// selfSignedSimulatorEKCert mints a throwaway certificate naming pub (the
// simulator's real EK public key) as its subject, signed by an unrelated
// one-off key rather than by the EK itself (an RSA EK is restricted to
// decryption and cannot sign). This stands in for the manufacturer
// certificate a real TPM carries; it is development and testing tooling
// only — see openDeviceTPM's simulator gate.
func selfSignedSimulatorEKCert(pub crypto.PublicKey) ([]byte, error) {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "xkms-simulator-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}

	return x509.CreateCertificate(rand.Reader, template, template, pub, signer)
}
