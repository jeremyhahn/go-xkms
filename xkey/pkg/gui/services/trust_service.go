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

package services

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// TagBrowserExport is the tag used to mark certificates for browser trust
// bundle export.
const TagBrowserExport = "browser-export"

// browserBundleManifestFile is the sidecar manifest written alongside the
// PEM bundle to enable fast staleness detection.
const browserBundleManifestFile = "trust-bundle.manifest.json"

// bundleManifest records the fingerprints of certificates included in the
// most recent browser trust bundle export, along with the generation time.
type bundleManifest struct {
	Fingerprints []string  `json:"fingerprints"`
	GeneratedAt  time.Time `json:"generated_at"`
	CertCount    int       `json:"cert_count"`
}

// TrustService errors.
var (
	// ErrNilTrustStore indicates the trust store has not been initialized.
	ErrNilTrustStore = errors.New("trust: store not initialized")

	// ErrImportCancelled indicates the user cancelled the import file dialog.
	ErrImportCancelled = errors.New("trust: import cancelled by user")
)

// TrustCertInfo is a JSON-friendly certificate representation for the frontend.
type TrustCertInfo struct {
	Fingerprint     string   `json:"fingerprint"`
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	Algorithm       string   `json:"algorithm"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	IsCA            bool     `json:"is_ca"`
	IsExpired       bool     `json:"is_expired"`
	Purpose         string   `json:"purpose"`
	Source          string   `json:"source"`
	Tags            []string `json:"tags"`
	SystemInstalled bool     `json:"system_installed"`
}

// BrowserBundleStatus describes the current state of the cached browser
// trust bundle on disk.
type BrowserBundleStatus struct {
	Exists        bool   `json:"exists"`
	Stale         bool   `json:"stale"`
	CertCount     int    `json:"cert_count"`
	LastGenerated string `json:"last_generated"`
	BundlePath    string `json:"bundle_path"`
}

// TrustService provides trust store operations for the GUI frontend.
type TrustService struct {
	ctx      context.Context
	log      *slog.Logger
	store    truststore.TrustStore
	elevator Elevator
	onMutate func() // called after trust store mutations (add/remove/import)
}

// NewTrustService creates a new TrustService.
func NewTrustService(store truststore.TrustStore) *TrustService {
	return &TrustService{
		log:   slog.Default().With("component", "trust_service"),
		store: store,
	}
}

// SetContext stores the Wails application context needed for native
// file dialogs and other runtime operations.
func (s *TrustService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetStore replaces the trust store. This is used for deferred initialization
// when the data directory is created after construction.
func (s *TrustService) SetStore(store truststore.TrustStore) {
	s.store = store
}

// SetOnMutate registers a callback that is invoked after trust store
// mutations (add, remove, import). Used by SecureBrowserService to
// trigger automatic browser certificate rebuilds.
func (s *TrustService) SetOnMutate(fn func()) {
	s.onMutate = fn
}

// notifyMutate calls the onMutate callback if registered.
func (s *TrustService) notifyMutate() {
	if s.onMutate != nil {
		s.onMutate()
	}
}

// SetElevator configures the privilege elevator used for operations
// that require root when the process is not running as root.
func (s *TrustService) SetElevator(e Elevator) {
	s.elevator = e
}

// ListCertificates returns all trusted certificates as JSON-friendly structs.
func (s *TrustService) ListCertificates() ([]TrustCertInfo, error) {
	if s.store == nil {
		return nil, nil
	}
	certs, err := s.store.Certificates()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	infos := make([]TrustCertInfo, 0, len(certs))
	for _, cert := range certs {
		info := TrustCertInfo{
			Fingerprint: truststore.Fingerprint(cert),
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			Algorithm:   cert.PublicKeyAlgorithm.String(),
			NotBefore:   cert.NotBefore.Format(time.RFC3339),
			NotAfter:    cert.NotAfter.Format(time.RFC3339),
			IsCA:        cert.IsCA,
			IsExpired:   now.After(cert.NotAfter),
		}

		meta, metaErr := s.store.Metadata(truststore.Fingerprint(cert))
		if metaErr == nil {
			info.Purpose = string(meta.Purpose)
			info.Source = meta.Source
			info.Tags = meta.Tags
			info.SystemInstalled = meta.SystemInstalled
		}

		infos = append(infos, info)
	}
	return infos, nil
}

// ListCertificatesByPurpose returns certificates matching the given purpose
// as JSON-friendly structs.
func (s *TrustService) ListCertificatesByPurpose(purpose string) ([]TrustCertInfo, error) {
	if s.store == nil {
		return nil, nil
	}

	certs, err := s.store.CertificatesByPurpose(truststore.CertPurpose(purpose))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	infos := make([]TrustCertInfo, 0, len(certs))
	for _, cert := range certs {
		info := TrustCertInfo{
			Fingerprint: truststore.Fingerprint(cert),
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			Algorithm:   cert.PublicKeyAlgorithm.String(),
			NotBefore:   cert.NotBefore.Format(time.RFC3339),
			NotAfter:    cert.NotAfter.Format(time.RFC3339),
			IsCA:        cert.IsCA,
			IsExpired:   now.After(cert.NotAfter),
		}

		meta, metaErr := s.store.Metadata(truststore.Fingerprint(cert))
		if metaErr == nil {
			info.Purpose = string(meta.Purpose)
			info.Source = meta.Source
			info.Tags = meta.Tags
			info.SystemInstalled = meta.SystemInstalled
		}

		infos = append(infos, info)
	}
	return infos, nil
}

// AddCertificatesPEM adds certificates from PEM data and returns the count added.
func (s *TrustService) AddCertificatesPEM(pemData string) (int, error) {
	if s.store == nil {
		return 0, nil
	}
	n, err := s.store.AddPEM([]byte(pemData))
	if err == nil && n > 0 {
		s.notifyMutate()
	}
	return n, err
}

// RemoveCertificate removes a certificate by fingerprint.
func (s *TrustService) RemoveCertificate(fingerprint string) error {
	if s.store == nil {
		return nil
	}
	err := s.store.RemoveCertificate(fingerprint)
	if err == nil {
		s.notifyMutate()
	}
	return err
}

// CertificateCount returns the number of trusted certificates.
func (s *TrustService) CertificateCount() (int, error) {
	if s.store == nil {
		return 0, nil
	}
	return s.store.Count()
}

// GetCertificatePEM returns a PEM-encoded string of the certificate
// matching the given fingerprint.
func (s *TrustService) GetCertificatePEM(fingerprint string) (string, error) {
	if s.store == nil {
		return "", ErrNilTrustStore
	}

	cert, err := s.findCertByFingerprint(fingerprint)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ImportCertificateFile opens a native file dialog for the user to select
// a certificate file (PEM or DER), reads it, and adds it to the trust store.
// Returns the number of certificates added. Returns 0, nil if the user
// cancels the dialog.
func (s *TrustService) ImportCertificateFile() (int, error) {
	if s.store == nil {
		return 0, ErrNilTrustStore
	}

	filePath, err := wailsruntime.OpenFileDialog(s.ctx, wailsruntime.OpenDialogOptions{
		Title: "Import Certificate",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "Certificates", Pattern: "*.pem;*.crt;*.cer;*.der"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return 0, err
	}

	// User cancelled the dialog.
	if filePath == "" {
		return 0, nil
	}

	data, err := os.ReadFile(filePath) // #nosec G304 -- user-selected file via native dialog
	if err != nil {
		return 0, err
	}

	// Detect PEM vs DER by checking for the PEM header.
	if strings.Contains(string(data), "BEGIN CERTIFICATE") {
		n, addErr := s.store.AddPEM(data)
		if addErr == nil && n > 0 {
			s.notifyMutate()
		}
		return n, addErr
	}

	// Treat as DER-encoded certificate.
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return 0, err
	}

	if err := s.store.AddCertificate(cert); err != nil {
		return 0, err
	}
	s.notifyMutate()
	return 1, nil
}

// ExportCertificatePEM returns the PEM-encoded certificate matching the
// given fingerprint. This is equivalent to GetCertificatePEM.
func (s *TrustService) ExportCertificatePEM(fingerprint string) (string, error) {
	return s.GetCertificatePEM(fingerprint)
}

// ExportCertificateDER returns the raw DER-encoded bytes of the certificate
// matching the given fingerprint.
func (s *TrustService) ExportCertificateDER(fingerprint string) ([]byte, error) {
	if s.store == nil {
		return nil, ErrNilTrustStore
	}

	cert, err := s.findCertByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// SetBrowserExport toggles whether a certificate is exported to the browser
// trust bundle. When enabled is true the TagBrowserExport tag is added to
// the certificate metadata; when false the tag is removed.
func (s *TrustService) SetBrowserExport(fingerprint string, enabled bool) error {
	if s.store == nil {
		return ErrNilTrustStore
	}

	meta, err := s.store.Metadata(fingerprint)
	if err != nil {
		return err
	}

	// Build new tags list, filtering out any existing browser-export tag.
	tags := make([]string, 0, len(meta.Tags)+1)
	for _, t := range meta.Tags {
		if t != TagBrowserExport {
			tags = append(tags, t)
		}
	}
	if enabled {
		tags = append(tags, TagBrowserExport)
	}

	return s.store.SetTags(fingerprint, tags)
}

// ExportBrowserTrustBundle writes all browser-exported certificates as a PEM
// bundle to the given path. Certificates with the TagBrowserExport tag and
// certificates with PurposeBootstrapCA are included automatically. Returns
// the number of certificates written. If no certificates qualify, any
// existing bundle file is removed.
func (s *TrustService) ExportBrowserTrustBundle(bundlePath string) (int, error) {
	if s.store == nil {
		return 0, ErrNilTrustStore
	}

	certs, err := s.store.Certificates()
	if err != nil {
		return 0, err
	}

	var pemData []byte
	count := 0

	for _, cert := range certs {
		fp := truststore.Fingerprint(cert)
		meta, metaErr := s.store.Metadata(fp)
		if metaErr != nil {
			continue
		}

		// Check for browser-export tag.
		exported := false
		for _, tag := range meta.Tags {
			if tag == TagBrowserExport {
				exported = true
				break
			}
		}

		// Also include bootstrap CA certificates by default.
		if !exported && meta.Purpose == truststore.PurposeBootstrapCA {
			exported = true
		}

		if exported {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			pemData = append(pemData, pem.EncodeToMemory(block)...)
			count++
		}
	}

	if count == 0 {
		// Remove stale bundle file if no certs are exported.
		_ = os.Remove(bundlePath)
		return 0, nil
	}

	dir := filepath.Dir(bundlePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrBrowserTrustBundleExport, err)
	}

	if err := os.WriteFile(bundlePath, pemData, 0o600); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrBrowserTrustBundleExport, err)
	}

	// Write manifest sidecar for staleness detection.
	manifest := bundleManifest{
		Fingerprints: s.eligibleFingerprints(),
		GeneratedAt:  time.Now().UTC(),
		CertCount:    count,
	}
	manifestData, marshalErr := json.MarshalIndent(manifest, "", "  ")
	if marshalErr == nil {
		manifestPath := filepath.Join(dir, browserBundleManifestFile)
		_ = os.WriteFile(manifestPath, manifestData, 0o600)
	}

	s.log.Info("exported browser trust bundle",
		"path", bundlePath,
		"certificates", count,
	)

	return count, nil
}

// GetBrowserBundleStatus returns the status of the cached browser trust
// bundle at the given path. It compares the manifest (if it exists) against
// the current set of export-eligible certificates to determine staleness.
func (s *TrustService) GetBrowserBundleStatus(bundlePath string) BrowserBundleStatus {
	status := BrowserBundleStatus{BundlePath: bundlePath}

	// Check if the PEM bundle exists on disk.
	info, err := os.Stat(bundlePath)
	if err != nil {
		return status
	}
	status.Exists = true
	status.LastGenerated = info.ModTime().Format(time.RFC3339)

	// Read the manifest sidecar.
	manifestPath := filepath.Join(filepath.Dir(bundlePath), browserBundleManifestFile)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		// No manifest means we can't determine staleness; assume stale.
		status.Stale = true
		return status
	}

	var manifest bundleManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		status.Stale = true
		return status
	}
	status.CertCount = manifest.CertCount
	status.LastGenerated = manifest.GeneratedAt.Format(time.RFC3339)

	// Compare manifest fingerprints to current eligible certificates.
	currentFPs := s.eligibleFingerprints()
	if len(currentFPs) != len(manifest.Fingerprints) {
		status.Stale = true
		return status
	}

	manifestSet := make(map[string]struct{}, len(manifest.Fingerprints))
	for _, fp := range manifest.Fingerprints {
		manifestSet[fp] = struct{}{}
	}
	for _, fp := range currentFPs {
		if _, ok := manifestSet[fp]; !ok {
			status.Stale = true
			return status
		}
	}

	return status
}

// SeedEmbeddedRoots adds embedded root certificates to the trust store for
// the given purpose. Returns the number of new certificates added. The
// operation is idempotent; certificates already in the store are skipped.
func (s *TrustService) SeedEmbeddedRoots(purpose string) (int, error) {
	if s.store == nil {
		return 0, nil
	}

	roots := truststore.LoadEmbeddedRoots(truststore.CertPurpose(purpose))
	if len(roots) == 0 {
		return 0, nil
	}

	added := 0
	for _, root := range roots {
		fp := truststore.Fingerprint(root)

		// Skip if already present.
		exists, err := s.store.Contains(fp)
		if err != nil {
			return added, err
		}
		if exists {
			continue
		}

		// Add with purpose and source metadata.
		if err := s.store.AddCertificateWithOptions(root, &truststore.AddCertificateOptions{
			Purpose: truststore.CertPurpose(purpose),
			Source:  "embedded",
		}); err != nil {
			return added, err
		}
		added++
	}
	if added > 0 {
		s.notifyMutate()
	}
	return added, nil
}

// InstallToSystem installs a certificate to the OS trust store using
// privilege elevation via sudo. The password is used to authenticate the
// sudo session and is zeroed from memory after use.
func (s *TrustService) InstallToSystem(fingerprint string, password string) error {
	if s.store == nil {
		return ErrNilTrustStore
	}

	s.log.Debug("InstallToSystem started", "fingerprint", fingerprint)

	// Verify the certificate exists in our store before requesting
	// privilege elevation. Fail fast with a clear error.
	if _, err := s.findCertByFingerprint(fingerprint); err != nil {
		return err
	}

	// Use sudo to invoke the CLI trust install command which is
	// self-contained: it opens the trust store, finds the cert by
	// fingerprint, writes it to the OS cert dir, and runs the
	// update command.
	elevator := NewSudoElevator(password)
	args := []string{"trust", "install", fingerprint}
	if _, err := elevator.Run(args, nil); err != nil {
		s.log.Debug("InstallToSystem failed",
			"fingerprint", fingerprint,
			"error", err)
		return err
	}

	s.log.Debug("InstallToSystem succeeded", "fingerprint", fingerprint)
	return s.store.SetSystemInstalled(fingerprint, true)
}

// RemoveFromSystem removes a certificate from the OS trust store using
// privilege elevation via sudo. The password is used to authenticate the
// sudo session and is zeroed from memory after use.
func (s *TrustService) RemoveFromSystem(fingerprint string, password string) error {
	if s.store == nil {
		return ErrNilTrustStore
	}

	// Verify the certificate exists in our store before requesting
	// privilege elevation.
	exists, err := s.store.Contains(fingerprint)
	if err != nil {
		return err
	}
	if !exists {
		return truststore.ErrCertificateNotFound
	}

	// Use sudo to invoke the CLI trust uninstall command which is
	// self-contained: it removes the file from the OS cert dir
	// and runs the update command.
	elevator := NewSudoElevator(password)
	args := []string{"trust", "uninstall", fingerprint}
	if _, err := elevator.Run(args, nil); err != nil {
		return err
	}

	return s.store.SetSystemInstalled(fingerprint, false)
}

// IsSystemInstalled checks if a certificate is installed in the OS trust store.
func (s *TrustService) IsSystemInstalled(fingerprint string) (bool, error) {
	if s.store == nil {
		return false, nil
	}

	label := "xkey-" + fingerprint[:16]

	osCertStore, err := truststore.NewOSCertStore()
	if err != nil {
		return false, err
	}

	return osCertStore.IsInstalled(label)
}

// AllCertificates returns all certificates from the trust store.
// Returns nil, ErrNilTrustStore if the trust store is not initialized.
func (s *TrustService) AllCertificates() ([]*x509.Certificate, error) {
	if s.store == nil {
		return nil, ErrNilTrustStore
	}
	return s.store.Certificates()
}

// eligibleFingerprints returns the sorted fingerprints of all certificates
// that qualify for browser trust bundle export (tagged browser-export or
// purpose bootstrap-ca).
func (s *TrustService) eligibleFingerprints() []string {
	if s.store == nil {
		return nil
	}

	certs, err := s.store.Certificates()
	if err != nil {
		return nil
	}

	var fps []string
	for _, cert := range certs {
		fp := truststore.Fingerprint(cert)
		meta, metaErr := s.store.Metadata(fp)
		if metaErr != nil {
			continue
		}

		eligible := false
		for _, tag := range meta.Tags {
			if tag == TagBrowserExport {
				eligible = true
				break
			}
		}
		if !eligible && meta.Purpose == truststore.PurposeBootstrapCA {
			eligible = true
		}

		if eligible {
			fps = append(fps, fp)
		}
	}

	sort.Strings(fps)
	return fps
}

// findCertByFingerprint iterates the store's certificates to find the one
// matching the given fingerprint.
func (s *TrustService) findCertByFingerprint(fingerprint string) (*x509.Certificate, error) {
	certs, err := s.store.Certificates()
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		if truststore.Fingerprint(cert) == fingerprint {
			return cert, nil
		}
	}

	return nil, truststore.ErrCertificateNotFound
}
