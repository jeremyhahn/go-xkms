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

//go:build linux

package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// linuxDistro identifies a Linux distribution family for certificate
// management path and command resolution.
type linuxDistro string

const (
	distroDebian  linuxDistro = "debian"
	distroRedHat  linuxDistro = "redhat"
	distroArch    linuxDistro = "arch"
	distroUnknown linuxDistro = "unknown"
)

const (
	osCertFileMode = 0o644
	osCertDirMode  = 0o755
	osReleaseFile  = "/etc/os-release"
)

// labelPattern matches labels containing only alphanumeric characters,
// hyphens, and underscores.
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// distroConfig holds the filesystem paths and update commands for a
// Linux distribution family.
type distroConfig struct {
	certDir    string
	certExt    string
	updateCmd  string
	updateArgs []string
}

// distroConfigs provides O(1) lookup for distribution-specific certificate
// management configuration.
var distroConfigs = map[linuxDistro]*distroConfig{
	distroDebian: {
		certDir:    "/usr/local/share/ca-certificates/xkey",
		certExt:    ".crt",
		updateCmd:  "update-ca-certificates",
		updateArgs: nil,
	},
	distroRedHat: {
		certDir:    "/etc/pki/ca-trust/source/anchors",
		certExt:    ".pem",
		updateCmd:  "update-ca-trust",
		updateArgs: nil,
	},
	distroArch: {
		certDir:    "/etc/ca-certificates/trust-source/anchors",
		certExt:    ".pem",
		updateCmd:  "update-ca-trust",
		updateArgs: nil,
	},
}

// distroDetectors maps os-release ID values to their linuxDistro family.
// Used for direct ID= field matching.
var distroDetectors = map[string]linuxDistro{
	"debian":      distroDebian,
	"ubuntu":      distroDebian,
	"mint":        distroDebian,
	"pop":         distroDebian,
	"fedora":      distroRedHat,
	"centos":      distroRedHat,
	"rhel":        distroRedHat,
	"rocky":       distroRedHat,
	"alma":        distroRedHat,
	"arch":        distroArch,
	"manjaro":     distroArch,
	"endeavouros": distroArch,
}

// idLikeDetectors maps substrings found in the ID_LIKE= field to their
// linuxDistro family. Checked in order when direct ID matching fails.
var idLikeDetectors = map[string]linuxDistro{
	"debian": distroDebian,
	"rhel":   distroRedHat,
	"fedora": distroRedHat,
	"arch":   distroArch,
}

// DistroConfig holds exported distribution-specific certificate paths and commands.
type DistroConfig struct {
	CertDir    string
	CertExt    string
	UpdateCmd  string
	UpdateArgs []string
}

// GetDistroConfig detects the current Linux distribution and returns its
// certificate management configuration. Returns ErrUnsupportedDistro if
// the distribution cannot be identified.
func GetDistroConfig() (*DistroConfig, error) {
	distro, err := detectDistro()
	if err != nil {
		return nil, err
	}
	cfg, ok := distroConfigs[distro]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDistro, string(distro))
	}
	return &DistroConfig{
		CertDir:    cfg.certDir,
		CertExt:    cfg.certExt,
		UpdateCmd:  cfg.updateCmd,
		UpdateArgs: cfg.updateArgs,
	}, nil
}

// OSCertStore manages certificates in the operating system's trust store.
type OSCertStore interface {
	// Install installs a certificate into the OS trust store.
	// The label is used for the filename. Requires root/sudo privileges.
	Install(cert *x509.Certificate, label string) error

	// Remove removes a certificate from the OS trust store by label.
	Remove(label string) error

	// IsInstalled checks if a certificate with the given label is installed.
	IsInstalled(label string) (bool, error)

	// RefreshSystemStore runs the OS-specific command to rebuild the trust store.
	RefreshSystemStore() error
}

// LinuxCertStore implements OSCertStore for Linux distributions. It
// auto-detects the distribution family and uses the appropriate paths
// and commands for certificate management.
type LinuxCertStore struct {
	distro     linuxDistro
	certDir    string
	certExt    string
	updateCmd  string
	updateArgs []string
}

// NewLinuxCertStore creates a new LinuxCertStore that auto-detects the
// Linux distribution from /etc/os-release. Returns ErrUnsupportedDistro
// if the distribution cannot be identified.
func NewLinuxCertStore() (*LinuxCertStore, error) {
	distro, err := detectDistro()
	if err != nil {
		return nil, err
	}

	cfg, ok := distroConfigs[distro]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDistro, string(distro))
	}

	return &LinuxCertStore{
		distro:     distro,
		certDir:    cfg.certDir,
		certExt:    cfg.certExt,
		updateCmd:  cfg.updateCmd,
		updateArgs: cfg.updateArgs,
	}, nil
}

// NewLinuxCertStoreWithDir creates a LinuxCertStore with explicit paths
// and update command, bypassing auto-detection. This is useful for testing
// and custom configurations.
func NewLinuxCertStoreWithDir(certDir string, certExt string, updateCmd string, updateArgs []string) *LinuxCertStore {
	return &LinuxCertStore{
		distro:     distroUnknown,
		certDir:    certDir,
		certExt:    certExt,
		updateCmd:  updateCmd,
		updateArgs: updateArgs,
	}
}

// NewOSCertStore creates a new OSCertStore for the current platform.
// On Linux, this returns a LinuxCertStore with auto-detected distribution.
func NewOSCertStore() (OSCertStore, error) {
	return NewLinuxCertStore()
}

// Install installs a certificate into the OS trust store. The label is
// sanitized and used as the filename (without extension). The certificate
// is PEM-encoded and written to the distribution-specific certificate
// directory, followed by a trust store refresh.
func (s *LinuxCertStore) Install(cert *x509.Certificate, label string) error {
	if cert == nil {
		return fmt.Errorf("%w: certificate is nil", ErrInstallFailed)
	}

	if err := validateLabel(label); err != nil {
		return err
	}

	if err := os.MkdirAll(s.certDir, osCertDirMode); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return fmt.Errorf("%w: failed to create certificate directory: %v", ErrInstallFailed, err)
	}

	certPath := s.certPath(label)

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(block)

	if err := os.WriteFile(certPath, pemBytes, osCertFileMode); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return fmt.Errorf("%w: failed to write certificate: %v", ErrInstallFailed, err)
	}

	if err := s.RefreshSystemStore(); err != nil {
		// Clean up the written file on refresh failure.
		_ = os.Remove(certPath)
		return err
	}

	return nil
}

// Remove removes a certificate from the OS trust store by label. The
// certificate file is deleted from the distribution-specific directory,
// followed by a trust store refresh.
func (s *LinuxCertStore) Remove(label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}

	certPath := s.certPath(label)

	if err := os.Remove(certPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: certificate %q not found", ErrRemoveFailed, label)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
		}
		return fmt.Errorf("%w: %v", ErrRemoveFailed, err)
	}

	if err := s.RefreshSystemStore(); err != nil {
		return err
	}

	return nil
}

// IsInstalled checks if a certificate with the given label is installed
// in the OS trust store by verifying the certificate file exists.
func (s *LinuxCertStore) IsInstalled(label string) (bool, error) {
	if err := validateLabel(label); err != nil {
		return false, err
	}

	certPath := s.certPath(label)
	_, err := os.Stat(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	return true, nil
}

// RefreshSystemStore runs the distribution-specific command to rebuild
// the system certificate trust store.
func (s *LinuxCertStore) RefreshSystemStore() error {
	cmd := exec.Command(s.updateCmd, s.updateArgs...) // #nosec G204 -- trusted system command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s: %s", ErrSystemStoreRefresh, err.Error(), strings.TrimSpace(string(output)))
	}

	return nil
}

// certPath returns the full filesystem path for a certificate file with
// the given label.
func (s *LinuxCertStore) certPath(label string) string {
	return filepath.Join(s.certDir, label+s.certExt)
}

// validateLabel checks that a label contains only alphanumeric characters,
// hyphens, and underscores.
func validateLabel(label string) error {
	if !labelPattern.MatchString(label) {
		return fmt.Errorf("%w: label must contain only alphanumeric characters, hyphens, and underscores", ErrInvalidLabel)
	}
	return nil
}

// detectDistro reads /etc/os-release and determines the Linux distribution
// family by examining the ID= and ID_LIKE= fields.
func detectDistro() (linuxDistro, error) {
	data, err := os.ReadFile(osReleaseFile)
	if err != nil {
		return distroUnknown, fmt.Errorf("%w: failed to read %s: %v", ErrUnsupportedDistro, osReleaseFile, err)
	}

	id, idLike := parseOSRelease(string(data))

	// First, try direct ID match.
	if distro, ok := distroDetectors[id]; ok {
		return distro, nil
	}

	// Fall back to ID_LIKE substring matching.
	if idLike != "" {
		for keyword, distro := range idLikeDetectors {
			if strings.Contains(idLike, keyword) {
				return distro, nil
			}
		}
	}

	return distroUnknown, fmt.Errorf("%w: unrecognized distribution ID=%q ID_LIKE=%q", ErrUnsupportedDistro, id, idLike)
}

// parseOSRelease extracts the ID and ID_LIKE values from the contents
// of /etc/os-release. Values may be unquoted or quoted with single or
// double quotes.
func parseOSRelease(content string) (id string, idLike string) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		value = unquote(value)

		switch key {
		case "ID":
			id = strings.ToLower(value)
		case "ID_LIKE":
			idLike = strings.ToLower(value)
		}
	}

	return id, idLike
}

// unquote removes surrounding single or double quotes from a value.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
