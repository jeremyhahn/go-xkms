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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Label validation tests
// ---------------------------------------------------------------------------

func TestValidateLabel_ValidLabels(t *testing.T) {
	tests := []struct {
		name  string
		label string
	}{
		{"hyphenated", "my-cert"},
		{"underscore", "ca_root"},
		{"alphanumeric", "TestCA123"},
		{"single char", "a"},
		{"mixed", "a-b_c"},
		{"digits only", "12345"},
		{"uppercase only", "ABCDEF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLabel(tt.label)
			if err != nil {
				t.Fatalf("validateLabel(%q) returned unexpected error: %v", tt.label, err)
			}
		})
	}
}

func TestValidateLabel_InvalidLabels(t *testing.T) {
	tests := []struct {
		name  string
		label string
	}{
		{"empty", ""},
		{"has space", "has space"},
		{"has slash", "has/slash"},
		{"has dot", "has.dot"},
		{"path traversal", "../path-traversal"},
		{"special at", "has@special"},
		{"special bang", "has!bang"},
		{"special colon", "host:port"},
		{"special equals", "key=value"},
		{"newline", "line\nbreak"},
		{"tab", "tab\there"},
		{"null byte", "null\x00byte"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLabel(tt.label)
			if err == nil {
				t.Fatalf("validateLabel(%q) expected error, got nil", tt.label)
			}
			if !errors.Is(err, ErrInvalidLabel) {
				t.Errorf("validateLabel(%q) error = %v, want ErrInvalidLabel", tt.label, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseOSRelease tests
// ---------------------------------------------------------------------------

func TestParseOSRelease_Ubuntu(t *testing.T) {
	content := `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
HOME_URL="https://www.ubuntu.com/"
`

	id, idLike := parseOSRelease(content)

	if id != "ubuntu" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "ubuntu")
	}
	if idLike != "debian" {
		t.Errorf("parseOSRelease() idLike = %q, want %q", idLike, "debian")
	}
}

func TestParseOSRelease_Fedora(t *testing.T) {
	content := `NAME="Fedora Linux"
ID=fedora
VERSION_ID="39"
`

	id, idLike := parseOSRelease(content)

	if id != "fedora" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "fedora")
	}
	if idLike != "" {
		t.Errorf("parseOSRelease() idLike = %q, want empty", idLike)
	}
}

func TestParseOSRelease_Comments(t *testing.T) {
	content := `# This is a comment
ID=arch
# Another comment
NAME="Arch Linux"
`

	id, _ := parseOSRelease(content)

	if id != "arch" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "arch")
	}
}

func TestParseOSRelease_EmptyContent(t *testing.T) {
	id, idLike := parseOSRelease("")

	if id != "" {
		t.Errorf("parseOSRelease(empty) id = %q, want empty", id)
	}
	if idLike != "" {
		t.Errorf("parseOSRelease(empty) idLike = %q, want empty", idLike)
	}
}

func TestParseOSRelease_EmptyLines(t *testing.T) {
	content := `ID=debian

NAME="Debian GNU/Linux"

VERSION_ID="12"
`

	id, _ := parseOSRelease(content)

	if id != "debian" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "debian")
	}
}

func TestParseOSRelease_SingleQuotedValues(t *testing.T) {
	content := `NAME='CentOS Stream'
ID=centos
`

	id, _ := parseOSRelease(content)

	if id != "centos" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "centos")
	}
}

func TestParseOSRelease_NoEqualsSign(t *testing.T) {
	content := `ID=debian
INVALID_LINE_WITHOUT_EQUALS
NAME="Debian"
`

	id, _ := parseOSRelease(content)

	if id != "debian" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "debian")
	}
}

func TestParseOSRelease_WhitespaceOnlyLines(t *testing.T) {
	content := "ID=debian\n   \n\t\nID_LIKE=\n"

	id, idLike := parseOSRelease(content)

	if id != "debian" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "debian")
	}
	if idLike != "" {
		t.Errorf("parseOSRelease() idLike = %q, want empty", idLike)
	}
}

func TestParseOSRelease_EmptyID(t *testing.T) {
	content := "ID=\nNAME=\"Debian\"\n"

	id, _ := parseOSRelease(content)

	if id != "" {
		t.Errorf("parseOSRelease() id = %q, want empty", id)
	}
}

func TestParseOSRelease_ValueWithEquals(t *testing.T) {
	content := `BUG_REPORT_URL="https://bugs.example.com/?product=linux&component=os"
ID=debian
`

	id, _ := parseOSRelease(content)

	if id != "debian" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "debian")
	}
}

func TestParseOSRelease_IDLikeMultipleValues(t *testing.T) {
	content := `ID=linuxmint
ID_LIKE="ubuntu debian"
`

	id, idLike := parseOSRelease(content)

	if id != "linuxmint" {
		t.Errorf("parseOSRelease() id = %q, want %q", id, "linuxmint")
	}
	if idLike != "ubuntu debian" {
		t.Errorf("parseOSRelease() idLike = %q, want %q", idLike, "ubuntu debian")
	}
}

// ---------------------------------------------------------------------------
// LinuxCertStore certPath tests
// ---------------------------------------------------------------------------

func TestLinuxCertStore_CertPath_Debian(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	got := store.certPath("my-cert")
	want := filepath.Join(certDir, "my-cert.crt")
	if got != want {
		t.Errorf("certPath(%q) = %q, want %q", "my-cert", got, want)
	}
}

func TestLinuxCertStore_CertPath_RedHat(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".pem", "echo", []string{"done"})

	got := store.certPath("my-cert")
	want := filepath.Join(certDir, "my-cert.pem")
	if got != want {
		t.Errorf("certPath(%q) = %q, want %q", "my-cert", got, want)
	}
}

func TestLinuxCertStore_CertPath_AllExtensions(t *testing.T) {
	tests := []struct {
		name    string
		certExt string
		label   string
		wantSfx string
	}{
		{"crt extension", ".crt", "my-cert", "my-cert.crt"},
		{"pem extension", ".pem", "my-cert", "my-cert.pem"},
		{"crt different label", ".crt", "root_ca", "root_ca.crt"},
		{"pem different label", ".pem", "root_ca", "root_ca.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certDir := t.TempDir()
			store := NewLinuxCertStoreWithDir(certDir, tt.certExt, "echo", nil)

			got := store.certPath(tt.label)
			want := filepath.Join(certDir, tt.wantSfx)
			if got != want {
				t.Errorf("certPath(%q) = %q, want %q", tt.label, got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// LinuxCertStore Install tests
// ---------------------------------------------------------------------------

func TestLinuxCertStore_Install_Success(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert := generateTestCert(t, "Install Test CA")

	err := store.Install(cert, "test-ca")
	if err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	// Verify the PEM file was written to disk.
	expectedPath := filepath.Join(certDir, "test-ca.crt")
	info, err := os.Stat(expectedPath)
	if err != nil {
		t.Fatalf("certificate file not created at %s: %v", expectedPath, err)
	}
	if info.Size() == 0 {
		t.Error("certificate file is empty")
	}

	// Verify the PEM content is valid and matches the original certificate.
	pemData, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM block from written file")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %q, want %q", block.Type, "CERTIFICATE")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate from PEM: %v", err)
	}
	if parsedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("parsed cert CN = %q, want %q", parsedCert.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestLinuxCertStore_Install_PEMExtension(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".pem", "echo", []string{"done"})

	cert := generateTestCert(t, "RedHat Install CA")

	err := store.Install(cert, "redhat-ca")
	if err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	// Should use .pem extension.
	expectedPath := filepath.Join(certDir, "redhat-ca.pem")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Fatalf("certificate file not created at %s: %v", expectedPath, err)
	}
}

func TestLinuxCertStore_Install_InvalidLabel(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert := generateTestCert(t, "Bad Label CA")

	tests := []struct {
		name  string
		label string
	}{
		{"empty", ""},
		{"slash", "has/slash"},
		{"dot", "has.dot"},
		{"space", "has space"},
		{"traversal", "../escape"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Install(cert, tt.label)
			if err == nil {
				t.Fatalf("Install() with label %q expected error, got nil", tt.label)
			}
			if !errors.Is(err, ErrInvalidLabel) {
				t.Errorf("Install() with label %q error = %v, want ErrInvalidLabel", tt.label, err)
			}
		})
	}
}

func TestLinuxCertStore_Install_NilCert(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	err := store.Install(nil, "valid-label")
	if err == nil {
		t.Fatal("Install(nil) expected error, got nil")
	}
	if !errors.Is(err, ErrInstallFailed) {
		t.Errorf("Install(nil) error = %v, want ErrInstallFailed", err)
	}
}

func TestLinuxCertStore_Install_ReadOnlyDir(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Make the cert directory read-only to force a write failure.
	os.Chmod(certDir, 0o500)
	t.Cleanup(func() { os.Chmod(certDir, 0o700) })

	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert := generateTestCert(t, "ReadOnly Dir CA")
	err := store.Install(cert, "readonly-test")
	if err == nil {
		t.Fatal("Install() with read-only dir expected error, got nil")
	}
	// Should get either ErrPermissionDenied or ErrInstallFailed depending on
	// which operation fails first.
	if !errors.Is(err, ErrInstallFailed) && !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("Install() with read-only dir error = %v, want ErrInstallFailed or ErrPermissionDenied", err)
	}
}

// ---------------------------------------------------------------------------
// LinuxCertStore Remove tests
// ---------------------------------------------------------------------------

func TestLinuxCertStore_Remove_Success(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert := generateTestCert(t, "Remove Test CA")

	// Install first.
	err := store.Install(cert, "remove-me")
	if err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	// Verify file exists.
	certPath := filepath.Join(certDir, "remove-me.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("certificate file not found before removal: %v", err)
	}

	// Remove.
	err = store.Remove("remove-me")
	if err != nil {
		t.Fatalf("Remove() returned unexpected error: %v", err)
	}

	// Verify file is gone.
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Error("certificate file still exists after Remove()")
	}
}

func TestLinuxCertStore_Remove_NotInstalled(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	err := store.Remove("nonexistent-cert")
	if err == nil {
		t.Fatal("Remove() for non-existent cert expected error, got nil")
	}
	if !errors.Is(err, ErrRemoveFailed) {
		t.Errorf("Remove() for non-existent cert error = %v, want ErrRemoveFailed", err)
	}
}

func TestLinuxCertStore_Remove_InvalidLabel(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	tests := []struct {
		name  string
		label string
	}{
		{"empty", ""},
		{"slash", "bad/label"},
		{"dot", "bad.label"},
		{"space", "bad label"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Remove(tt.label)
			if err == nil {
				t.Fatalf("Remove(%q) expected error, got nil", tt.label)
			}
			if !errors.Is(err, ErrInvalidLabel) {
				t.Errorf("Remove(%q) error = %v, want ErrInvalidLabel", tt.label, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// LinuxCertStore IsInstalled tests
// ---------------------------------------------------------------------------

func TestLinuxCertStore_IsInstalled_True(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert := generateTestCert(t, "IsInstalled Test CA")

	if err := store.Install(cert, "check-me"); err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	installed, err := store.IsInstalled("check-me")
	if err != nil {
		t.Fatalf("IsInstalled() returned unexpected error: %v", err)
	}
	if !installed {
		t.Error("IsInstalled() = false, want true for installed certificate")
	}
}

func TestLinuxCertStore_IsInstalled_False(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	installed, err := store.IsInstalled("not-installed")
	if err != nil {
		t.Fatalf("IsInstalled() returned unexpected error: %v", err)
	}
	if installed {
		t.Error("IsInstalled() = true, want false for non-existent certificate")
	}
}

func TestLinuxCertStore_IsInstalled_InvalidLabel(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	tests := []struct {
		name  string
		label string
	}{
		{"empty", ""},
		{"slash", "bad/label"},
		{"dot", "bad.label"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.IsInstalled(tt.label)
			if err == nil {
				t.Fatalf("IsInstalled(%q) expected error, got nil", tt.label)
			}
			if !errors.Is(err, ErrInvalidLabel) {
				t.Errorf("IsInstalled(%q) error = %v, want ErrInvalidLabel", tt.label, err)
			}
		})
	}
}

func TestLinuxCertStore_IsInstalled_AfterRemove(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert := generateTestCert(t, "Remove Then Check CA")

	if err := store.Install(cert, "remove-check"); err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	if err := store.Remove("remove-check"); err != nil {
		t.Fatalf("Remove() returned unexpected error: %v", err)
	}

	installed, err := store.IsInstalled("remove-check")
	if err != nil {
		t.Fatalf("IsInstalled() returned unexpected error: %v", err)
	}
	if installed {
		t.Error("IsInstalled() = true after Remove(), want false")
	}
}

// ---------------------------------------------------------------------------
// RefreshSystemStore tests
// ---------------------------------------------------------------------------

func TestLinuxCertStore_RefreshSystemStore_Success(t *testing.T) {
	certDir := t.TempDir()
	// Use "echo" as the update command -- it always succeeds.
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"refreshed"})

	err := store.RefreshSystemStore()
	if err != nil {
		t.Fatalf("RefreshSystemStore() returned unexpected error: %v", err)
	}
}

func TestLinuxCertStore_RefreshSystemStore_CommandNotFound(t *testing.T) {
	certDir := t.TempDir()
	// Use a non-existent command that will fail to execute.
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "/nonexistent/update-ca-certificates-fake", nil)

	err := store.RefreshSystemStore()
	if err == nil {
		t.Fatal("RefreshSystemStore() with non-existent command expected error, got nil")
	}
	if !errors.Is(err, ErrSystemStoreRefresh) {
		t.Errorf("RefreshSystemStore() error = %v, want ErrSystemStoreRefresh", err)
	}
}

func TestLinuxCertStore_RefreshSystemStore_CommandFails(t *testing.T) {
	certDir := t.TempDir()
	// Use "false" which always exits with code 1.
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "false", nil)

	err := store.RefreshSystemStore()
	if err == nil {
		t.Fatal("RefreshSystemStore() with failing command expected error, got nil")
	}
	if !errors.Is(err, ErrSystemStoreRefresh) {
		t.Errorf("RefreshSystemStore() error = %v, want ErrSystemStoreRefresh", err)
	}
}

// ---------------------------------------------------------------------------
// Install + RefreshSystemStore integration (within temp dir)
// ---------------------------------------------------------------------------

func TestLinuxCertStore_InstallAndRefresh(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"updated"})

	cert := generateTestCert(t, "Full Flow CA")

	// Install cert.
	if err := store.Install(cert, "full-flow"); err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	// Verify installed.
	installed, err := store.IsInstalled("full-flow")
	if err != nil {
		t.Fatalf("IsInstalled() returned unexpected error: %v", err)
	}
	if !installed {
		t.Error("IsInstalled() = false after Install(), want true")
	}

	// Refresh system store.
	if err := store.RefreshSystemStore(); err != nil {
		t.Fatalf("RefreshSystemStore() returned unexpected error: %v", err)
	}

	// Remove cert.
	if err := store.Remove("full-flow"); err != nil {
		t.Fatalf("Remove() returned unexpected error: %v", err)
	}

	// Verify removed.
	installed, err = store.IsInstalled("full-flow")
	if err != nil {
		t.Fatalf("IsInstalled() returned unexpected error: %v", err)
	}
	if installed {
		t.Error("IsInstalled() = true after Remove(), want false")
	}
}

// ---------------------------------------------------------------------------
// Multiple certificates
// ---------------------------------------------------------------------------

func TestLinuxCertStore_Install_MultipleCerts(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	labels := []string{"root-ca", "intermediate-ca", "signing-ca"}
	for _, label := range labels {
		cert := generateTestCert(t, "CA for "+label)
		if err := store.Install(cert, label); err != nil {
			t.Fatalf("Install(%q) returned unexpected error: %v", label, err)
		}
	}

	// Verify all are installed.
	for _, label := range labels {
		installed, err := store.IsInstalled(label)
		if err != nil {
			t.Fatalf("IsInstalled(%q) returned unexpected error: %v", label, err)
		}
		if !installed {
			t.Errorf("IsInstalled(%q) = false, want true", label)
		}
	}

	// Verify the correct number of files.
	entries, err := os.ReadDir(certDir)
	if err != nil {
		t.Fatalf("failed to read cert dir: %v", err)
	}
	if len(entries) != len(labels) {
		t.Errorf("cert dir has %d files, want %d", len(entries), len(labels))
	}
}

// ---------------------------------------------------------------------------
// Install overwrites existing file
// ---------------------------------------------------------------------------

func TestLinuxCertStore_Install_Overwrite(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	cert1 := generateTestCert(t, "First CA")
	cert2 := generateTestCert(t, "Second CA")

	// Install first cert.
	if err := store.Install(cert1, "overwrite-test"); err != nil {
		t.Fatalf("first Install() returned unexpected error: %v", err)
	}

	// Install second cert with the same label (should overwrite).
	if err := store.Install(cert2, "overwrite-test"); err != nil {
		t.Fatalf("second Install() returned unexpected error: %v", err)
	}

	// Verify the file contains the second certificate.
	certPath := filepath.Join(certDir, "overwrite-test.crt")
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if parsedCert.Subject.CommonName != "Second CA" {
		t.Errorf("overwritten cert CN = %q, want %q", parsedCert.Subject.CommonName, "Second CA")
	}
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestOSCertStoreInterfaceCompliance(t *testing.T) {
	// Verify LinuxCertStore implements OSCertStore at compile time.
	var _ OSCertStore = (*LinuxCertStore)(nil)
}

// ---------------------------------------------------------------------------
// Distro type string representation
// ---------------------------------------------------------------------------

func TestLinuxDistroValues(t *testing.T) {
	tests := []struct {
		distro linuxDistro
		want   string
	}{
		{distroDebian, "debian"},
		{distroRedHat, "redhat"},
		{distroArch, "arch"},
		{distroUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := string(tt.distro)
			if got != tt.want {
				t.Errorf("linuxDistro = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error type verification
// ---------------------------------------------------------------------------

func TestOSCertStoreErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrUnsupportedDistro", ErrUnsupportedDistro, "truststore: unsupported Linux distribution"},
		{"ErrInvalidLabel", ErrInvalidLabel, "truststore: invalid certificate label"},
		{"ErrSystemStoreRefresh", ErrSystemStoreRefresh, "truststore: system trust store refresh failed"},
		{"ErrInstallFailed", ErrInstallFailed, "truststore: certificate installation failed"},
		{"ErrRemoveFailed", ErrRemoveFailed, "truststore: certificate removal failed"},
		{"ErrPermissionDenied", ErrPermissionDenied, "truststore: permission denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error variable is nil")
			}
			if tt.err.Error() != tt.msg {
				t.Errorf("error message = %q, want %q", tt.err.Error(), tt.msg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Distro config map tests
// ---------------------------------------------------------------------------

func TestDistroConfigs_AllDistrosHaveConfig(t *testing.T) {
	distros := []linuxDistro{distroDebian, distroRedHat, distroArch}
	for _, d := range distros {
		cfg, ok := distroConfigs[d]
		if !ok {
			t.Errorf("distroConfigs missing entry for %q", d)
			continue
		}
		if cfg.certDir == "" {
			t.Errorf("distroConfigs[%q].certDir is empty", d)
		}
		if cfg.certExt == "" {
			t.Errorf("distroConfigs[%q].certExt is empty", d)
		}
		if cfg.updateCmd == "" {
			t.Errorf("distroConfigs[%q].updateCmd is empty", d)
		}
	}
}

func TestDistroDetectors_KnownIDs(t *testing.T) {
	tests := []struct {
		id   string
		want linuxDistro
	}{
		{"debian", distroDebian},
		{"ubuntu", distroDebian},
		{"mint", distroDebian},
		{"pop", distroDebian},
		{"fedora", distroRedHat},
		{"centos", distroRedHat},
		{"rhel", distroRedHat},
		{"rocky", distroRedHat},
		{"alma", distroRedHat},
		{"arch", distroArch},
		{"manjaro", distroArch},
		{"endeavouros", distroArch},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := distroDetectors[tt.id]
			if !ok {
				t.Fatalf("distroDetectors[%q] not found", tt.id)
			}
			if got != tt.want {
				t.Errorf("distroDetectors[%q] = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestIDLikeDetectors_KnownKeywords(t *testing.T) {
	tests := []struct {
		keyword string
		want    linuxDistro
	}{
		{"debian", distroDebian},
		{"rhel", distroRedHat},
		{"fedora", distroRedHat},
		{"arch", distroArch},
	}

	for _, tt := range tests {
		t.Run(tt.keyword, func(t *testing.T) {
			got, ok := idLikeDetectors[tt.keyword]
			if !ok {
				t.Fatalf("idLikeDetectors[%q] not found", tt.keyword)
			}
			if got != tt.want {
				t.Errorf("idLikeDetectors[%q] = %q, want %q", tt.keyword, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewLinuxCertStoreWithDir tests
// ---------------------------------------------------------------------------

func TestNewLinuxCertStoreWithDir(t *testing.T) {
	certDir := t.TempDir()
	store := NewLinuxCertStoreWithDir(certDir, ".crt", "echo", []string{"done"})

	if store.certDir != certDir {
		t.Errorf("certDir = %q, want %q", store.certDir, certDir)
	}
	if store.certExt != ".crt" {
		t.Errorf("certExt = %q, want %q", store.certExt, ".crt")
	}
	if store.updateCmd != "echo" {
		t.Errorf("updateCmd = %q, want %q", store.updateCmd, "echo")
	}
	if store.distro != distroUnknown {
		t.Errorf("distro = %q, want %q", store.distro, distroUnknown)
	}
}

// ---------------------------------------------------------------------------
// unquote tests
// ---------------------------------------------------------------------------

func TestUnquote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"double quoted", `"hello"`, "hello"},
		{"single quoted", `'hello'`, "hello"},
		{"no quotes", "hello", "hello"},
		{"empty", "", ""},
		{"single char", "a", "a"},
		{"mismatched quotes", `"hello'`, `"hello'`},
		{"only opening", `"hello`, `"hello`},
		{"empty double quoted", `""`, ""},
		{"empty single quoted", `''`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unquote(tt.input)
			if got != tt.want {
				t.Errorf("unquote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetDistroConfig tests
// ---------------------------------------------------------------------------

func TestGetDistroConfig_ReturnsConfig(t *testing.T) {
	cfg, err := GetDistroConfig()
	if err != nil {
		// On unknown CI distros, ErrUnsupportedDistro is acceptable.
		if errors.Is(err, ErrUnsupportedDistro) {
			t.Logf("GetDistroConfig() returned ErrUnsupportedDistro (acceptable on unknown distro): %v", err)
			return
		}
		t.Fatalf("GetDistroConfig() returned unexpected error: %v", err)
	}

	// If detection succeeded, all fields must be populated.
	if cfg.CertDir == "" {
		t.Error("GetDistroConfig().CertDir is empty")
	}
	if cfg.CertExt == "" {
		t.Error("GetDistroConfig().CertExt is empty")
	}
	if cfg.UpdateCmd == "" {
		t.Error("GetDistroConfig().UpdateCmd is empty")
	}
}

func TestGetDistroConfig_FieldsPopulated(t *testing.T) {
	cfg, err := GetDistroConfig()
	if err != nil {
		if errors.Is(err, ErrUnsupportedDistro) {
			t.Logf("GetDistroConfig() returned ErrUnsupportedDistro (acceptable on unknown distro): %v", err)
			return
		}
		t.Fatalf("GetDistroConfig() returned unexpected error: %v", err)
	}

	// CertDir must be an absolute path.
	if !strings.HasPrefix(cfg.CertDir, "/") {
		t.Errorf("GetDistroConfig().CertDir = %q, want path starting with /", cfg.CertDir)
	}

	// CertExt must start with a dot.
	if !strings.HasPrefix(cfg.CertExt, ".") {
		t.Errorf("GetDistroConfig().CertExt = %q, want extension starting with .", cfg.CertExt)
	}

	// UpdateCmd must be non-empty (already checked above, but verify the value
	// is one of the known update commands).
	if cfg.UpdateCmd != "update-ca-certificates" && cfg.UpdateCmd != "update-ca-trust" {
		t.Errorf("GetDistroConfig().UpdateCmd = %q, want update-ca-certificates or update-ca-trust", cfg.UpdateCmd)
	}
}
