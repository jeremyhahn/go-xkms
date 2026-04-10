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

package manager

import (
	"os"
	"path/filepath"
	"runtime"
)

// CommonModulePaths contains well-known PKCS#11 module paths by platform.
var CommonModulePaths = map[string][]string{
	"linux": {
		// xkey/xkms PKCS#11 modules
		"/usr/lib/libxkey.so",
		"/usr/lib/x86_64-linux-gnu/libxkey.so",
		"/usr/local/lib/libxkey.so",
		"/usr/lib/libxkms.so",
		"/usr/lib/x86_64-linux-gnu/libxkms.so",
		"/usr/local/lib/libxkms.so",
		// SoftHSM2
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		// OpenSC
		"/usr/lib/opensc-pkcs11.so",
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
		"/usr/lib/pkcs11/opensc-pkcs11.so",
		// YubiKey
		"/usr/lib/libykcs11.so",
		"/usr/lib/x86_64-linux-gnu/libykcs11.so",
		"/usr/lib64/libykcs11.so",
		"/usr/local/lib/libykcs11.so",
		// Nitrokey
		"/usr/lib/libnitrokey.so",
		// eToken/SafeNet
		"/usr/lib/libeToken.so",
		"/usr/lib/libeTPkcs11.so",
	},
	"darwin": {
		// xkey/xkms PKCS#11 modules
		"/usr/local/lib/libxkey.dylib",
		"/opt/homebrew/lib/libxkey.dylib",
		"/usr/local/lib/libxkms.dylib",
		"/opt/homebrew/lib/libxkms.dylib",
		// SoftHSM2
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
		// OpenSC
		"/Library/OpenSC/lib/opensc-pkcs11.so",
		"/usr/local/lib/opensc-pkcs11.so",
		// YubiKey
		"/usr/local/lib/libykcs11.dylib",
		"/opt/homebrew/lib/libykcs11.dylib",
	},
	"windows": {
		// xkey/xkms PKCS#11 modules
		"C:\\Program Files\\xkey\\libxkey.dll",
		"C:\\Program Files\\xkms\\libxkms.dll",
		// SoftHSM2
		"C:\\SoftHSM2\\lib\\softhsm2.dll",
		"C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
		// OpenSC
		"C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
		// YubiKey
		"C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll",
	},
}

// ProbeModulePaths detects available PKCS#11 modules on the system.
// It checks common installation paths for the current platform and returns
// paths that exist as files.
func ProbeModulePaths() []string {
	platform := runtime.GOOS
	paths, ok := CommonModulePaths[platform]
	if !ok {
		return nil
	}

	var found []string
	for _, path := range paths {
		if fileExists(path) {
			found = append(found, path)
		}
	}

	return found
}

// ProbeModulesWithNames returns detected modules with suggested display names.
func ProbeModulesWithNames() []ModuleProbe {
	platform := runtime.GOOS
	paths, ok := CommonModulePaths[platform]
	if !ok {
		return nil
	}

	var found []ModuleProbe
	for _, path := range paths {
		if fileExists(path) {
			found = append(found, ModuleProbe{
				LibraryPath: path,
				DisplayName: suggestModuleName(path),
			})
		}
	}

	return found
}

// ModuleProbe represents a detected PKCS#11 module.
type ModuleProbe struct {
	LibraryPath string `json:"library_path"`
	DisplayName string `json:"display_name"`
}

// suggestModuleName generates a human-readable name from a library path.
func suggestModuleName(path string) string {
	base := filepath.Base(path)

	// Remove common prefixes and extensions
	name := base
	for _, prefix := range []string{"lib", "pkcs11-"} {
		if len(name) > len(prefix) && name[:len(prefix)] == prefix {
			name = name[len(prefix):]
		}
	}
	for _, ext := range []string{".so", ".dylib", ".dll"} {
		if idx := findString(name, ext); idx > 0 {
			name = name[:idx]
			break
		}
	}

	// Map known names to friendly names
	friendlyNames := map[string]string{
		"xkey":          "xkey PKCS#11",
		"xkms":          "xkms PKCS#11",
		"softhsm2":      "SoftHSM2",
		"softhsm":       "SoftHSM",
		"opensc-pkcs11": "OpenSC",
		"opensc":        "OpenSC",
		"ykcs11":        "YubiKey",
		"nitrokey":      "Nitrokey",
		"eToken":        "SafeNet eToken",
		"eTPkcs11":      "SafeNet eToken",
	}

	if friendly, ok := friendlyNames[name]; ok {
		return friendly
	}

	return name
}

// findString finds the index of needle in haystack, returns -1 if not found.
func findString(haystack, needle string) int {
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// fileExists checks if a file exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// DeriveModuleID generates a module ID from a library path.
// For example, "/usr/lib/libykcs11.so" becomes "pkcs11-libykcs11".
func DeriveModuleID(libraryPath string) string {
	base := filepath.Base(libraryPath)
	// Strip common library extensions.
	for _, ext := range []string{".so", ".dylib", ".dll"} {
		if idx := findString(base, ext); idx > 0 {
			base = base[:idx]
			break
		}
	}
	return "pkcs11-" + base
}
