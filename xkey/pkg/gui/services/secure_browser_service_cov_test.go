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
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockPath creates a regular file at path so that any directory the service
// tries to create beneath it fails.
func blockPath(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0o600))
}

func TestTargetNSSDBDirResolvesPerFamilyAndMode(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)

	dir, ok := svc.targetNSSDBDir(nativemsg.BrowserFirefox)
	assert.True(t, ok)
	assert.Equal(t, filepath.Join(baseDir, "firefox", "profile"), dir)

	config := svc.browserService.GetConfig()
	config.FirefoxProfileMode = ProfileModeShared
	require.NoError(t, svc.browserService.SetConfig(config))
	_, ok = svc.targetNSSDBDir(nativemsg.BrowserFirefox)
	assert.False(t, ok, "the user's own Firefox profile is never a sync target")

	_, ok = svc.targetNSSDBDir(nativemsg.Browser("lynx"))
	assert.False(t, ok)
}

func TestSyncChromeSharedModeWithoutHome(t *testing.T) {
	svc, _ := newTestSecureBrowserService(t, nil)
	setChromeMode(t, svc, ProfileModeShared)
	t.Setenv("HOME", "")

	err := svc.syncChrome([]*x509.Certificate{testSecureBrowserCA(t, "Chrome CA")})
	assert.ErrorIs(t, err, ErrSecureBrowserNSSDB)
	assert.ErrorIs(t, err, ErrSecureBrowserHomeDir)
}

func TestSyncChromeUncreatableNSSDB(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)
	blockPath(t, filepath.Join(baseDir, "chrome"))

	err := svc.syncChrome([]*x509.Certificate{testSecureBrowserCA(t, "Chrome CA")})
	assert.ErrorIs(t, err, ErrSecureBrowserNSSDB)
}

func TestSyncFirefoxSharedModeExportsWithoutTouchingProfile(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)
	config := svc.browserService.GetConfig()
	config.FirefoxProfileMode = ProfileModeShared
	require.NoError(t, svc.browserService.SetConfig(config))

	cert := testSecureBrowserCA(t, "Firefox CA")
	require.NoError(t, svc.syncFirefox([]*x509.Certificate{cert}))

	assert.FileExists(t, filepath.Join(baseDir, "firefox", "certs", certFingerprint(cert)+".pem"))
	assert.NoDirExists(t, filepath.Join(baseDir, "firefox", "profile"),
		"shared mode must not create or seed an isolated profile NSS DB")
}

func TestSyncFirefoxUncreatableCertsDir(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, nil)
	blockPath(t, filepath.Join(baseDir, "firefox"))

	err := svc.syncFirefox([]*x509.Certificate{testSecureBrowserCA(t, "Firefox CA")})
	assert.ErrorIs(t, err, ErrSecureBrowserCertExport)
}

func TestRebuildDoesNotRecordHashForFailedSyncs(t *testing.T) {
	svc, baseDir := newTestSecureBrowserService(t, []*x509.Certificate{testSecureBrowserCA(t, "Rebuild CA")})
	blockPath(t, filepath.Join(baseDir, "chrome"))
	blockPath(t, filepath.Join(baseDir, "firefox"))

	require.NoError(t, svc.Rebuild(), "per-family sync failures are logged, not returned")

	for _, family := range []nativemsg.Browser{nativemsg.BrowserChrome, nativemsg.BrowserFirefox} {
		_, err := svc.readTrustHash(family)
		assert.ErrorIs(t, err, ErrSecureBrowserHashRead, "a failed %s sync must not mark its store up to date", family)
	}
}

func TestBuildLaunchArgsIsolatedProfileUncreatable(t *testing.T) {
	for _, family := range []nativemsg.Browser{nativemsg.BrowserChrome, nativemsg.BrowserFirefox} {
		t.Run(string(family), func(t *testing.T) {
			svc, baseDir := newTestSecureBrowserService(t, nil)
			blockPath(t, filepath.Join(baseDir, string(family)))

			args, _, err := svc.buildLaunchArgs(family, ProfileModeIsolated, "/usr/bin/browser", "https://kms.example.com")
			assert.ErrorIs(t, err, ErrSecureBrowserLaunchFailed)
			assert.NotContains(t, args, "https://kms.example.com", "no URL is passed when the profile cannot be prepared")
		})
	}
}
