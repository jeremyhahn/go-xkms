package cmd

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// c704cLauncher stands in for the secure browser service.
type c704cLauncher struct {
	detected  []services.BrowserInfo
	result    *services.LaunchResult
	err       error
	path, url string
	opts      services.LaunchOptions
	launches  int
}

func (l *c704cLauncher) DetectBrowsers() []services.BrowserInfo { return l.detected }

func (l *c704cLauncher) LaunchBrowserWithOptions(path, url string, opts services.LaunchOptions) (*services.LaunchResult, error) {
	l.launches++
	l.path, l.url, l.opts = path, url, opts
	return l.result, l.err
}

// c704cBrowserLauncher routes browser launch through a fake service.
func c704cBrowserLauncher(t *testing.T) *c704cLauncher {
	t.Helper()
	c704cBrowserHome(t)
	launcher := &c704cLauncher{result: &services.LaunchResult{Family: "chrome", Mode: services.ProfileModeIsolated, CertCount: 2}}
	saved := newSecureBrowser
	newSecureBrowser = func(string, *services.BrowserService, *services.TrustService, *slog.Logger) secureBrowser {
		return launcher
	}
	t.Cleanup(func() { newSecureBrowser = saved })
	return launcher
}

func TestC704cBrowserLaunch_AutoDetectsAndLaunches(t *testing.T) {
	launcher := c704cBrowserLauncher(t)
	launcher.detected = []services.BrowserInfo{{Name: "Chromium", Path: "/usr/bin/chromium"}}

	cmd, out := c704cBrowserCmd(t, "")
	require.NoError(t, runBrowserLaunch(cmd, nil))
	assert.Equal(t, "/usr/bin/chromium", launcher.path)
	assert.Equal(t, "about:blank", launcher.url, "no URL argument opens a blank page")
	assert.Contains(t, out.String(), "Auto-detected: Chromium (/usr/bin/chromium)")
	assert.Contains(t, out.String(), "Launched chrome (isolated mode, 2 certificates)\n")
}

func TestC704cBrowserLaunch_ReportsImportedExtensions(t *testing.T) {
	launcher := c704cBrowserLauncher(t)
	launcher.result.ExtensionsImported = 3
	saved := browserInclExts
	browserInclExts = true
	t.Cleanup(func() { browserInclExts = saved })

	cmd, out := c704cBrowserCmd(t, "/opt/chrome/chrome")
	require.NoError(t, runBrowserLaunch(cmd, []string{"https://example.test/"}))
	assert.Equal(t, "https://example.test/", launcher.url)
	assert.True(t, launcher.opts.IncludeExtensions)
	assert.Contains(t, out.String(), "Launched chrome (isolated mode, 2 certificates, 3 extensions)")
}

func TestC704cBrowserLaunch_Failures(t *testing.T) {
	t.Run("no browser installed", func(t *testing.T) {
		launcher := c704cBrowserLauncher(t)

		cmd, _ := c704cBrowserCmd(t, "")
		require.ErrorIs(t, runBrowserLaunch(cmd, nil), ErrBrowserNoBrowsers)
		assert.Zero(t, launcher.launches)
	})
	t.Run("launch refused", func(t *testing.T) {
		launcher := c704cBrowserLauncher(t)
		launcher.err = services.ErrSecureBrowserLaunchFailed

		cmd, out := c704cBrowserCmd(t, "/opt/chrome/chrome")
		err := runBrowserLaunch(cmd, nil)
		require.ErrorIs(t, err, ErrBrowserLaunchFailed)
		require.ErrorIs(t, err, services.ErrSecureBrowserLaunchFailed)
		assert.NotContains(t, out.String(), "Launched")
	})
}
