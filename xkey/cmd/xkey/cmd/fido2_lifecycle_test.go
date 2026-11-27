// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package cmd

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

var errTestNotifierClose = errors.New("notifier close failed")

// closeFailingNotifier is a notify.Notifier whose Close always fails, so
// fido2Device.Close's error aggregation can be observed.
type closeFailingNotifier struct{}

func (closeFailingNotifier) NotifyTouchRequired(*notify.TouchRequest) error { return nil }
func (closeFailingNotifier) Close() error                                   { return errTestNotifierClose }

func TestCreateNotifier_SelectsByType(t *testing.T) {
	logger := discardLogger()

	none, err := createNotifier(&FIDO2Config{NotifyType: "none"}, logger)
	require.NoError(t, err)
	assert.IsType(t, &notify.MultiNotifier{}, none)

	logOnly, err := createNotifier(&FIDO2Config{NotifyType: "log"}, logger)
	require.NoError(t, err)
	assert.IsType(t, &notify.LogNotifier{}, logOnly)

	command, err := createNotifier(&FIDO2Config{NotifyType: "dialog", NotifyCommand: "notify-send xkey"}, logger)
	require.NoError(t, err)
	assert.IsType(t, &notify.MultiNotifier{}, command)

	unknown, err := createNotifier(&FIDO2Config{NotifyType: "carrier-pigeon"}, logger)
	require.NoError(t, err)
	assert.IsType(t, &notify.MultiNotifier{}, unknown)
}

func TestCreateNotifier_RejectsInvalidCommand(t *testing.T) {
	_, err := createNotifier(&FIDO2Config{NotifyType: "dialog", NotifyCommand: "   "}, discardLogger())
	require.ErrorIs(t, err, ErrFIDO2InvalidNotifyCommand)
}

func TestFido2DeviceClose_ReleasesSubsystems(t *testing.T) {
	store, err := openPasswordStore(t.TempDir())
	require.NoError(t, err)

	device := &fido2Device{
		cfg:      &FIDO2Config{},
		logger:   discardLogger(),
		pwStore:  store,
		notifier: notify.NewLogNotifier(discardLogger()),
	}
	socketDir := privateTempDir(t)
	server, err := ipc.NewServer(filepath.Join(socketDir, "fido2.sock"), device, discardLogger())
	require.NoError(t, err)
	device.ipcServer = server

	require.NoError(t, device.Close())
	assert.Nil(t, device.ipcServer)
	assert.Nil(t, device.pwStore)
	assert.Nil(t, device.notifier)

	require.NoError(t, device.Close(), "a second Close must be a no-op")
}

func TestFido2DeviceClose_JoinsErrorsAndKeepsClosing(t *testing.T) {
	store, err := openPasswordStore(t.TempDir())
	require.NoError(t, err)

	device := &fido2Device{
		logger:   discardLogger(),
		pwStore:  store,
		notifier: closeFailingNotifier{},
	}

	require.ErrorIs(t, device.Close(), errTestNotifierClose)
	assert.Nil(t, device.pwStore, "a failing notifier must not stop the password store closing")
	assert.Nil(t, device.notifier)
}
