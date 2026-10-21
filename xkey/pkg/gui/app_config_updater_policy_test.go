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

package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// TestApp_UpdateConfig_EnterpriseLockedAutoFillPolicyNotApplied verifies a
// settings change carrying an autofill policy is saved, but the running
// autofill service keeps its policy when the enterprise policy forbids the
// user from configuring the extension.
func TestApp_UpdateConfig_EnterpriseLockedAutoFillPolicyNotApplied(t *testing.T) {
	app := newWiredApp(t)
	logs := captureLog(app)
	app.autofillService.SetEnterprisePolicy(&services.EnterpriseExtensionPolicy{
		Enabled:          true,
		UserCanConfigure: false,
	})
	running := app.autofillService.GetPolicy()
	policy := xkmssdk.DefaultAutoFillPolicy()
	policy.MaxFillsPerMinute = 7

	data := app.appService.GetConfig()
	data.AutoFillPolicy = policy
	require.NoError(t, app.appService.UpdateConfig(data))

	assert.Same(t, running, app.autofillService.GetPolicy(), "a locked extension policy must not be replaced")
	assert.Same(t, policy, app.config.AutoFillPolicy, "the saved configuration still records the request")
	assert.True(t, logs.Contains("failed to apply updated autofill policy"))
	assert.True(t, logs.Contains("enterprise policy prevents enabling extension"))
}
