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
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunBarrierInit_UnresolvableHomeIsError(t *testing.T) {
	assertBarrierRunnerReportsUnresolvableHome(t, runBarrierInit)
}

func TestRunBarrierInit_InvalidCloudKMSSettingsStopBeforeTouchingDisk(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStrategy = "aws_kms"
	setBarrierFlagForTest(t, &loadedConfig, &config.Config{})
	setBarrierFlagForTest(t, &barrierAWSRegion, "")

	out, err := runBarrierCmd(t, runBarrierInit)
	require.ErrorIs(t, err, config.ErrBarrierCloudKMSConfigInvalid)
	assert.NotContains(t, out, "Barrier initialized successfully.")
	assert.False(t, barrierRootKeyExists(dir), "invalid settings must not leave a root key behind")
}
