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

package main

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACMELintConfigDefaultsToPrivatePKI(t *testing.T) {
	got := acmeLintConfig(&config.ACMELintConfig{})

	assert.Equal(t, linter.PrivatePKIConfig(), got)
	_, err := linter.New(got)
	require.NoError(t, err)
}

func TestACMELintConfigAddsOperatorExclusions(t *testing.T) {
	got := acmeLintConfig(&config.ACMELintConfig{
		ExcludeLints:   []string{"w_subject_common_name_included"},
		ExcludeSources: []string{"Mozilla"},
	})

	assert.Subset(t, got.ExcludeLints, linter.PrivatePKIConfig().ExcludeLints)
	assert.Contains(t, got.ExcludeLints, "w_subject_common_name_included")
	assert.Equal(t, []string{"Mozilla"}, got.ExcludeSources)
	_, err := linter.New(got)
	require.NoError(t, err)
}

func TestACMELintConfigUnknownLintStopsStartup(t *testing.T) {
	_, err := linter.New(acmeLintConfig(&config.ACMELintConfig{ExcludeLints: []string{"e_no_such_lint"}}))

	require.ErrorIs(t, err, linter.ErrConfig)
}
