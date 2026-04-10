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

package pkcs11mgr

import (
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithRegistry(t *testing.T) {
	t.Parallel()

	registry := backendregistry.NewMemoryRegistry()
	opt := WithRegistry(registry)
	require.NotNil(t, opt)

	o := &options{}
	opt(o)
	assert.Equal(t, registry, o.registry)
}

func TestWithRegistry_Nil(t *testing.T) {
	t.Parallel()

	opt := WithRegistry(nil)
	o := &options{}
	opt(o)
	assert.Nil(t, o.registry)
}

func TestWithLogger(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	opt := WithLogger(logger)
	require.NotNil(t, opt)

	o := &options{}
	opt(o)
	assert.Equal(t, logger, o.logger)
}

func TestWithLogger_Nil(t *testing.T) {
	t.Parallel()

	opt := WithLogger(nil)
	o := &options{}
	opt(o)
	assert.Nil(t, o.logger)
}

func TestOptions_DefaultValues(t *testing.T) {
	t.Parallel()

	o := &options{}
	assert.Nil(t, o.registry)
	assert.Nil(t, o.logger)
}

func TestOptions_MultipleApply(t *testing.T) {
	t.Parallel()

	registry := backendregistry.NewMemoryRegistry()
	logger := slog.Default()

	opts := []Option{
		WithRegistry(registry),
		WithLogger(logger),
	}

	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	assert.Equal(t, registry, o.registry)
	assert.Equal(t, logger, o.logger)
}
