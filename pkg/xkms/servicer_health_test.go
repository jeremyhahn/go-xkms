package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealth_Success(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	status, version, err := svc.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", status)
	assert.NotEmpty(t, version)
}

func TestHealth_VersionNonEmpty(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, version, err := svc.Health(context.Background())
	require.NoError(t, err)
	// Version comes from the VERSION file; should be a semver-like string or "unknown"
	assert.NotEqual(t, "", version)
}
