//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
)

func TestProvisionOwner(t *testing.T) {

	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	ssrkAttrs, err := tpm.SSRKAttributes()
	assert.Nil(t, err)

	iakAttrs, err := tpm.IAKAttributes()
	assert.Nil(t, err)

	store.DebugKeyAttributes(logger, ekAttrs)
	store.DebugKeyAttributes(logger, ssrkAttrs)
	store.DebugKeyAttributes(logger, iakAttrs)
}

func TestSetHierarchyAuth(t *testing.T) {

	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	password := store.NewClearPassword([]byte("test"))
	err = tpm.SetHierarchyAuth(hierarchyAuth, password, nil)

	assert.Nil(t, err)
}

func TestGoldenMeasurements(t *testing.T) {

	logger, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	goldenPCR := tpm.GoldenMeasurements()
	assert.NotNil(t, goldenPCR)

	logger.Debugf("Golden PCR: 0x%s", Encode(goldenPCR))
}
