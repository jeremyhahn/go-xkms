// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package xkms

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
)

func TestSubsystem_ZeroValueHoldsNothing(t *testing.T) {
	var manager subsystem[*tpmpolicy.Service]
	assert.Nil(t, manager.load())

	var reader subsystem[io.Reader]
	assert.Nil(t, reader.load(), "an interface subsystem that was never stored loads a nil interface")
}

func TestSubsystem_LoadReturnsTheLatestStore(t *testing.T) {
	var reader subsystem[io.Reader]
	first := strings.NewReader("first")
	second := strings.NewReader("second")

	reader.store(first)
	assert.Same(t, first, reader.load())

	reader.store(second)
	assert.Same(t, second, reader.load())

	reader.store(nil)
	assert.Nil(t, reader.load(), "storing nil unwires the subsystem")
}
