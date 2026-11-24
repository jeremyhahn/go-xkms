package services

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Setup records whether the barrier it initialized is bound to the user PIN,
// so a later PIN change knows whether to reseal it.
func TestSetupWizard_RecordsBarrierPINBinding(t *testing.T) {
	cases := []struct {
		name            string
		barrierPassword string
		wantBound       bool
	}{
		{name: "own barrier password", barrierPassword: "test-barrier-pw", wantBound: false},
		{name: "barrier on the user PIN", barrierPassword: "", wantBound: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tw := newTestSetupWizard(&GUIConfigData{})
			barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
			barrierSvc.SetContext(context.Background())
			tw.svc.SetBarrierService(barrierSvc)

			result, err := tw.svc.ApplySetup(&SetupChoices{
				Mode:            "standalone",
				SOPin:           testSOPin,
				UserPin:         testUserPin,
				StorageType:     "barrier",
				BarrierPassword: tc.barrierPassword,
				SealerBackend:   "passphrase",
			})
			require.NoError(t, err)
			require.NotNil(t, result)
			require.True(t, result.Success, "errors: %v", result.Errors)

			bound, known, err := barrierSvc.pinBinding()
			require.NoError(t, err)
			assert.True(t, known)
			assert.Equal(t, tc.wantBound, bound)
		})
	}
}
