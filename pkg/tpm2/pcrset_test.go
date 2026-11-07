package tpm2

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultPlatformPCRs(t *testing.T) {
	assert.Equal(t, PCRSet{7, 11}, DefaultPlatformPCRs())
	assert.NoError(t, DefaultPlatformPCRs().Validate())

	// Each call returns a fresh set, so a caller cannot edit the default.
	set := DefaultPlatformPCRs()
	set[0] = 0
	assert.Equal(t, PCRSet{7, 11}, DefaultPlatformPCRs())
}

func TestPCRSet_Validate_Refuses(t *testing.T) {
	tests := map[string]struct {
		set     PCRSet
		wantErr error
		wantPCR uint
	}{
		"debug PCR 16":               {set: PCRSet{7, 16}, wantErr: ErrPlatformPCRResettable, wantPCR: 16},
		"application support PCR 23": {set: PCRSet{23}, wantErr: ErrPlatformPCRResettable, wantPCR: 23},
		"index above 23":             {set: PCRSet{7, 24}, wantErr: ErrPlatformPCROutOfRange, wantPCR: 24},
		"duplicate":                  {set: PCRSet{7, 11, 7}, wantErr: ErrPlatformPCRDuplicate, wantPCR: 7},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := tt.set.Validate()
			require.ErrorIs(t, err, tt.wantErr)
			var pcrErr *PlatformPCRError
			require.True(t, errors.As(err, &pcrErr), "error %v must be a *PlatformPCRError", err)
			assert.Equal(t, tt.wantPCR, pcrErr.PCR)
			assert.Contains(t, err.Error(), tt.wantErr.Error())
		})
	}
}

func TestPCRSet_Validate_RefusesEmpty(t *testing.T) {
	assert.ErrorIs(t, PCRSet{}.Validate(), ErrPlatformPCRSetEmpty)
	assert.ErrorIs(t, PCRSet(nil).Validate(), ErrPlatformPCRSetEmpty)
}

func TestPCRSetFromSelection_OtherBankIgnored(t *testing.T) {
	sel := PolicyPCRSelection(tpm2.TPMAlgSHA1, 7, 11)
	assert.Empty(t, pcrSetFromSelection(sel, tpm2.TPMAlgSHA256))
	assert.Empty(t, pcrSetFromSelection(tpm2.TPMLPCRSelection{}, tpm2.TPMAlgSHA256))
}

func TestPCRSet_UnmarshalYAML(t *testing.T) {
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte("platform-pcrs: [7, 14]\n"), &cfg))
	assert.Equal(t, PCRSet{7, 14}, cfg.PlatformPCRs)

	var unset Config
	require.NoError(t, yaml.Unmarshal([]byte("hash: SHA-256\n"), &unset))
	assert.Nil(t, unset.PlatformPCRs, "an absent key leaves the set to NewTPM2's default")
}

func TestPCRSet_UnmarshalYAML_Refuses(t *testing.T) {
	tests := map[string]error{
		"platform-pcrs: [7, 16]\n": ErrPlatformPCRResettable,
		"platform-pcrs: [23]\n":    ErrPlatformPCRResettable,
		"platform-pcrs: [7, 24]\n": ErrPlatformPCROutOfRange,
		"platform-pcrs: [7, 7]\n":  ErrPlatformPCRDuplicate,
		"platform-pcrs: []\n":      ErrPlatformPCRSetEmpty,
	}
	for doc, want := range tests {
		var cfg Config
		err := yaml.Unmarshal([]byte(doc), &cfg)
		assert.ErrorIs(t, err, want, "document %q", doc)
		assert.Nil(t, cfg.PlatformPCRs, "a refused set must not be stored: %q", doc)
	}

	var cfg Config
	assert.Error(t, yaml.Unmarshal([]byte("platform-pcrs: seven\n"), &cfg))
}

func TestPCRSet_UnmarshalJSON(t *testing.T) {
	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(`{"platform_pcrs":[7,14]}`), &cfg))
	assert.Equal(t, PCRSet{7, 14}, cfg.PlatformPCRs)

	var set PCRSet
	require.NoError(t, json.Unmarshal([]byte(`null`), &set))
	assert.Nil(t, set, "JSON null leaves the set unset")
}

func TestPCRSet_UnmarshalJSON_Refuses(t *testing.T) {
	tests := map[string]error{
		`[7,16]`:  ErrPlatformPCRResettable,
		`[23]`:    ErrPlatformPCRResettable,
		`[24]`:    ErrPlatformPCROutOfRange,
		`[11,11]`: ErrPlatformPCRDuplicate,
		`[]`:      ErrPlatformPCRSetEmpty,
	}
	for doc, want := range tests {
		var set PCRSet
		err := json.Unmarshal([]byte(doc), &set)
		assert.ErrorIs(t, err, want, "document %s", doc)
		assert.Nil(t, set, "a refused set must not be stored: %s", doc)
	}

	var set PCRSet
	assert.Error(t, json.Unmarshal([]byte(`"7,11"`), &set))
}

// TestNewTPM2_RefusesInvalidPlatformPCRs verifies NewTPM2 refuses a bad
// sealing set before it opens any transport, and that an explicit empty set
// is refused rather than replaced by the default.
func TestNewTPM2_RefusesInvalidPlatformPCRs(t *testing.T) {
	tests := map[string]struct {
		set     PCRSet
		wantErr error
	}{
		"resettable PCR 16": {set: PCRSet{7, 16}, wantErr: ErrPlatformPCRResettable},
		"explicit empty":    {set: PCRSet{}, wantErr: ErrPlatformPCRSetEmpty},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig
			cfg.PlatformPCRs = tt.set
			tpm, err := NewTPM2(&Params{Config: &cfg})
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, tpm)
		})
	}
}
