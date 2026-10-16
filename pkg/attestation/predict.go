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

package attestation

import (
	"bytes"
	"crypto"
	"maps"
	"slices"
	"strconv"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// predictHash maps each PCR bank PredictPCRs predicts to its hash.
var predictHash = map[tpm2.TPMAlgID]crypto.Hash{
	tpm2.TPMAlgSHA256: crypto.SHA256,
	tpm2.TPMAlgSHA384: crypto.SHA384,
	tpm2.TPMAlgSHA512: crypto.SHA512,
}

// PredictPCRs predicts the values PCRs will hold once the images a
// reference-value manifest describes are installed. current holds the live
// values of bank's PCRs, and its keys select the PCRs to predict.
//
// A PCR the manifest states a final value for takes that value. A PCR the
// manifest names a component of is predicted by replaying log with each
// component's digest extended in place of the event it replaces; the log must
// first reproduce the PCR's live value, so a prediction never rests on a log
// that does not describe this platform. Any other selected PCR keeps its live
// value. The manifest must cover at least one selected PCR, and state either
// one final value or components for a PCR, never both.
func PredictPCRs(log *evidence.EventLog, m *refvalue.Manifest, bank tpm2.TPMAlgID, current map[int][]byte) (map[int][]byte, error) {
	hash, ok := predictHash[bank]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedPCRBank, Detail: "0x" + strconv.FormatUint(uint64(bank), 16)}
	}
	finals, err := m.PCRDigests(hash)
	if err != nil {
		return nil, err
	}
	components, err := m.ComponentDigests(hash)
	if err != nil {
		return nil, err
	}

	componentPCRs := make(map[int]bool, len(components))
	var subs []evidence.Substitution
	for _, c := range components {
		if _, selected := current[c.PCR]; !selected {
			continue
		}
		componentPCRs[c.PCR] = true
		subs = append(subs, evidence.Substitution{PCR: c.PCR, Ordinal: c.Ordinal, Digest: c.Digest})
	}

	predicted := make(map[int][]byte, len(current))
	live := make(map[int][]byte, len(componentPCRs))
	covered := false
	for _, pcr := range slices.Sorted(maps.Keys(current)) {
		values, final := finals[pcr]
		switch {
		case final && componentPCRs[pcr]:
			return nil, &errs.Detail{Err: ErrConflictingReference, Detail: "PCR " + strconv.Itoa(pcr)}
		case final && len(values) > 1:
			return nil, &errs.Detail{Err: ErrAmbiguousReference, Detail: "PCR " + strconv.Itoa(pcr)}
		case final:
			predicted[pcr] = values[0]
			covered = true
		case componentPCRs[pcr]:
			live[pcr] = current[pcr]
			covered = true
		default:
			predicted[pcr] = bytes.Clone(current[pcr])
		}
	}
	if !covered {
		return nil, ErrNoReferencedPCR
	}
	if len(subs) == 0 {
		return predicted, nil
	}

	if err := evidence.VerifyEventLog(log, bank, live); err != nil {
		return nil, err
	}
	replayed, err := log.ReplayWith(bank, subs)
	if err != nil {
		return nil, err
	}
	for pcr := range live {
		predicted[pcr] = replayed[pcr]
	}
	return predicted, nil
}
