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

package handlers

import (
	"bytes"
	"context"
	"sort"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// What the validated challenge decides (go-xkms#789, #1391, #1392)
//
// A permanent-identifier order can be finalized three ways, and each is only
// sound for an order its own challenge validated:
//
//   - a TCG-CSR-IDEVID, for an enroll-01 order. The credential activation
//     proved a TPM holds the endorsement key and activation key the CSR must
//     then be built around (bindEnrollActivation);
//   - an EK-certificate request, for an endorse-01 order. EAB authorized the
//     account to be given a certificate for the identifier's key; nothing proved
//     the account holds it, so this is the ONLY thing such an order may become;
//   - a standard certificate request, for a device-attest-01 order, whose key
//     must be the attested key (bindDeviceAttestationKey).
//
// What an order is was once inferred from its request, or from the bytes of its
// identifier, and a request of one kind was then honored for an order another
// kind of challenge validated: an endorse-01 authorization could finalize a
// TCG-CSR and be issued an IDevID, or a device-attest-01 authorization an EK
// certificate. The validated challenge decides instead. An order whose
// attestation authorizations were validated by anything but the challenge the
// request belongs to is refused.

// validatedAttestations holds the attestation challenges that validated an
// order's permanent-identifier and ip authorizations, by challenge type.
type validatedAttestations struct {
	challenges map[string][]*entities.ACMEChallenge
}

// deviceChallengeTypes are the challenge types that authorize a device
// rather than a name.
var deviceChallengeTypes = map[string]struct{}{
	common.ChallengeTypeEnroll01:       {},
	common.ChallengeTypeEndorse01:      {},
	common.ChallengeTypeDeviceAttest01: {},
}

// validatedAttestations returns the attestation challenges that validated the
// order's permanent-identifier and ip authorizations. A dns authorization is
// not a device's and is not read; an authorization the order references that
// storage does not hold refuses the request (orderAuthorizations).
func (s *RestService) validatedAttestations(
	ctx context.Context,
	authzDAO qrdbsdk.GenericDAO[*entities.ACMEAuthorization],
	order *entities.ACMEOrder,
) (*validatedAttestations, *entities.Error) {

	authzs, problem := s.orderAuthorizations(ctx, authzDAO, order)
	if problem != nil {
		return nil, problem
	}

	validated := &validatedAttestations{challenges: make(map[string][]*entities.ACMEChallenge)}
	for _, authz := range authzs {
		if authz.Identifier.Type != common.AuthzTypePermanentIdentifier && authz.Identifier.Type != common.AuthzTypeIP {
			continue
		}
		for i := range authz.Challenges {
			challenge := &authz.Challenges[i]
			if challenge.Status != common.StatusValid {
				continue
			}
			if _, attestation := deviceChallengeTypes[challenge.Type]; !attestation {
				continue
			}
			validated.challenges[challenge.Type] = append(validated.challenges[challenge.Type], challenge)
		}
	}
	return validated, nil
}

// records returns the attestation records the validated challenges of
// challengeType persisted.
func (v *validatedAttestations) records(challengeType string) []*entities.DeviceAttestation {
	var records []*entities.DeviceAttestation
	for _, challenge := range v.challenges[challengeType] {
		if challenge.DeviceAttestation != nil {
			records = append(records, challenge.DeviceAttestation)
		}
	}
	return records
}

// types returns the attestation challenge types that validated the order,
// sorted.
func (v *validatedAttestations) types() []string {
	types := make([]string, 0, len(v.challenges))
	for challengeType := range v.challenges {
		types = append(types, challengeType)
	}
	sort.Strings(types)
	return types
}

// requireOnly refuses a finalize request unless challengeType is the only
// attestation challenge that validated the order, and at least one did.
// request names the finalize request, for the problem document.
func (v *validatedAttestations) requireOnly(orderID uint64, challengeType, request string) *entities.Error {
	types := v.types()
	if len(types) == 1 && types[0] == challengeType {
		return nil
	}
	return common.BadCSR((&ErrFinalizeRequestNotPermitted{
		OrderID:   orderID,
		Request:   request,
		Required:  challengeType,
		Validated: types,
	}).Error())
}

// bindEnrollActivation refuses a TCG-CSR-IDEVID whose endorsement key or
// activation key is not the one a credential was activated for (go-xkms#1391).
//
// Credential activation at the challenge proved a TPM holding one endorsement
// key and one activation key answered. The TCG-CSR arrives one request later,
// and nothing else ties it to that TPM: a client that passed the challenge once
// could build a TCG-CSR in software around ANOTHER device's public endorsement
// key certificate and be issued an IDevID carrying that device's identity. So
// the endorsement key certificate's TCG permanent identifier and the activation
// key's public area must be those the activation recorded.
//
// records are the enroll-01 activation records of the order. A CSR is accepted
// when one of them names its endorsement key and activation key.
func bindEnrollActivation(records []*entities.DeviceAttestation, orderID uint64, ekCertificate, attestPub []byte) *entities.Error {
	if len(records) == 0 {
		return common.BadCSR((&ErrEnrollActivationNotFound{OrderID: orderID}).Error())
	}

	ek, _, err := evidence.ParseEKCertificateChain(ekCertificate)
	if err != nil {
		return common.BadCSR((&ErrEnrollActivationMismatch{OrderID: orderID, Subject: "endorsement key certificate", Cause: err}).Error())
	}
	permanentIdentifier, err := ca.EKCertificatePermanentIdentifier(ek)
	if err != nil {
		return common.BadCSR((&ErrEnrollActivationMismatch{OrderID: orderID, Subject: "endorsement key certificate", Cause: err}).Error())
	}

	var activatedEK bool
	for _, rec := range records {
		if rec.DeviceIdentityValue != permanentIdentifier {
			continue
		}
		activatedEK = true
		if bytes.Equal(rec.PubArea, attestPub) {
			return nil
		}
	}
	subject := "endorsement key"
	if activatedEK {
		subject = "attestation key"
	}
	return common.BadCSR((&ErrEnrollActivationMismatch{OrderID: orderID, Subject: subject}).Error())
}

// bindTCGCSRToActivation is the gate in front of finalizeTCGCSR: the order must
// have been validated by enroll-01 alone, and the TCG-CSR-IDEVID must be built
// around the endorsement key and activation key that passed credential
// activation there.
func (s *RestService) bindTCGCSRToActivation(
	ctx context.Context,
	authzDAO qrdbsdk.GenericDAO[*entities.ACMEAuthorization],
	order *entities.ACMEOrder,
	csrDER []byte,
) *entities.Error {

	validated, problem := s.validatedAttestations(ctx, authzDAO, order)
	if problem != nil {
		return problem
	}
	if problem := validated.requireOnly(order.ID, common.ChallengeTypeEnroll01, "TCG-CSR-IDEVID"); problem != nil {
		return problem
	}

	tcgCSR, err := xkmssdk.UnmarshalIDevIDCSR(csrDER)
	if err != nil {
		return common.MalformedError("Failed to parse TCG-CSR-IDEVID", nil)
	}
	if problem := bindEnrollActivation(
		validated.records(common.ChallengeTypeEnroll01), order.ID,
		tcgCSR.CsrContents.EkCert, tcgCSR.CsrContents.AttestPub); problem != nil {
		s.logger.Warn("TCG-CSR-IDEVID is not for the TPM that passed enroll-01 credential activation",
			"order_id", order.ID, "reason", problem.Detail)
		return problem
	}
	return nil
}
