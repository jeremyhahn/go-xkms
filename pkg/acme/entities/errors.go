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

package entities

// Error represents an ACME error as per RFC 8555.
// ACME errors provide detailed information about failures during the protocol flow.
type Error struct {
	Type        string          `json:"type"`
	Detail      string          `json:"detail"`
	Status      int             `json:"-"`
	SubProblems []SubProblem    `json:"subproblems,omitempty"`
	Identifier  *ACMEIdentifier `json:"identifier,omitempty"`
	Instance    string          `json:"instance,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Detail
}

// NewError creates a new ACME error with the specified type, detail, status, and subproblems.
func NewError(errType, detail string, status int, subproblems []SubProblem) *Error {
	return &Error{
		Type:        "urn:ietf:params:acme:error:" + errType,
		Detail:      detail,
		Status:      status,
		SubProblems: subproblems,
	}
}

// SubProblem represents a subproblem in a compound error per RFC 8555.
// Subproblems provide detailed error information for specific identifiers.
type SubProblem struct {
	Type       string          `json:"type"`
	Detail     string          `json:"detail"`
	Identifier *ACMEIdentifier `json:"identifier,omitempty"`
}
