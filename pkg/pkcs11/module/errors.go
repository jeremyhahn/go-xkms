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

// Package module provides PKCS#11 Cryptoki module implementation types and utilities.
// This package implements the OASIS PKCS#11 v3.2 specification for cryptographic
// token interface.
package module

import (
	"errors"
	"fmt"
)

// CK_RV represents a PKCS#11 return value (Cryptoki Return Value).
// All PKCS#11 functions return a value of this type to indicate success or failure.
type CK_RV uint32

// PKCS#11 v3.0/v3.2 Return Values (CKR_* error codes)
// Reference: OASIS PKCS#11 Cryptographic Token Interface Base Specification v3.2 CSD01
const (
	// CKR_OK indicates successful execution of a Cryptoki function.
	CKR_OK CK_RV = 0x00000000

	// CKR_CANCEL indicates that the user or application cancelled the operation.
	CKR_CANCEL CK_RV = 0x00000001

	// CKR_HOST_MEMORY indicates that the computer running Cryptoki has insufficient memory.
	CKR_HOST_MEMORY CK_RV = 0x00000002

	// CKR_SLOT_ID_INVALID indicates an invalid slot ID was specified.
	CKR_SLOT_ID_INVALID CK_RV = 0x00000003

	// CKR_GENERAL_ERROR indicates a general or unspecified error occurred.
	CKR_GENERAL_ERROR CK_RV = 0x00000005

	// CKR_FUNCTION_FAILED indicates the function failed for an unspecified reason.
	CKR_FUNCTION_FAILED CK_RV = 0x00000006

	// CKR_ARGUMENTS_BAD indicates invalid or malformed arguments were supplied.
	CKR_ARGUMENTS_BAD CK_RV = 0x00000007

	// CKR_NO_EVENT indicates no slot event (token insertion/removal) is available.
	CKR_NO_EVENT CK_RV = 0x00000008

	// CKR_NEED_TO_CREATE_THREADS indicates the library needs to create threads
	// but the application specified CKF_LIBRARY_CANT_CREATE_OS_THREADS.
	CKR_NEED_TO_CREATE_THREADS CK_RV = 0x00000009

	// CKR_CANT_LOCK indicates that the application specified CKF_OS_LOCKING_OK
	// but the library cannot provide thread-safe behavior.
	CKR_CANT_LOCK CK_RV = 0x0000000A

	// CKR_ATTRIBUTE_READ_ONLY indicates an attempt to modify a read-only attribute.
	CKR_ATTRIBUTE_READ_ONLY CK_RV = 0x00000010

	// CKR_ATTRIBUTE_SENSITIVE indicates an attempt to read a sensitive attribute
	// that cannot be revealed.
	CKR_ATTRIBUTE_SENSITIVE CK_RV = 0x00000011

	// CKR_ATTRIBUTE_TYPE_INVALID indicates an invalid attribute type was specified.
	CKR_ATTRIBUTE_TYPE_INVALID CK_RV = 0x00000012

	// CKR_ATTRIBUTE_VALUE_INVALID indicates an invalid attribute value was specified.
	CKR_ATTRIBUTE_VALUE_INVALID CK_RV = 0x00000013

	// CKR_ACTION_PROHIBITED indicates the action is prohibited by a constraint.
	CKR_ACTION_PROHIBITED CK_RV = 0x0000001B

	// CKR_DATA_INVALID indicates the data provided is invalid for the operation.
	CKR_DATA_INVALID CK_RV = 0x00000020

	// CKR_DATA_LEN_RANGE indicates the data length is out of range for the operation.
	CKR_DATA_LEN_RANGE CK_RV = 0x00000021

	// CKR_DEVICE_ERROR indicates an error occurred with the token or slot.
	CKR_DEVICE_ERROR CK_RV = 0x00000030

	// CKR_DEVICE_MEMORY indicates the token has insufficient memory.
	CKR_DEVICE_MEMORY CK_RV = 0x00000031

	// CKR_DEVICE_REMOVED indicates the token was removed during the operation.
	CKR_DEVICE_REMOVED CK_RV = 0x00000032

	// CKR_ENCRYPTED_DATA_INVALID indicates the encrypted data is invalid.
	CKR_ENCRYPTED_DATA_INVALID CK_RV = 0x00000040

	// CKR_ENCRYPTED_DATA_LEN_RANGE indicates the encrypted data length is invalid.
	CKR_ENCRYPTED_DATA_LEN_RANGE CK_RV = 0x00000041

	// CKR_AEAD_DECRYPT_FAILED indicates AEAD decryption failed (authentication tag mismatch).
	CKR_AEAD_DECRYPT_FAILED CK_RV = 0x00000042

	// CKR_FUNCTION_CANCELED indicates the function was cancelled mid-execution.
	CKR_FUNCTION_CANCELED CK_RV = 0x00000050

	// CKR_FUNCTION_NOT_PARALLEL indicates the function cannot run in parallel.
	CKR_FUNCTION_NOT_PARALLEL CK_RV = 0x00000051

	// CKR_FUNCTION_NOT_SUPPORTED indicates the function is not supported by the library.
	CKR_FUNCTION_NOT_SUPPORTED CK_RV = 0x00000054

	// CKR_KEY_HANDLE_INVALID indicates the specified key handle is invalid.
	CKR_KEY_HANDLE_INVALID CK_RV = 0x00000060

	// CKR_KEY_SIZE_RANGE indicates the specified key size is out of range.
	CKR_KEY_SIZE_RANGE CK_RV = 0x00000062

	// CKR_KEY_TYPE_INCONSISTENT indicates the key type is inconsistent with the mechanism.
	CKR_KEY_TYPE_INCONSISTENT CK_RV = 0x00000063

	// CKR_KEY_NOT_NEEDED indicates a key was supplied but not needed.
	CKR_KEY_NOT_NEEDED CK_RV = 0x00000064

	// CKR_KEY_CHANGED indicates the key has been changed.
	CKR_KEY_CHANGED CK_RV = 0x00000065

	// CKR_KEY_NEEDED indicates a key is needed but was not supplied.
	CKR_KEY_NEEDED CK_RV = 0x00000066

	// CKR_KEY_INDIGESTIBLE indicates the key cannot be digested.
	CKR_KEY_INDIGESTIBLE CK_RV = 0x00000067

	// CKR_KEY_FUNCTION_NOT_PERMITTED indicates the key cannot be used for this function.
	CKR_KEY_FUNCTION_NOT_PERMITTED CK_RV = 0x00000068

	// CKR_KEY_NOT_WRAPPABLE indicates the key cannot be wrapped.
	CKR_KEY_NOT_WRAPPABLE CK_RV = 0x00000069

	// CKR_KEY_UNEXTRACTABLE indicates the key is not extractable.
	CKR_KEY_UNEXTRACTABLE CK_RV = 0x0000006A

	// CKR_MECHANISM_INVALID indicates an invalid mechanism was specified.
	CKR_MECHANISM_INVALID CK_RV = 0x00000070

	// CKR_MECHANISM_PARAM_INVALID indicates invalid mechanism parameters were specified.
	CKR_MECHANISM_PARAM_INVALID CK_RV = 0x00000071

	// CKR_OBJECT_HANDLE_INVALID indicates the specified object handle is invalid.
	CKR_OBJECT_HANDLE_INVALID CK_RV = 0x00000082

	// CKR_OPERATION_ACTIVE indicates an operation is already active.
	CKR_OPERATION_ACTIVE CK_RV = 0x00000090

	// CKR_OPERATION_NOT_INITIALIZED indicates no operation has been initialized.
	CKR_OPERATION_NOT_INITIALIZED CK_RV = 0x00000091

	// CKR_PIN_INCORRECT indicates the specified PIN is incorrect.
	CKR_PIN_INCORRECT CK_RV = 0x000000A0

	// CKR_PIN_INVALID indicates the specified PIN is invalid (e.g., contains invalid characters).
	CKR_PIN_INVALID CK_RV = 0x000000A1

	// CKR_PIN_LEN_RANGE indicates the PIN length is out of range.
	CKR_PIN_LEN_RANGE CK_RV = 0x000000A2

	// CKR_PIN_EXPIRED indicates the PIN has expired.
	CKR_PIN_EXPIRED CK_RV = 0x000000A3

	// CKR_PIN_LOCKED indicates the PIN is locked (too many failed attempts).
	CKR_PIN_LOCKED CK_RV = 0x000000A4

	// CKR_SESSION_CLOSED indicates the session has been closed.
	CKR_SESSION_CLOSED CK_RV = 0x000000B0

	// CKR_SESSION_COUNT indicates no more sessions can be opened.
	CKR_SESSION_COUNT CK_RV = 0x000000B1

	// CKR_SESSION_HANDLE_INVALID indicates the specified session handle is invalid.
	CKR_SESSION_HANDLE_INVALID CK_RV = 0x000000B3

	// CKR_SESSION_PARALLEL_NOT_SUPPORTED indicates parallel sessions are not supported.
	CKR_SESSION_PARALLEL_NOT_SUPPORTED CK_RV = 0x000000B4

	// CKR_SESSION_READ_ONLY indicates the session is read-only.
	CKR_SESSION_READ_ONLY CK_RV = 0x000000B5

	// CKR_SESSION_EXISTS indicates a session already exists for the token.
	CKR_SESSION_EXISTS CK_RV = 0x000000B6

	// CKR_SESSION_READ_ONLY_EXISTS indicates a read-only session exists and prevents
	// a read-write SO session from being opened.
	CKR_SESSION_READ_ONLY_EXISTS CK_RV = 0x000000B7

	// CKR_SESSION_READ_WRITE_SO_EXISTS indicates a read-write SO session exists and
	// prevents a read-only session from being opened.
	CKR_SESSION_READ_WRITE_SO_EXISTS CK_RV = 0x000000B8

	// CKR_SIGNATURE_INVALID indicates the signature is invalid.
	CKR_SIGNATURE_INVALID CK_RV = 0x000000C0

	// CKR_SIGNATURE_LEN_RANGE indicates the signature length is invalid.
	CKR_SIGNATURE_LEN_RANGE CK_RV = 0x000000C1

	// CKR_TEMPLATE_INCOMPLETE indicates the template is incomplete.
	CKR_TEMPLATE_INCOMPLETE CK_RV = 0x000000D0

	// CKR_TEMPLATE_INCONSISTENT indicates the template has inconsistent attributes.
	CKR_TEMPLATE_INCONSISTENT CK_RV = 0x000000D1

	// CKR_TOKEN_NOT_PRESENT indicates the token is not present in the slot.
	CKR_TOKEN_NOT_PRESENT CK_RV = 0x000000E0

	// CKR_TOKEN_NOT_RECOGNIZED indicates the token is not recognized.
	CKR_TOKEN_NOT_RECOGNIZED CK_RV = 0x000000E1

	// CKR_TOKEN_WRITE_PROTECTED indicates the token is write-protected.
	CKR_TOKEN_WRITE_PROTECTED CK_RV = 0x000000E2

	// CKR_UNWRAPPING_KEY_HANDLE_INVALID indicates the unwrapping key handle is invalid.
	CKR_UNWRAPPING_KEY_HANDLE_INVALID CK_RV = 0x000000F0

	// CKR_UNWRAPPING_KEY_SIZE_RANGE indicates the unwrapping key size is out of range.
	CKR_UNWRAPPING_KEY_SIZE_RANGE CK_RV = 0x000000F1

	// CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT indicates the unwrapping key type is
	// inconsistent with the mechanism.
	CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT CK_RV = 0x000000F2

	// CKR_USER_ALREADY_LOGGED_IN indicates the specified user is already logged in.
	CKR_USER_ALREADY_LOGGED_IN CK_RV = 0x00000100

	// CKR_USER_NOT_LOGGED_IN indicates the required user is not logged in.
	CKR_USER_NOT_LOGGED_IN CK_RV = 0x00000101

	// CKR_USER_PIN_NOT_INITIALIZED indicates the user PIN has not been initialized.
	CKR_USER_PIN_NOT_INITIALIZED CK_RV = 0x00000102

	// CKR_USER_TYPE_INVALID indicates an invalid user type was specified.
	CKR_USER_TYPE_INVALID CK_RV = 0x00000103

	// CKR_USER_ANOTHER_ALREADY_LOGGED_IN indicates another user is already logged in.
	CKR_USER_ANOTHER_ALREADY_LOGGED_IN CK_RV = 0x00000104

	// CKR_USER_TOO_MANY_TYPES indicates too many user types are logged in.
	CKR_USER_TOO_MANY_TYPES CK_RV = 0x00000105

	// CKR_WRAPPED_KEY_INVALID indicates the wrapped key is invalid.
	CKR_WRAPPED_KEY_INVALID CK_RV = 0x00000110

	// CKR_WRAPPED_KEY_LEN_RANGE indicates the wrapped key length is out of range.
	CKR_WRAPPED_KEY_LEN_RANGE CK_RV = 0x00000112

	// CKR_WRAPPING_KEY_HANDLE_INVALID indicates the wrapping key handle is invalid.
	CKR_WRAPPING_KEY_HANDLE_INVALID CK_RV = 0x00000113

	// CKR_WRAPPING_KEY_SIZE_RANGE indicates the wrapping key size is out of range.
	CKR_WRAPPING_KEY_SIZE_RANGE CK_RV = 0x00000114

	// CKR_WRAPPING_KEY_TYPE_INCONSISTENT indicates the wrapping key type is
	// inconsistent with the mechanism.
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT CK_RV = 0x00000115

	// CKR_RANDOM_SEED_NOT_SUPPORTED indicates random seed is not supported.
	CKR_RANDOM_SEED_NOT_SUPPORTED CK_RV = 0x00000120

	// CKR_RANDOM_NO_RNG indicates no random number generator is available.
	CKR_RANDOM_NO_RNG CK_RV = 0x00000121

	// CKR_DOMAIN_PARAMS_INVALID indicates the domain parameters are invalid.
	CKR_DOMAIN_PARAMS_INVALID CK_RV = 0x00000130

	// CKR_CURVE_NOT_SUPPORTED indicates the specified curve is not supported.
	CKR_CURVE_NOT_SUPPORTED CK_RV = 0x00000140

	// CKR_BUFFER_TOO_SMALL indicates the output buffer is too small.
	CKR_BUFFER_TOO_SMALL CK_RV = 0x00000150

	// CKR_SAVED_STATE_INVALID indicates the saved cryptographic state is invalid.
	CKR_SAVED_STATE_INVALID CK_RV = 0x00000160

	// CKR_INFORMATION_SENSITIVE indicates the requested information is sensitive.
	CKR_INFORMATION_SENSITIVE CK_RV = 0x00000170

	// CKR_STATE_UNSAVEABLE indicates the cryptographic state cannot be saved.
	CKR_STATE_UNSAVEABLE CK_RV = 0x00000180

	// CKR_CRYPTOKI_NOT_INITIALIZED indicates Cryptoki has not been initialized.
	CKR_CRYPTOKI_NOT_INITIALIZED CK_RV = 0x00000190

	// CKR_CRYPTOKI_ALREADY_INITIALIZED indicates Cryptoki is already initialized.
	CKR_CRYPTOKI_ALREADY_INITIALIZED CK_RV = 0x00000191

	// CKR_MUTEX_BAD indicates the mutex is bad or invalid.
	CKR_MUTEX_BAD CK_RV = 0x000001A0

	// CKR_MUTEX_NOT_LOCKED indicates the mutex is not locked.
	CKR_MUTEX_NOT_LOCKED CK_RV = 0x000001A1

	// CKR_NEW_PIN_MODE indicates the token requires a new PIN.
	CKR_NEW_PIN_MODE CK_RV = 0x000001B0

	// CKR_NEXT_OTP indicates the next OTP value should be provided.
	CKR_NEXT_OTP CK_RV = 0x000001B1

	// CKR_EXCEEDED_MAX_ITERATIONS indicates maximum iterations were exceeded.
	CKR_EXCEEDED_MAX_ITERATIONS CK_RV = 0x000001B5

	// CKR_FIPS_SELF_TEST_FAILED indicates a FIPS self-test failed.
	CKR_FIPS_SELF_TEST_FAILED CK_RV = 0x000001B6

	// CKR_LIBRARY_LOAD_FAILED indicates the library failed to load.
	CKR_LIBRARY_LOAD_FAILED CK_RV = 0x000001B7

	// CKR_PIN_TOO_WEAK indicates the PIN is too weak.
	CKR_PIN_TOO_WEAK CK_RV = 0x000001B8

	// CKR_PUBLIC_KEY_INVALID indicates the public key is invalid.
	CKR_PUBLIC_KEY_INVALID CK_RV = 0x000001B9

	// CKR_FUNCTION_REJECTED indicates the function was rejected by a callback.
	CKR_FUNCTION_REJECTED CK_RV = 0x00000200

	// CKR_TOKEN_RESOURCE_EXCEEDED indicates a token resource limit was exceeded.
	CKR_TOKEN_RESOURCE_EXCEEDED CK_RV = 0x00000201

	// CKR_OPERATION_CANCEL_FAILED indicates operation cancellation failed.
	CKR_OPERATION_CANCEL_FAILED CK_RV = 0x00000202

	// CKR_KEY_EXHAUSTED indicates the key usage count has been exhausted.
	CKR_KEY_EXHAUSTED CK_RV = 0x00000203

	// PKCS#11 v3.2 Return Values

	// CKR_PENDING indicates an asynchronous operation is pending completion.
	CKR_PENDING CK_RV = 0x00000204

	// CKR_SESSION_ASYNC_NOT_SUPPORTED indicates the session does not support
	// asynchronous operations.
	CKR_SESSION_ASYNC_NOT_SUPPORTED CK_RV = 0x00000205

	// CKR_SEED_RANDOM_REQUIRED indicates the token requires the application to
	// seed the random number generator before use.
	CKR_SEED_RANDOM_REQUIRED CK_RV = 0x00000206

	// CKR_OPERATION_NOT_VALIDATED indicates the operation has not been validated
	// according to the token's validation policy.
	CKR_OPERATION_NOT_VALIDATED CK_RV = 0x00000207

	// CKR_OPERATION_INCOMPATIBLE indicates the operation is incompatible with
	// the current session state or token capabilities.
	// NOTE: This return value is NOT in the final PKCS#11 v3.2 CSD01 spec.
	// It appeared in early drafts but was removed. Retained for forward
	// compatibility with implementations that may use this code.
	CKR_OPERATION_INCOMPATIBLE CK_RV = 0x00000208

	// CKR_PARAMETER_SET_NOT_SUPPORTED indicates the requested parameter set is
	// not supported by the token.
	CKR_PARAMETER_SET_NOT_SUPPORTED CK_RV = 0x00000209

	// Vendor defined error code range starts at 0x80000000.
	// Applications should not use values in this range.
	CKR_VENDOR_DEFINED CK_RV = 0x80000000
)

// ckrNames maps CK_RV values to their string names.
var ckrNames = map[CK_RV]string{
	CKR_OK:                               "CKR_OK",
	CKR_CANCEL:                           "CKR_CANCEL",
	CKR_HOST_MEMORY:                      "CKR_HOST_MEMORY",
	CKR_SLOT_ID_INVALID:                  "CKR_SLOT_ID_INVALID",
	CKR_GENERAL_ERROR:                    "CKR_GENERAL_ERROR",
	CKR_FUNCTION_FAILED:                  "CKR_FUNCTION_FAILED",
	CKR_ARGUMENTS_BAD:                    "CKR_ARGUMENTS_BAD",
	CKR_NO_EVENT:                         "CKR_NO_EVENT",
	CKR_NEED_TO_CREATE_THREADS:           "CKR_NEED_TO_CREATE_THREADS",
	CKR_CANT_LOCK:                        "CKR_CANT_LOCK",
	CKR_ATTRIBUTE_READ_ONLY:              "CKR_ATTRIBUTE_READ_ONLY",
	CKR_ATTRIBUTE_SENSITIVE:              "CKR_ATTRIBUTE_SENSITIVE",
	CKR_ATTRIBUTE_TYPE_INVALID:           "CKR_ATTRIBUTE_TYPE_INVALID",
	CKR_ATTRIBUTE_VALUE_INVALID:          "CKR_ATTRIBUTE_VALUE_INVALID",
	CKR_ACTION_PROHIBITED:                "CKR_ACTION_PROHIBITED",
	CKR_DATA_INVALID:                     "CKR_DATA_INVALID",
	CKR_DATA_LEN_RANGE:                   "CKR_DATA_LEN_RANGE",
	CKR_DEVICE_ERROR:                     "CKR_DEVICE_ERROR",
	CKR_DEVICE_MEMORY:                    "CKR_DEVICE_MEMORY",
	CKR_DEVICE_REMOVED:                   "CKR_DEVICE_REMOVED",
	CKR_ENCRYPTED_DATA_INVALID:           "CKR_ENCRYPTED_DATA_INVALID",
	CKR_ENCRYPTED_DATA_LEN_RANGE:         "CKR_ENCRYPTED_DATA_LEN_RANGE",
	CKR_AEAD_DECRYPT_FAILED:              "CKR_AEAD_DECRYPT_FAILED",
	CKR_FUNCTION_CANCELED:                "CKR_FUNCTION_CANCELED",
	CKR_FUNCTION_NOT_PARALLEL:            "CKR_FUNCTION_NOT_PARALLEL",
	CKR_FUNCTION_NOT_SUPPORTED:           "CKR_FUNCTION_NOT_SUPPORTED",
	CKR_KEY_HANDLE_INVALID:               "CKR_KEY_HANDLE_INVALID",
	CKR_KEY_SIZE_RANGE:                   "CKR_KEY_SIZE_RANGE",
	CKR_KEY_TYPE_INCONSISTENT:            "CKR_KEY_TYPE_INCONSISTENT",
	CKR_KEY_NOT_NEEDED:                   "CKR_KEY_NOT_NEEDED",
	CKR_KEY_CHANGED:                      "CKR_KEY_CHANGED",
	CKR_KEY_NEEDED:                       "CKR_KEY_NEEDED",
	CKR_KEY_INDIGESTIBLE:                 "CKR_KEY_INDIGESTIBLE",
	CKR_KEY_FUNCTION_NOT_PERMITTED:       "CKR_KEY_FUNCTION_NOT_PERMITTED",
	CKR_KEY_NOT_WRAPPABLE:                "CKR_KEY_NOT_WRAPPABLE",
	CKR_KEY_UNEXTRACTABLE:                "CKR_KEY_UNEXTRACTABLE",
	CKR_MECHANISM_INVALID:                "CKR_MECHANISM_INVALID",
	CKR_MECHANISM_PARAM_INVALID:          "CKR_MECHANISM_PARAM_INVALID",
	CKR_OBJECT_HANDLE_INVALID:            "CKR_OBJECT_HANDLE_INVALID",
	CKR_OPERATION_ACTIVE:                 "CKR_OPERATION_ACTIVE",
	CKR_OPERATION_NOT_INITIALIZED:        "CKR_OPERATION_NOT_INITIALIZED",
	CKR_PIN_INCORRECT:                    "CKR_PIN_INCORRECT",
	CKR_PIN_INVALID:                      "CKR_PIN_INVALID",
	CKR_PIN_LEN_RANGE:                    "CKR_PIN_LEN_RANGE",
	CKR_PIN_EXPIRED:                      "CKR_PIN_EXPIRED",
	CKR_PIN_LOCKED:                       "CKR_PIN_LOCKED",
	CKR_SESSION_CLOSED:                   "CKR_SESSION_CLOSED",
	CKR_SESSION_COUNT:                    "CKR_SESSION_COUNT",
	CKR_SESSION_HANDLE_INVALID:           "CKR_SESSION_HANDLE_INVALID",
	CKR_SESSION_PARALLEL_NOT_SUPPORTED:   "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	CKR_SESSION_READ_ONLY:                "CKR_SESSION_READ_ONLY",
	CKR_SESSION_EXISTS:                   "CKR_SESSION_EXISTS",
	CKR_SESSION_READ_ONLY_EXISTS:         "CKR_SESSION_READ_ONLY_EXISTS",
	CKR_SESSION_READ_WRITE_SO_EXISTS:     "CKR_SESSION_READ_WRITE_SO_EXISTS",
	CKR_SIGNATURE_INVALID:                "CKR_SIGNATURE_INVALID",
	CKR_SIGNATURE_LEN_RANGE:              "CKR_SIGNATURE_LEN_RANGE",
	CKR_TEMPLATE_INCOMPLETE:              "CKR_TEMPLATE_INCOMPLETE",
	CKR_TEMPLATE_INCONSISTENT:            "CKR_TEMPLATE_INCONSISTENT",
	CKR_TOKEN_NOT_PRESENT:                "CKR_TOKEN_NOT_PRESENT",
	CKR_TOKEN_NOT_RECOGNIZED:             "CKR_TOKEN_NOT_RECOGNIZED",
	CKR_TOKEN_WRITE_PROTECTED:            "CKR_TOKEN_WRITE_PROTECTED",
	CKR_UNWRAPPING_KEY_HANDLE_INVALID:    "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	CKR_UNWRAPPING_KEY_SIZE_RANGE:        "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
	CKR_USER_ALREADY_LOGGED_IN:           "CKR_USER_ALREADY_LOGGED_IN",
	CKR_USER_NOT_LOGGED_IN:               "CKR_USER_NOT_LOGGED_IN",
	CKR_USER_PIN_NOT_INITIALIZED:         "CKR_USER_PIN_NOT_INITIALIZED",
	CKR_USER_TYPE_INVALID:                "CKR_USER_TYPE_INVALID",
	CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	CKR_USER_TOO_MANY_TYPES:              "CKR_USER_TOO_MANY_TYPES",
	CKR_WRAPPED_KEY_INVALID:              "CKR_WRAPPED_KEY_INVALID",
	CKR_WRAPPED_KEY_LEN_RANGE:            "CKR_WRAPPED_KEY_LEN_RANGE",
	CKR_WRAPPING_KEY_HANDLE_INVALID:      "CKR_WRAPPING_KEY_HANDLE_INVALID",
	CKR_WRAPPING_KEY_SIZE_RANGE:          "CKR_WRAPPING_KEY_SIZE_RANGE",
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	CKR_RANDOM_SEED_NOT_SUPPORTED:        "CKR_RANDOM_SEED_NOT_SUPPORTED",
	CKR_RANDOM_NO_RNG:                    "CKR_RANDOM_NO_RNG",
	CKR_DOMAIN_PARAMS_INVALID:            "CKR_DOMAIN_PARAMS_INVALID",
	CKR_CURVE_NOT_SUPPORTED:              "CKR_CURVE_NOT_SUPPORTED",
	CKR_BUFFER_TOO_SMALL:                 "CKR_BUFFER_TOO_SMALL",
	CKR_SAVED_STATE_INVALID:              "CKR_SAVED_STATE_INVALID",
	CKR_INFORMATION_SENSITIVE:            "CKR_INFORMATION_SENSITIVE",
	CKR_STATE_UNSAVEABLE:                 "CKR_STATE_UNSAVEABLE",
	CKR_CRYPTOKI_NOT_INITIALIZED:         "CKR_CRYPTOKI_NOT_INITIALIZED",
	CKR_CRYPTOKI_ALREADY_INITIALIZED:     "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	CKR_MUTEX_BAD:                        "CKR_MUTEX_BAD",
	CKR_MUTEX_NOT_LOCKED:                 "CKR_MUTEX_NOT_LOCKED",
	CKR_NEW_PIN_MODE:                     "CKR_NEW_PIN_MODE",
	CKR_NEXT_OTP:                         "CKR_NEXT_OTP",
	CKR_EXCEEDED_MAX_ITERATIONS:          "CKR_EXCEEDED_MAX_ITERATIONS",
	CKR_FIPS_SELF_TEST_FAILED:            "CKR_FIPS_SELF_TEST_FAILED",
	CKR_LIBRARY_LOAD_FAILED:              "CKR_LIBRARY_LOAD_FAILED",
	CKR_PIN_TOO_WEAK:                     "CKR_PIN_TOO_WEAK",
	CKR_PUBLIC_KEY_INVALID:               "CKR_PUBLIC_KEY_INVALID",
	CKR_FUNCTION_REJECTED:                "CKR_FUNCTION_REJECTED",
	CKR_TOKEN_RESOURCE_EXCEEDED:          "CKR_TOKEN_RESOURCE_EXCEEDED",
	CKR_OPERATION_CANCEL_FAILED:          "CKR_OPERATION_CANCEL_FAILED",
	CKR_KEY_EXHAUSTED:                    "CKR_KEY_EXHAUSTED",
	CKR_PENDING:                          "CKR_PENDING",
	CKR_SESSION_ASYNC_NOT_SUPPORTED:      "CKR_SESSION_ASYNC_NOT_SUPPORTED",
	CKR_SEED_RANDOM_REQUIRED:             "CKR_SEED_RANDOM_REQUIRED",
	CKR_OPERATION_NOT_VALIDATED:          "CKR_OPERATION_NOT_VALIDATED",
	CKR_OPERATION_INCOMPATIBLE:           "CKR_OPERATION_INCOMPATIBLE",
	CKR_PARAMETER_SET_NOT_SUPPORTED:      "CKR_PARAMETER_SET_NOT_SUPPORTED",
	CKR_VENDOR_DEFINED:                   "CKR_VENDOR_DEFINED",
}

// String returns the string representation of the CK_RV value.
func (rv CK_RV) String() string {
	if name, ok := ckrNames[rv]; ok {
		return name
	}
	if rv >= CKR_VENDOR_DEFINED {
		return fmt.Sprintf("CKR_VENDOR_DEFINED+0x%08X", uint32(rv-CKR_VENDOR_DEFINED))
	}
	return fmt.Sprintf("CKR_UNKNOWN(0x%08X)", uint32(rv))
}

// PKCS11Error represents a PKCS#11 error with an associated CK_RV return value.
// It implements the error interface and provides methods for converting between
// Go errors and PKCS#11 return values.
type PKCS11Error struct {
	// Code is the PKCS#11 CK_RV return value.
	Code CK_RV
	// Message provides additional context about the error.
	Message string
	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *PKCS11Error) Error() string {
	if e.Message != "" && e.Cause != nil {
		return fmt.Sprintf("pkcs11: %s: %s: %v", e.Code.String(), e.Message, e.Cause)
	}
	if e.Message != "" {
		return fmt.Sprintf("pkcs11: %s: %s", e.Code.String(), e.Message)
	}
	if e.Cause != nil {
		return fmt.Sprintf("pkcs11: %s: %v", e.Code.String(), e.Cause)
	}
	return fmt.Sprintf("pkcs11: %s", e.Code.String())
}

// Unwrap returns the underlying cause of the error.
func (e *PKCS11Error) Unwrap() error {
	return e.Cause
}

// Is reports whether the target error matches this error.
// It matches if the target is a PKCS11Error with the same code,
// or if it matches one of the sentinel errors.
func (e *PKCS11Error) Is(target error) bool {
	if t, ok := target.(*PKCS11Error); ok {
		return e.Code == t.Code
	}
	// Check against sentinel errors
	if sentinel, ok := sentinelErrors[e.Code]; ok {
		return errors.Is(target, sentinel)
	}
	return false
}

// NewPKCS11Error creates a new PKCS11Error with the given code.
func NewPKCS11Error(code CK_RV) *PKCS11Error {
	return &PKCS11Error{Code: code}
}

// NewPKCS11ErrorWithMessage creates a new PKCS11Error with the given code and message.
func NewPKCS11ErrorWithMessage(code CK_RV, message string) *PKCS11Error {
	return &PKCS11Error{Code: code, Message: message}
}

// NewPKCS11ErrorWithCause creates a new PKCS11Error with the given code and cause.
func NewPKCS11ErrorWithCause(code CK_RV, cause error) *PKCS11Error {
	return &PKCS11Error{Code: code, Cause: cause}
}

// NewPKCS11ErrorFull creates a new PKCS11Error with code, message, and cause.
func NewPKCS11ErrorFull(code CK_RV, message string, cause error) *PKCS11Error {
	return &PKCS11Error{Code: code, Message: message, Cause: cause}
}

// Sentinel errors for common PKCS#11 error conditions.
// These allow using errors.Is() for error checking.
var (
	// ErrOK indicates successful execution (not an error).
	ErrOK = errors.New("pkcs11: operation successful")

	// ErrCancel indicates the operation was cancelled.
	ErrCancel = errors.New("pkcs11: operation cancelled")

	// ErrHostMemory indicates insufficient host memory.
	ErrHostMemory = errors.New("pkcs11: host memory exhausted")

	// ErrSlotIDInvalid indicates an invalid slot ID.
	ErrSlotIDInvalid = errors.New("pkcs11: invalid slot ID")

	// ErrGeneralError indicates a general unspecified error.
	ErrGeneralError = errors.New("pkcs11: general error")

	// ErrFunctionFailed indicates the function failed.
	ErrFunctionFailed = errors.New("pkcs11: function failed")

	// ErrArgumentsBad indicates invalid arguments.
	ErrArgumentsBad = errors.New("pkcs11: bad arguments")

	// ErrNoEvent indicates no slot event is available.
	ErrNoEvent = errors.New("pkcs11: no event")

	// ErrNeedToCreateThreads indicates the library needs to create threads.
	ErrNeedToCreateThreads = errors.New("pkcs11: need to create threads")

	// ErrCantLock indicates the library cannot provide locking.
	ErrCantLock = errors.New("pkcs11: cannot lock")

	// ErrAttributeReadOnly indicates the attribute is read-only.
	ErrAttributeReadOnly = errors.New("pkcs11: attribute is read-only")

	// ErrAttributeSensitive indicates the attribute is sensitive.
	ErrAttributeSensitive = errors.New("pkcs11: attribute is sensitive")

	// ErrAttributeTypeInvalid indicates an invalid attribute type.
	ErrAttributeTypeInvalid = errors.New("pkcs11: invalid attribute type")

	// ErrAttributeValueInvalid indicates an invalid attribute value.
	ErrAttributeValueInvalid = errors.New("pkcs11: invalid attribute value")

	// ErrActionProhibited indicates the action is prohibited.
	ErrActionProhibited = errors.New("pkcs11: action prohibited")

	// ErrDataInvalid indicates invalid data.
	ErrDataInvalid = errors.New("pkcs11: invalid data")

	// ErrDataLenRange indicates data length out of range.
	ErrDataLenRange = errors.New("pkcs11: data length out of range")

	// ErrDeviceError indicates a device error.
	ErrDeviceError = errors.New("pkcs11: device error")

	// ErrDeviceMemory indicates insufficient device memory.
	ErrDeviceMemory = errors.New("pkcs11: device memory exhausted")

	// ErrDeviceRemoved indicates the device was removed.
	ErrDeviceRemoved = errors.New("pkcs11: device removed")

	// ErrEncryptedDataInvalid indicates invalid encrypted data.
	ErrEncryptedDataInvalid = errors.New("pkcs11: invalid encrypted data")

	// ErrEncryptedDataLenRange indicates encrypted data length out of range.
	ErrEncryptedDataLenRange = errors.New("pkcs11: encrypted data length out of range")

	// ErrAEADDecryptFailed indicates AEAD decryption failed.
	ErrAEADDecryptFailed = errors.New("pkcs11: AEAD decryption failed")

	// ErrFunctionCanceled indicates the function was canceled.
	ErrFunctionCanceled = errors.New("pkcs11: function canceled")

	// ErrFunctionNotParallel indicates the function cannot run in parallel.
	ErrFunctionNotParallel = errors.New("pkcs11: function not parallel")

	// ErrFunctionNotSupported indicates the function is not supported.
	ErrFunctionNotSupported = errors.New("pkcs11: function not supported")

	// ErrKeyHandleInvalid indicates an invalid key handle.
	ErrKeyHandleInvalid = errors.New("pkcs11: invalid key handle")

	// ErrKeySizeRange indicates key size out of range.
	ErrKeySizeRange = errors.New("pkcs11: key size out of range")

	// ErrKeyTypeInconsistent indicates inconsistent key type.
	ErrKeyTypeInconsistent = errors.New("pkcs11: key type inconsistent")

	// ErrKeyNotNeeded indicates a key was not needed.
	ErrKeyNotNeeded = errors.New("pkcs11: key not needed")

	// ErrKeyChanged indicates the key has changed.
	ErrKeyChanged = errors.New("pkcs11: key changed")

	// ErrKeyNeeded indicates a key is needed.
	ErrKeyNeeded = errors.New("pkcs11: key needed")

	// ErrKeyIndigestible indicates the key cannot be digested.
	ErrKeyIndigestible = errors.New("pkcs11: key indigestible")

	// ErrKeyFunctionNotPermitted indicates the key function is not permitted.
	ErrKeyFunctionNotPermitted = errors.New("pkcs11: key function not permitted")

	// ErrKeyNotWrappable indicates the key cannot be wrapped.
	ErrKeyNotWrappable = errors.New("pkcs11: key not wrappable")

	// ErrKeyUnextractable indicates the key is not extractable.
	ErrKeyUnextractable = errors.New("pkcs11: key unextractable")

	// ErrMechanismInvalid indicates an invalid mechanism.
	ErrMechanismInvalid = errors.New("pkcs11: invalid mechanism")

	// ErrMechanismParamInvalid indicates invalid mechanism parameters.
	ErrMechanismParamInvalid = errors.New("pkcs11: invalid mechanism parameters")

	// ErrObjectHandleInvalid indicates an invalid object handle.
	ErrObjectHandleInvalid = errors.New("pkcs11: invalid object handle")

	// ErrOperationActive indicates an operation is already active.
	ErrOperationActive = errors.New("pkcs11: operation active")

	// ErrOperationNotInitialized indicates no operation is initialized.
	ErrOperationNotInitialized = errors.New("pkcs11: operation not initialized")

	// ErrPINIncorrect indicates an incorrect PIN.
	ErrPINIncorrect = errors.New("pkcs11: incorrect PIN")

	// ErrPINInvalid indicates an invalid PIN.
	ErrPINInvalid = errors.New("pkcs11: invalid PIN")

	// ErrPINLenRange indicates PIN length out of range.
	ErrPINLenRange = errors.New("pkcs11: PIN length out of range")

	// ErrPINExpired indicates the PIN has expired.
	ErrPINExpired = errors.New("pkcs11: PIN expired")

	// ErrPINLocked indicates the PIN is locked.
	ErrPINLocked = errors.New("pkcs11: PIN locked")

	// ErrSessionClosed indicates the session is closed.
	ErrSessionClosed = errors.New("pkcs11: session closed")

	// ErrSessionCount indicates the session count limit reached.
	ErrSessionCount = errors.New("pkcs11: session count exceeded")

	// ErrSessionHandleInvalid indicates an invalid session handle.
	ErrSessionHandleInvalid = errors.New("pkcs11: invalid session handle")

	// ErrSessionParallelNotSupported indicates parallel sessions not supported.
	ErrSessionParallelNotSupported = errors.New("pkcs11: parallel sessions not supported")

	// ErrSessionReadOnly indicates the session is read-only.
	ErrSessionReadOnly = errors.New("pkcs11: session is read-only")

	// ErrSessionExists indicates a session already exists.
	ErrSessionExists = errors.New("pkcs11: session exists")

	// ErrSessionReadOnlyExists indicates a read-only session exists.
	ErrSessionReadOnlyExists = errors.New("pkcs11: read-only session exists")

	// ErrSessionReadWriteSOExists indicates a read-write SO session exists.
	ErrSessionReadWriteSOExists = errors.New("pkcs11: read-write SO session exists")

	// ErrSignatureInvalid indicates an invalid signature.
	ErrSignatureInvalid = errors.New("pkcs11: invalid signature")

	// ErrSignatureLenRange indicates signature length out of range.
	ErrSignatureLenRange = errors.New("pkcs11: signature length out of range")

	// ErrTemplateIncomplete indicates an incomplete template.
	ErrTemplateIncomplete = errors.New("pkcs11: template incomplete")

	// ErrTemplateInconsistent indicates an inconsistent template.
	ErrTemplateInconsistent = errors.New("pkcs11: template inconsistent")

	// ErrTokenNotPresent indicates the token is not present.
	ErrTokenNotPresent = errors.New("pkcs11: token not present")

	// ErrTokenNotRecognized indicates the token is not recognized.
	ErrTokenNotRecognized = errors.New("pkcs11: token not recognized")

	// ErrTokenWriteProtected indicates the token is write-protected.
	ErrTokenWriteProtected = errors.New("pkcs11: token write-protected")

	// ErrUnwrappingKeyHandleInvalid indicates an invalid unwrapping key handle.
	ErrUnwrappingKeyHandleInvalid = errors.New("pkcs11: invalid unwrapping key handle")

	// ErrUnwrappingKeySizeRange indicates unwrapping key size out of range.
	ErrUnwrappingKeySizeRange = errors.New("pkcs11: unwrapping key size out of range")

	// ErrUnwrappingKeyTypeInconsistent indicates inconsistent unwrapping key type.
	ErrUnwrappingKeyTypeInconsistent = errors.New("pkcs11: unwrapping key type inconsistent")

	// ErrUserAlreadyLoggedIn indicates the user is already logged in.
	ErrUserAlreadyLoggedIn = errors.New("pkcs11: user already logged in")

	// ErrUserNotLoggedIn indicates the user is not logged in.
	ErrUserNotLoggedIn = errors.New("pkcs11: user not logged in")

	// ErrUserPINNotInitialized indicates the user PIN is not initialized.
	ErrUserPINNotInitialized = errors.New("pkcs11: user PIN not initialized")

	// ErrUserTypeInvalid indicates an invalid user type.
	ErrUserTypeInvalid = errors.New("pkcs11: invalid user type")

	// ErrUserAnotherAlreadyLoggedIn indicates another user is already logged in.
	ErrUserAnotherAlreadyLoggedIn = errors.New("pkcs11: another user already logged in")

	// ErrUserTooManyTypes indicates too many user types are logged in.
	ErrUserTooManyTypes = errors.New("pkcs11: too many user types")

	// ErrWrappedKeyInvalid indicates an invalid wrapped key.
	ErrWrappedKeyInvalid = errors.New("pkcs11: invalid wrapped key")

	// ErrWrappedKeyLenRange indicates wrapped key length out of range.
	ErrWrappedKeyLenRange = errors.New("pkcs11: wrapped key length out of range")

	// ErrWrappingKeyHandleInvalid indicates an invalid wrapping key handle.
	ErrWrappingKeyHandleInvalid = errors.New("pkcs11: invalid wrapping key handle")

	// ErrWrappingKeySizeRange indicates wrapping key size out of range.
	ErrWrappingKeySizeRange = errors.New("pkcs11: wrapping key size out of range")

	// ErrWrappingKeyTypeInconsistent indicates inconsistent wrapping key type.
	ErrWrappingKeyTypeInconsistent = errors.New("pkcs11: wrapping key type inconsistent")

	// ErrRandomSeedNotSupported indicates random seed is not supported.
	ErrRandomSeedNotSupported = errors.New("pkcs11: random seed not supported")

	// ErrRandomNoRNG indicates no random number generator available.
	ErrRandomNoRNG = errors.New("pkcs11: no random number generator")

	// ErrDomainParamsInvalid indicates invalid domain parameters.
	ErrDomainParamsInvalid = errors.New("pkcs11: invalid domain parameters")

	// ErrCurveNotSupported indicates the curve is not supported.
	ErrCurveNotSupported = errors.New("pkcs11: curve not supported")

	// ErrBufferTooSmall indicates the buffer is too small.
	ErrBufferTooSmall = errors.New("pkcs11: buffer too small")

	// ErrSavedStateInvalid indicates the saved state is invalid.
	ErrSavedStateInvalid = errors.New("pkcs11: invalid saved state")

	// ErrInformationSensitive indicates the information is sensitive.
	ErrInformationSensitive = errors.New("pkcs11: information sensitive")

	// ErrStateUnsaveable indicates the state cannot be saved.
	ErrStateUnsaveable = errors.New("pkcs11: state unsaveable")

	// ErrCryptokiNotInitialized indicates Cryptoki is not initialized.
	ErrCryptokiNotInitialized = errors.New("pkcs11: cryptoki not initialized")

	// ErrCryptokiAlreadyInitialized indicates Cryptoki is already initialized.
	ErrCryptokiAlreadyInitialized = errors.New("pkcs11: cryptoki already initialized")

	// ErrMutexBad indicates a bad mutex.
	ErrMutexBad = errors.New("pkcs11: bad mutex")

	// ErrMutexNotLocked indicates the mutex is not locked.
	ErrMutexNotLocked = errors.New("pkcs11: mutex not locked")

	// ErrNewPINMode indicates new PIN mode is required.
	ErrNewPINMode = errors.New("pkcs11: new PIN mode")

	// ErrNextOTP indicates the next OTP is required.
	ErrNextOTP = errors.New("pkcs11: next OTP required")

	// ErrExceededMaxIterations indicates maximum iterations exceeded.
	ErrExceededMaxIterations = errors.New("pkcs11: exceeded max iterations")

	// ErrFIPSSelfTestFailed indicates a FIPS self-test failed.
	ErrFIPSSelfTestFailed = errors.New("pkcs11: FIPS self-test failed")

	// ErrLibraryLoadFailed indicates the library failed to load.
	ErrLibraryLoadFailed = errors.New("pkcs11: library load failed")

	// ErrPINTooWeak indicates the PIN is too weak.
	ErrPINTooWeak = errors.New("pkcs11: PIN too weak")

	// ErrPublicKeyInvalid indicates an invalid public key.
	ErrPublicKeyInvalid = errors.New("pkcs11: invalid public key")

	// ErrFunctionRejected indicates the function was rejected.
	ErrFunctionRejected = errors.New("pkcs11: function rejected")

	// ErrTokenResourceExceeded indicates a token resource was exceeded.
	ErrTokenResourceExceeded = errors.New("pkcs11: token resource exceeded")

	// ErrOperationCancelFailed indicates operation cancellation failed.
	ErrOperationCancelFailed = errors.New("pkcs11: operation cancel failed")

	// ErrKeyExhausted indicates the key usage has been exhausted.
	ErrKeyExhausted = errors.New("pkcs11: key exhausted")

	// ErrPending indicates an asynchronous operation is pending.
	ErrPending = errors.New("pkcs11: operation pending")

	// ErrSessionAsyncNotSupported indicates the session does not support async operations.
	ErrSessionAsyncNotSupported = errors.New("pkcs11: session async not supported")

	// ErrSeedRandomRequired indicates random seed is required before use.
	ErrSeedRandomRequired = errors.New("pkcs11: seed random required")

	// ErrOperationNotValidated indicates the operation has not been validated.
	ErrOperationNotValidated = errors.New("pkcs11: operation not validated")

	// ErrOperationIncompatible indicates the operation is incompatible with the session state.
	ErrOperationIncompatible = errors.New("pkcs11: operation incompatible")

	// ErrParameterSetNotSupported indicates the parameter set is not supported.
	ErrParameterSetNotSupported = errors.New("pkcs11: parameter set not supported")

	// ErrVendorDefined indicates a vendor-defined error.
	ErrVendorDefined = errors.New("pkcs11: vendor defined error")
)

// sentinelErrors maps CK_RV codes to their corresponding sentinel errors.
var sentinelErrors = map[CK_RV]error{
	CKR_OK:                               ErrOK,
	CKR_CANCEL:                           ErrCancel,
	CKR_HOST_MEMORY:                      ErrHostMemory,
	CKR_SLOT_ID_INVALID:                  ErrSlotIDInvalid,
	CKR_GENERAL_ERROR:                    ErrGeneralError,
	CKR_FUNCTION_FAILED:                  ErrFunctionFailed,
	CKR_ARGUMENTS_BAD:                    ErrArgumentsBad,
	CKR_NO_EVENT:                         ErrNoEvent,
	CKR_NEED_TO_CREATE_THREADS:           ErrNeedToCreateThreads,
	CKR_CANT_LOCK:                        ErrCantLock,
	CKR_ATTRIBUTE_READ_ONLY:              ErrAttributeReadOnly,
	CKR_ATTRIBUTE_SENSITIVE:              ErrAttributeSensitive,
	CKR_ATTRIBUTE_TYPE_INVALID:           ErrAttributeTypeInvalid,
	CKR_ATTRIBUTE_VALUE_INVALID:          ErrAttributeValueInvalid,
	CKR_ACTION_PROHIBITED:                ErrActionProhibited,
	CKR_DATA_INVALID:                     ErrDataInvalid,
	CKR_DATA_LEN_RANGE:                   ErrDataLenRange,
	CKR_DEVICE_ERROR:                     ErrDeviceError,
	CKR_DEVICE_MEMORY:                    ErrDeviceMemory,
	CKR_DEVICE_REMOVED:                   ErrDeviceRemoved,
	CKR_ENCRYPTED_DATA_INVALID:           ErrEncryptedDataInvalid,
	CKR_ENCRYPTED_DATA_LEN_RANGE:         ErrEncryptedDataLenRange,
	CKR_AEAD_DECRYPT_FAILED:              ErrAEADDecryptFailed,
	CKR_FUNCTION_CANCELED:                ErrFunctionCanceled,
	CKR_FUNCTION_NOT_PARALLEL:            ErrFunctionNotParallel,
	CKR_FUNCTION_NOT_SUPPORTED:           ErrFunctionNotSupported,
	CKR_KEY_HANDLE_INVALID:               ErrKeyHandleInvalid,
	CKR_KEY_SIZE_RANGE:                   ErrKeySizeRange,
	CKR_KEY_TYPE_INCONSISTENT:            ErrKeyTypeInconsistent,
	CKR_KEY_NOT_NEEDED:                   ErrKeyNotNeeded,
	CKR_KEY_CHANGED:                      ErrKeyChanged,
	CKR_KEY_NEEDED:                       ErrKeyNeeded,
	CKR_KEY_INDIGESTIBLE:                 ErrKeyIndigestible,
	CKR_KEY_FUNCTION_NOT_PERMITTED:       ErrKeyFunctionNotPermitted,
	CKR_KEY_NOT_WRAPPABLE:                ErrKeyNotWrappable,
	CKR_KEY_UNEXTRACTABLE:                ErrKeyUnextractable,
	CKR_MECHANISM_INVALID:                ErrMechanismInvalid,
	CKR_MECHANISM_PARAM_INVALID:          ErrMechanismParamInvalid,
	CKR_OBJECT_HANDLE_INVALID:            ErrObjectHandleInvalid,
	CKR_OPERATION_ACTIVE:                 ErrOperationActive,
	CKR_OPERATION_NOT_INITIALIZED:        ErrOperationNotInitialized,
	CKR_PIN_INCORRECT:                    ErrPINIncorrect,
	CKR_PIN_INVALID:                      ErrPINInvalid,
	CKR_PIN_LEN_RANGE:                    ErrPINLenRange,
	CKR_PIN_EXPIRED:                      ErrPINExpired,
	CKR_PIN_LOCKED:                       ErrPINLocked,
	CKR_SESSION_CLOSED:                   ErrSessionClosed,
	CKR_SESSION_COUNT:                    ErrSessionCount,
	CKR_SESSION_HANDLE_INVALID:           ErrSessionHandleInvalid,
	CKR_SESSION_PARALLEL_NOT_SUPPORTED:   ErrSessionParallelNotSupported,
	CKR_SESSION_READ_ONLY:                ErrSessionReadOnly,
	CKR_SESSION_EXISTS:                   ErrSessionExists,
	CKR_SESSION_READ_ONLY_EXISTS:         ErrSessionReadOnlyExists,
	CKR_SESSION_READ_WRITE_SO_EXISTS:     ErrSessionReadWriteSOExists,
	CKR_SIGNATURE_INVALID:                ErrSignatureInvalid,
	CKR_SIGNATURE_LEN_RANGE:              ErrSignatureLenRange,
	CKR_TEMPLATE_INCOMPLETE:              ErrTemplateIncomplete,
	CKR_TEMPLATE_INCONSISTENT:            ErrTemplateInconsistent,
	CKR_TOKEN_NOT_PRESENT:                ErrTokenNotPresent,
	CKR_TOKEN_NOT_RECOGNIZED:             ErrTokenNotRecognized,
	CKR_TOKEN_WRITE_PROTECTED:            ErrTokenWriteProtected,
	CKR_UNWRAPPING_KEY_HANDLE_INVALID:    ErrUnwrappingKeyHandleInvalid,
	CKR_UNWRAPPING_KEY_SIZE_RANGE:        ErrUnwrappingKeySizeRange,
	CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: ErrUnwrappingKeyTypeInconsistent,
	CKR_USER_ALREADY_LOGGED_IN:           ErrUserAlreadyLoggedIn,
	CKR_USER_NOT_LOGGED_IN:               ErrUserNotLoggedIn,
	CKR_USER_PIN_NOT_INITIALIZED:         ErrUserPINNotInitialized,
	CKR_USER_TYPE_INVALID:                ErrUserTypeInvalid,
	CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   ErrUserAnotherAlreadyLoggedIn,
	CKR_USER_TOO_MANY_TYPES:              ErrUserTooManyTypes,
	CKR_WRAPPED_KEY_INVALID:              ErrWrappedKeyInvalid,
	CKR_WRAPPED_KEY_LEN_RANGE:            ErrWrappedKeyLenRange,
	CKR_WRAPPING_KEY_HANDLE_INVALID:      ErrWrappingKeyHandleInvalid,
	CKR_WRAPPING_KEY_SIZE_RANGE:          ErrWrappingKeySizeRange,
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   ErrWrappingKeyTypeInconsistent,
	CKR_RANDOM_SEED_NOT_SUPPORTED:        ErrRandomSeedNotSupported,
	CKR_RANDOM_NO_RNG:                    ErrRandomNoRNG,
	CKR_DOMAIN_PARAMS_INVALID:            ErrDomainParamsInvalid,
	CKR_CURVE_NOT_SUPPORTED:              ErrCurveNotSupported,
	CKR_BUFFER_TOO_SMALL:                 ErrBufferTooSmall,
	CKR_SAVED_STATE_INVALID:              ErrSavedStateInvalid,
	CKR_INFORMATION_SENSITIVE:            ErrInformationSensitive,
	CKR_STATE_UNSAVEABLE:                 ErrStateUnsaveable,
	CKR_CRYPTOKI_NOT_INITIALIZED:         ErrCryptokiNotInitialized,
	CKR_CRYPTOKI_ALREADY_INITIALIZED:     ErrCryptokiAlreadyInitialized,
	CKR_MUTEX_BAD:                        ErrMutexBad,
	CKR_MUTEX_NOT_LOCKED:                 ErrMutexNotLocked,
	CKR_NEW_PIN_MODE:                     ErrNewPINMode,
	CKR_NEXT_OTP:                         ErrNextOTP,
	CKR_EXCEEDED_MAX_ITERATIONS:          ErrExceededMaxIterations,
	CKR_FIPS_SELF_TEST_FAILED:            ErrFIPSSelfTestFailed,
	CKR_LIBRARY_LOAD_FAILED:              ErrLibraryLoadFailed,
	CKR_PIN_TOO_WEAK:                     ErrPINTooWeak,
	CKR_PUBLIC_KEY_INVALID:               ErrPublicKeyInvalid,
	CKR_FUNCTION_REJECTED:                ErrFunctionRejected,
	CKR_TOKEN_RESOURCE_EXCEEDED:          ErrTokenResourceExceeded,
	CKR_OPERATION_CANCEL_FAILED:          ErrOperationCancelFailed,
	CKR_KEY_EXHAUSTED:                    ErrKeyExhausted,
	CKR_PENDING:                          ErrPending,
	CKR_SESSION_ASYNC_NOT_SUPPORTED:      ErrSessionAsyncNotSupported,
	CKR_SEED_RANDOM_REQUIRED:             ErrSeedRandomRequired,
	CKR_OPERATION_NOT_VALIDATED:          ErrOperationNotValidated,
	CKR_OPERATION_INCOMPATIBLE:           ErrOperationIncompatible,
	CKR_PARAMETER_SET_NOT_SUPPORTED:      ErrParameterSetNotSupported,
	CKR_VENDOR_DEFINED:                   ErrVendorDefined,
}

// errorToCKR maps sentinel errors back to CK_RV codes.
var errorToCKR = map[error]CK_RV{
	ErrOK:                            CKR_OK,
	ErrCancel:                        CKR_CANCEL,
	ErrHostMemory:                    CKR_HOST_MEMORY,
	ErrSlotIDInvalid:                 CKR_SLOT_ID_INVALID,
	ErrGeneralError:                  CKR_GENERAL_ERROR,
	ErrFunctionFailed:                CKR_FUNCTION_FAILED,
	ErrArgumentsBad:                  CKR_ARGUMENTS_BAD,
	ErrNoEvent:                       CKR_NO_EVENT,
	ErrNeedToCreateThreads:           CKR_NEED_TO_CREATE_THREADS,
	ErrCantLock:                      CKR_CANT_LOCK,
	ErrAttributeReadOnly:             CKR_ATTRIBUTE_READ_ONLY,
	ErrAttributeSensitive:            CKR_ATTRIBUTE_SENSITIVE,
	ErrAttributeTypeInvalid:          CKR_ATTRIBUTE_TYPE_INVALID,
	ErrAttributeValueInvalid:         CKR_ATTRIBUTE_VALUE_INVALID,
	ErrActionProhibited:              CKR_ACTION_PROHIBITED,
	ErrDataInvalid:                   CKR_DATA_INVALID,
	ErrDataLenRange:                  CKR_DATA_LEN_RANGE,
	ErrDeviceError:                   CKR_DEVICE_ERROR,
	ErrDeviceMemory:                  CKR_DEVICE_MEMORY,
	ErrDeviceRemoved:                 CKR_DEVICE_REMOVED,
	ErrEncryptedDataInvalid:          CKR_ENCRYPTED_DATA_INVALID,
	ErrEncryptedDataLenRange:         CKR_ENCRYPTED_DATA_LEN_RANGE,
	ErrAEADDecryptFailed:             CKR_AEAD_DECRYPT_FAILED,
	ErrFunctionCanceled:              CKR_FUNCTION_CANCELED,
	ErrFunctionNotParallel:           CKR_FUNCTION_NOT_PARALLEL,
	ErrFunctionNotSupported:          CKR_FUNCTION_NOT_SUPPORTED,
	ErrKeyHandleInvalid:              CKR_KEY_HANDLE_INVALID,
	ErrKeySizeRange:                  CKR_KEY_SIZE_RANGE,
	ErrKeyTypeInconsistent:           CKR_KEY_TYPE_INCONSISTENT,
	ErrKeyNotNeeded:                  CKR_KEY_NOT_NEEDED,
	ErrKeyChanged:                    CKR_KEY_CHANGED,
	ErrKeyNeeded:                     CKR_KEY_NEEDED,
	ErrKeyIndigestible:               CKR_KEY_INDIGESTIBLE,
	ErrKeyFunctionNotPermitted:       CKR_KEY_FUNCTION_NOT_PERMITTED,
	ErrKeyNotWrappable:               CKR_KEY_NOT_WRAPPABLE,
	ErrKeyUnextractable:              CKR_KEY_UNEXTRACTABLE,
	ErrMechanismInvalid:              CKR_MECHANISM_INVALID,
	ErrMechanismParamInvalid:         CKR_MECHANISM_PARAM_INVALID,
	ErrObjectHandleInvalid:           CKR_OBJECT_HANDLE_INVALID,
	ErrOperationActive:               CKR_OPERATION_ACTIVE,
	ErrOperationNotInitialized:       CKR_OPERATION_NOT_INITIALIZED,
	ErrPINIncorrect:                  CKR_PIN_INCORRECT,
	ErrPINInvalid:                    CKR_PIN_INVALID,
	ErrPINLenRange:                   CKR_PIN_LEN_RANGE,
	ErrPINExpired:                    CKR_PIN_EXPIRED,
	ErrPINLocked:                     CKR_PIN_LOCKED,
	ErrSessionClosed:                 CKR_SESSION_CLOSED,
	ErrSessionCount:                  CKR_SESSION_COUNT,
	ErrSessionHandleInvalid:          CKR_SESSION_HANDLE_INVALID,
	ErrSessionParallelNotSupported:   CKR_SESSION_PARALLEL_NOT_SUPPORTED,
	ErrSessionReadOnly:               CKR_SESSION_READ_ONLY,
	ErrSessionExists:                 CKR_SESSION_EXISTS,
	ErrSessionReadOnlyExists:         CKR_SESSION_READ_ONLY_EXISTS,
	ErrSessionReadWriteSOExists:      CKR_SESSION_READ_WRITE_SO_EXISTS,
	ErrSignatureInvalid:              CKR_SIGNATURE_INVALID,
	ErrSignatureLenRange:             CKR_SIGNATURE_LEN_RANGE,
	ErrTemplateIncomplete:            CKR_TEMPLATE_INCOMPLETE,
	ErrTemplateInconsistent:          CKR_TEMPLATE_INCONSISTENT,
	ErrTokenNotPresent:               CKR_TOKEN_NOT_PRESENT,
	ErrTokenNotRecognized:            CKR_TOKEN_NOT_RECOGNIZED,
	ErrTokenWriteProtected:           CKR_TOKEN_WRITE_PROTECTED,
	ErrUnwrappingKeyHandleInvalid:    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
	ErrUnwrappingKeySizeRange:        CKR_UNWRAPPING_KEY_SIZE_RANGE,
	ErrUnwrappingKeyTypeInconsistent: CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
	ErrUserAlreadyLoggedIn:           CKR_USER_ALREADY_LOGGED_IN,
	ErrUserNotLoggedIn:               CKR_USER_NOT_LOGGED_IN,
	ErrUserPINNotInitialized:         CKR_USER_PIN_NOT_INITIALIZED,
	ErrUserTypeInvalid:               CKR_USER_TYPE_INVALID,
	ErrUserAnotherAlreadyLoggedIn:    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
	ErrUserTooManyTypes:              CKR_USER_TOO_MANY_TYPES,
	ErrWrappedKeyInvalid:             CKR_WRAPPED_KEY_INVALID,
	ErrWrappedKeyLenRange:            CKR_WRAPPED_KEY_LEN_RANGE,
	ErrWrappingKeyHandleInvalid:      CKR_WRAPPING_KEY_HANDLE_INVALID,
	ErrWrappingKeySizeRange:          CKR_WRAPPING_KEY_SIZE_RANGE,
	ErrWrappingKeyTypeInconsistent:   CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
	ErrRandomSeedNotSupported:        CKR_RANDOM_SEED_NOT_SUPPORTED,
	ErrRandomNoRNG:                   CKR_RANDOM_NO_RNG,
	ErrDomainParamsInvalid:           CKR_DOMAIN_PARAMS_INVALID,
	ErrCurveNotSupported:             CKR_CURVE_NOT_SUPPORTED,
	ErrBufferTooSmall:                CKR_BUFFER_TOO_SMALL,
	ErrSavedStateInvalid:             CKR_SAVED_STATE_INVALID,
	ErrInformationSensitive:          CKR_INFORMATION_SENSITIVE,
	ErrStateUnsaveable:               CKR_STATE_UNSAVEABLE,
	ErrCryptokiNotInitialized:        CKR_CRYPTOKI_NOT_INITIALIZED,
	ErrCryptokiAlreadyInitialized:    CKR_CRYPTOKI_ALREADY_INITIALIZED,
	ErrMutexBad:                      CKR_MUTEX_BAD,
	ErrMutexNotLocked:                CKR_MUTEX_NOT_LOCKED,
	ErrNewPINMode:                    CKR_NEW_PIN_MODE,
	ErrNextOTP:                       CKR_NEXT_OTP,
	ErrExceededMaxIterations:         CKR_EXCEEDED_MAX_ITERATIONS,
	ErrFIPSSelfTestFailed:            CKR_FIPS_SELF_TEST_FAILED,
	ErrLibraryLoadFailed:             CKR_LIBRARY_LOAD_FAILED,
	ErrPINTooWeak:                    CKR_PIN_TOO_WEAK,
	ErrPublicKeyInvalid:              CKR_PUBLIC_KEY_INVALID,
	ErrFunctionRejected:              CKR_FUNCTION_REJECTED,
	ErrTokenResourceExceeded:         CKR_TOKEN_RESOURCE_EXCEEDED,
	ErrOperationCancelFailed:         CKR_OPERATION_CANCEL_FAILED,
	ErrKeyExhausted:                  CKR_KEY_EXHAUSTED,
	ErrPending:                       CKR_PENDING,
	ErrSessionAsyncNotSupported:      CKR_SESSION_ASYNC_NOT_SUPPORTED,
	ErrSeedRandomRequired:            CKR_SEED_RANDOM_REQUIRED,
	ErrOperationNotValidated:         CKR_OPERATION_NOT_VALIDATED,
	ErrOperationIncompatible:         CKR_OPERATION_INCOMPATIBLE,
	ErrParameterSetNotSupported:      CKR_PARAMETER_SET_NOT_SUPPORTED,
	ErrVendorDefined:                 CKR_VENDOR_DEFINED,
}

// ToError converts a CK_RV return value to a Go error.
// Returns nil for CKR_OK.
// For known error codes, returns a PKCS11Error wrapping the sentinel error.
// For unknown codes, returns a PKCS11Error with just the code.
func ToError(rv CK_RV) error {
	if rv == CKR_OK {
		return nil
	}
	return NewPKCS11Error(rv)
}

// ToErrorWithMessage converts a CK_RV return value to a Go error with context.
// Returns nil for CKR_OK.
func ToErrorWithMessage(rv CK_RV, message string) error {
	if rv == CKR_OK {
		return nil
	}
	return NewPKCS11ErrorWithMessage(rv, message)
}

// FromError converts a Go error to a CK_RV return value.
// Returns CKR_OK for nil errors.
// For PKCS11Error, returns the embedded code.
// For known sentinel errors, returns the corresponding CK_RV.
// For unknown errors, returns CKR_GENERAL_ERROR.
func FromError(err error) CK_RV {
	if err == nil {
		return CKR_OK
	}

	// Check if it's a PKCS11Error
	var pkcs11Err *PKCS11Error
	if errors.As(err, &pkcs11Err) {
		return pkcs11Err.Code
	}

	// Check sentinel errors
	for sentinel, rv := range errorToCKR {
		if errors.Is(err, sentinel) {
			return rv
		}
	}

	// Unknown error
	return CKR_GENERAL_ERROR
}

// IsPKCS11Error checks if an error is a PKCS#11 error and returns the code.
// Returns CKR_OK and false if the error is not a PKCS11Error.
func IsPKCS11Error(err error) (CK_RV, bool) {
	var pkcs11Err *PKCS11Error
	if errors.As(err, &pkcs11Err) {
		return pkcs11Err.Code, true
	}
	return CKR_OK, false
}

// IsRetryable returns true if the error indicates a transient condition
// that may succeed if retried.
func IsRetryable(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_DEVICE_ERROR,
		CKR_DEVICE_MEMORY,
		CKR_HOST_MEMORY,
		CKR_SESSION_COUNT,
		CKR_TOKEN_RESOURCE_EXCEEDED:
		return true
	}
	return false
}

// IsAuthenticationError returns true if the error is related to authentication.
func IsAuthenticationError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_PIN_INCORRECT,
		CKR_PIN_INVALID,
		CKR_PIN_LEN_RANGE,
		CKR_PIN_EXPIRED,
		CKR_PIN_LOCKED,
		CKR_PIN_TOO_WEAK,
		CKR_USER_NOT_LOGGED_IN,
		CKR_USER_ALREADY_LOGGED_IN,
		CKR_USER_TYPE_INVALID,
		CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
		CKR_USER_PIN_NOT_INITIALIZED:
		return true
	}
	return false
}

// IsSessionError returns true if the error is related to session management.
func IsSessionError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_SESSION_CLOSED,
		CKR_SESSION_COUNT,
		CKR_SESSION_HANDLE_INVALID,
		CKR_SESSION_PARALLEL_NOT_SUPPORTED,
		CKR_SESSION_READ_ONLY,
		CKR_SESSION_EXISTS,
		CKR_SESSION_READ_ONLY_EXISTS,
		CKR_SESSION_READ_WRITE_SO_EXISTS,
		CKR_SESSION_ASYNC_NOT_SUPPORTED:
		return true
	}
	return false
}

// IsKeyError returns true if the error is related to key operations.
func IsKeyError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_KEY_HANDLE_INVALID,
		CKR_KEY_SIZE_RANGE,
		CKR_KEY_TYPE_INCONSISTENT,
		CKR_KEY_NOT_NEEDED,
		CKR_KEY_CHANGED,
		CKR_KEY_NEEDED,
		CKR_KEY_INDIGESTIBLE,
		CKR_KEY_FUNCTION_NOT_PERMITTED,
		CKR_KEY_NOT_WRAPPABLE,
		CKR_KEY_UNEXTRACTABLE,
		CKR_KEY_EXHAUSTED:
		return true
	}
	return false
}

// IsCryptographicError returns true if the error is related to cryptographic operations.
func IsCryptographicError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_MECHANISM_INVALID,
		CKR_MECHANISM_PARAM_INVALID,
		CKR_SIGNATURE_INVALID,
		CKR_SIGNATURE_LEN_RANGE,
		CKR_ENCRYPTED_DATA_INVALID,
		CKR_ENCRYPTED_DATA_LEN_RANGE,
		CKR_AEAD_DECRYPT_FAILED,
		CKR_DATA_INVALID,
		CKR_DATA_LEN_RANGE,
		CKR_WRAPPED_KEY_INVALID,
		CKR_WRAPPED_KEY_LEN_RANGE:
		return true
	}
	return false
}

// IsDeviceError returns true if the error is related to device/token issues.
func IsDeviceError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_DEVICE_ERROR,
		CKR_DEVICE_MEMORY,
		CKR_DEVICE_REMOVED,
		CKR_TOKEN_NOT_PRESENT,
		CKR_TOKEN_NOT_RECOGNIZED,
		CKR_TOKEN_WRITE_PROTECTED,
		CKR_TOKEN_RESOURCE_EXCEEDED,
		CKR_SLOT_ID_INVALID:
		return true
	}
	return false
}

// IsAsyncError returns true if the error is related to asynchronous operations.
func IsAsyncError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_PENDING,
		CKR_SESSION_ASYNC_NOT_SUPPORTED,
		CKR_OPERATION_CANCEL_FAILED:
		return true
	}
	return false
}

// IsValidationError returns true if the error is related to validation or parameter sets.
func IsValidationError(err error) bool {
	rv := FromError(err)
	switch rv {
	case CKR_OPERATION_NOT_VALIDATED,
		CKR_OPERATION_INCOMPATIBLE,
		CKR_PARAMETER_SET_NOT_SUPPORTED:
		return true
	}
	return false
}

// Configuration errors for module setup and initialization.
var (
	// ErrNilConfig indicates a nil configuration was provided.
	ErrNilConfig = errors.New("pkcs11/module: config is nil")

	// ErrEmptyTarget indicates the gRPC target is empty.
	ErrEmptyTarget = errors.New("pkcs11/module: target is required")

	// ErrInvalidTarget indicates the gRPC target format is invalid.
	ErrInvalidTarget = errors.New("pkcs11/module: invalid target format")

	// ErrInvalidTimeout indicates an invalid timeout value.
	ErrInvalidTimeout = errors.New("pkcs11/module: timeout must be non-negative")

	// ErrMissingTLSCert indicates TLS is enabled but certificate is missing.
	ErrMissingTLSCert = errors.New("pkcs11/module: TLS certificate file is required when key is specified")

	// ErrMissingTLSKey indicates TLS is enabled but key is missing.
	ErrMissingTLSKey = errors.New("pkcs11/module: TLS key file is required when certificate is specified")

	// ErrTLSCertNotFound indicates the TLS certificate file does not exist.
	ErrTLSCertNotFound = errors.New("pkcs11/module: TLS certificate file not found")

	// ErrTLSKeyNotFound indicates the TLS key file does not exist.
	ErrTLSKeyNotFound = errors.New("pkcs11/module: TLS key file not found")

	// ErrTLSCANotFound indicates the TLS CA file does not exist.
	ErrTLSCANotFound = errors.New("pkcs11/module: TLS CA file not found")

	// ErrConfigFileOpen indicates the configuration file could not be opened.
	ErrConfigFileOpen = errors.New("pkcs11/module: failed to open config file")

	// ErrConfigFileRead indicates the configuration file could not be read.
	ErrConfigFileRead = errors.New("pkcs11/module: failed to read config file")

	// ErrConfigFileParse indicates the configuration file could not be parsed.
	ErrConfigFileParse = errors.New("pkcs11/module: failed to parse config file")

	// ErrInvalidStorageType indicates an invalid storage type was specified.
	ErrInvalidStorageType = errors.New("pkcs11/module: invalid storage type")

	// ErrStoragePathRequired indicates a storage path is required for file storage.
	ErrStoragePathRequired = errors.New("pkcs11/module: storage path is required for file storage")

	// ErrStorageInit indicates storage initialization failed.
	ErrStorageInit = errors.New("pkcs11/module: failed to initialize storage")
)
