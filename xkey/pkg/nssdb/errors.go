// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

// Package nssdb provides a pure Go NSS cert9.db/key4.db writer for adding
// trusted CA certificates to Chromium browser profiles.
package nssdb

import "errors"

// Database lifecycle errors.
var (
	// ErrDirNotExist is returned when the NSS database directory does not exist.
	ErrDirNotExist = errors.New("nssdb: directory does not exist")

	// ErrOpenDatabase is returned when a SQLite database cannot be opened.
	ErrOpenDatabase = errors.New("nssdb: failed to open database")

	// ErrCloseDatabase is returned when a SQLite database cannot be closed.
	ErrCloseDatabase = errors.New("nssdb: failed to close database")

	// ErrCreateSchema is returned when the database schema cannot be created.
	ErrCreateSchema = errors.New("nssdb: failed to create schema")

	// ErrWriterClosed is returned when an operation is attempted on a closed Writer.
	ErrWriterClosed = errors.New("nssdb: writer is closed")
)

// Certificate and trust object errors.
var (
	// ErrNilCertificate is returned when a nil certificate is provided.
	ErrNilCertificate = errors.New("nssdb: certificate is nil")

	// ErrEmptyLabel is returned when an empty label is provided.
	ErrEmptyLabel = errors.New("nssdb: label is empty")

	// ErrInsertCertificate is returned when inserting a certificate object fails.
	ErrInsertCertificate = errors.New("nssdb: failed to insert certificate object")

	// ErrInsertTrust is returned when inserting a trust object fails.
	ErrInsertTrust = errors.New("nssdb: failed to insert trust object")

	// ErrRemoveCertificate is returned when removing certificate objects fails.
	ErrRemoveCertificate = errors.New("nssdb: failed to remove certificate objects")

	// ErrRemoveTrust is returned when removing trust objects fails.
	ErrRemoveTrust = errors.New("nssdb: failed to remove trust objects")

	// ErrEmptyPrefix is returned when an empty prefix is provided to RemoveByPrefix.
	ErrEmptyPrefix = errors.New("nssdb: prefix is empty")

	// ErrBeginTx is returned when starting a database transaction fails.
	ErrBeginTx = errors.New("nssdb: failed to begin transaction")

	// ErrCommitTx is returned when committing a database transaction fails.
	ErrCommitTx = errors.New("nssdb: failed to commit transaction")

	// ErrSerialEncode is returned when DER-encoding a certificate serial number fails.
	ErrSerialEncode = errors.New("nssdb: failed to encode serial number")
)

// Password and signature errors.
var (
	// ErrPasswordInit is returned when initializing the key4.db password entry fails.
	ErrPasswordInit = errors.New("nssdb: failed to initialize password entry")

	// ErrSignatureInsert is returned when inserting a trust object signature fails.
	ErrSignatureInsert = errors.New("nssdb: failed to insert trust signature")

	// ErrASN1Marshal is returned when ASN.1 marshaling fails.
	ErrASN1Marshal = errors.New("nssdb: failed to marshal ASN.1 structure")

	// ErrEncrypt is returned when AES-256-CBC encryption fails.
	ErrEncrypt = errors.New("nssdb: encryption failed")

	// ErrInitDir is returned when initializing the NSS database directory fails.
	ErrInitDir = errors.New("nssdb: failed to initialize directory")

	// ErrWritePKCS11Txt is returned when writing pkcs11.txt fails.
	ErrWritePKCS11Txt = errors.New("nssdb: failed to write pkcs11.txt")
)
