//go:build qrdb_vector

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

// This file re-exports vector index types from go-qrdb/sdk/go that
// require the qrdb_vector build tag.

package xkms

import qrdb "github.com/jeremyhahn/go-qrdb/sdk/go"

// ==========================================================================
// HNSW index types
// ==========================================================================

// QRDBHNSWIndexImpl is the concrete HNSW index implementation.
type QRDBHNSWIndexImpl = qrdb.HNSWIndexImpl

// QRDBHNSWIndexConfig configures HNSW index parameters.
type QRDBHNSWIndexConfig = qrdb.HNSWIndexConfig

// QRDBNewHNSWIndexImpl creates a new HNSW index.
var QRDBNewHNSWIndexImpl = qrdb.NewHNSWIndexImpl

// QRDBHNSWDistanceMetric identifies the distance metric for HNSW indexes.
type QRDBHNSWDistanceMetric = qrdb.HNSWDistanceMetric

// QRDBHNSWDistanceMetric constants.
const (
	QRDBHNSWL2Distance         = qrdb.HNSWL2Distance
	QRDBHNSWCosineDistance     = qrdb.HNSWCosineDistance
	QRDBHNSWDotProductDistance = qrdb.HNSWDotProductDistance
	QRDBHNSWManhattanDistance  = qrdb.HNSWManhattanDistance
	QRDBHNSWHammingDistance    = qrdb.HNSWHammingDistance
)

// ==========================================================================
// Flat index types
// ==========================================================================

// QRDBFlatIndex is a brute-force vector index.
type QRDBFlatIndex = qrdb.FlatIndex

// QRDBFlatSearchResult holds a single flat index search result.
type QRDBFlatSearchResult = qrdb.FlatSearchResult

// QRDBNewFlatIndex creates a new flat (brute-force) vector index.
var QRDBNewFlatIndex = qrdb.NewFlatIndex

// ==========================================================================
// IVF index types
// ==========================================================================

// QRDBIVFIndex is the interface for IVF (Inverted File) indexes.
type QRDBIVFIndex = qrdb.IVFIndex

// QRDBIVFConfig configures IVF index parameters.
type QRDBIVFConfig = qrdb.IVFConfig

// QRDBIVFResult holds a single IVF search result.
type QRDBIVFResult = qrdb.IVFResult

// QRDBNewIVFIndex creates a new IVF index.
var QRDBNewIVFIndex = qrdb.NewIVFIndex

// QRDBIVFDistanceMetric identifies the distance metric for IVF indexes.
type QRDBIVFDistanceMetric = qrdb.IVFDistanceMetric

// QRDBIVFDistanceMetric constants.
const (
	QRDBIVFL2Distance         = qrdb.IVFL2Distance
	QRDBIVFCosineDistance     = qrdb.IVFCosineDistance
	QRDBIVFDotProductDistance = qrdb.IVFDotProductDistance
)

// ==========================================================================
// GPU index types
// ==========================================================================

// QRDBErrGPUNotCompiled is returned when GPU support is not compiled in.
var QRDBErrGPUNotCompiled = qrdb.ErrGPUNotCompiled
