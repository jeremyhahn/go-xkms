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

package ca

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// getObject returns the blob stored under key in the CA's object store.
// go-qrdb storage reports a missing key as a nil value rather than an error,
// so a nil value is surfaced here as ErrObjectNotFound.
func (ca *CA) getObject(key string) ([]byte, error) {
	data, err := ca.objectStore.Get([]byte(key))
	if err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("get %s: %v", key, err)}
	}
	if data == nil {
		return nil, &errs.Detail{Err: ErrObjectNotFound, Detail: key}
	}
	return data, nil
}

// putObject stores data under key in the CA's object store.
func (ca *CA) putObject(key string, data []byte) error {
	if err := ca.objectStore.Set([]byte(key), data); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("set %s: %v", key, err)}
	}
	return nil
}

// listObjects returns every key in the CA's object store under prefix.
func (ca *CA) listObjects(prefix string) ([]string, error) {
	keys, err := ca.objectStore.List([]byte(prefix))
	if err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("list %s: %v", prefix, err)}
	}
	names := make([]string, len(keys))
	for i, key := range keys {
		names[i] = string(key)
	}
	return names, nil
}
