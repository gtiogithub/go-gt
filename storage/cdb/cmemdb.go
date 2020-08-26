// Copyright (C) 2018 go-gt authors
//
// This file is part of the go-gt library.
//
// the go-gt library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// the go-gt library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-gt library.  If not, see <http://www.gnu.org/licenses/>.
//

package cdb

import (
	"sync"

	"gt.pro/gtio/go-gt/util/byteutils"
)

// MemoryDB the nodes in trie.
type MemoryDB struct {
	data *sync.Map
}

// kv entry
type kv struct{ k, v []byte }

// MemoryBatch do batch task in memory storage
type MemoryBatch struct {
	db      *MemoryDB
	entries []*kv
}

// NewMemoryStorage init a storage
func NewMemoryStorage() (*MemoryDB, error) {
	return &MemoryDB{
		data: new(sync.Map),
	}, nil
}

// Get return value to the key in Storage
func (db *MemoryDB) Get(key []byte) ([]byte, error) {
	if entry, ok := db.data.Load(byteutils.Hex(key)); ok {
		return entry.([]byte), nil
	}
	return nil, ErrKeyNotFound
}

// Put put the key-value entry to Storage
func (db *MemoryDB) Put(key []byte, value []byte) error {
	db.data.Store(byteutils.Hex(key), value)
	return nil
}

// Del delete the key in Storage.
func (db *MemoryDB) Del(key []byte) error {
	db.data.Delete(byteutils.Hex(key))
	return nil
}

// EnableBatch enable batch write.
func (db *MemoryDB) EnableBatch() {
}

// Flush write and flush pending batch write.
func (db *MemoryDB) Flush() error {
	return nil
}

// DisableBatch disable batch write.
func (db *MemoryDB) DisableBatch() {
}

func (db *MemoryDB) Has(key []byte) (bool, error) {
	_, ok := db.data.Load(key)
	return ok, nil
}

func (db *MemoryDB) ValueSize() int {
	return 0
}

func (db *MemoryDB) Close() error {
	return nil
}

func (db *MemoryDB) Delete(key []byte) error {
	db.data.Delete(key)
	return nil
}
