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
	"gt.pro/gtio/go-gt/util/byteutils"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"sync"
)

const (
	minCache   = 16
	minHandles = 16
)

type LevelDB struct {
	ldb         *leveldb.DB
	enableBatch bool
	filename    string
	mutex       sync.Mutex
	batchOpts   map[string]*batchOpt
}

type batchOpt struct {
	key     []byte
	value   []byte
	deleted bool
}

func NewLevelDB(dbcfg *DbConfig, cache int, handles int) (*LevelDB, error) {
	if cache < minCache {
		cache = minCache
	}
	if handles < minHandles {
		handles = minHandles
	}

	db, err := leveldb.OpenFile(dbcfg.DbDir, &opt.Options{
		OpenFilesCacheCapacity: handles,
		BlockCacheCapacity:     cache / 2 * opt.MiB,
		WriteBuffer:            cache / 4 * opt.MiB, // Two of these are used internally
		Filter:                 filter.NewBloomFilter(10),
	})

	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(dbcfg.DbDir, nil)
	}
	if err != nil {
		return nil, err
	}

	enableBatch := dbcfg.EnableBatch

	ldb := &LevelDB{
		ldb:         db,
		enableBatch: enableBatch,
		filename:    dbcfg.DbDir,
		batchOpts:   make(map[string]*batchOpt),
	}

	return ldb, nil
}

func (db *LevelDB) Close() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	return db.ldb.Close()
}

func (db *LevelDB) Has(key []byte) (bool, error) {
	return db.ldb.Has(key, nil)
}

func (db *LevelDB) Get(key []byte) ([]byte, error) {
	value, err := db.ldb.Get(key, nil)
	if err != nil && err == leveldb.ErrNotFound {
		return nil, ErrKeyNotFound
	}
	return value, err
}

func (db *LevelDB) Put(key, value []byte) error {
	if db.enableBatch {
		db.mutex.Lock()
		defer db.mutex.Unlock()

		db.batchOpts[byteutils.Hex(key)] = &batchOpt{
			key:     key,
			value:   value,
			deleted: false,
		}

		return nil
	}
	return db.ldb.Put(key, value, nil)
}

func (db *LevelDB) Delete(key []byte) error {
	if db.enableBatch {
		db.mutex.Lock()
		defer db.mutex.Unlock()

		db.batchOpts[byteutils.Hex(key)] = &batchOpt{
			key:     key,
			deleted: true,
		}

		return nil
	}

	return db.ldb.Delete(key, nil)
}

func (db *LevelDB) EnableBatch() {
	db.enableBatch = true
}

func (db *LevelDB) DisableBatch() {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.batchOpts = make(map[string]*batchOpt)
	db.enableBatch = false
}

//
func (db *LevelDB) ValueSize() int {
	if db.batchOpts == nil {
		return 0
	}
	return len(db.batchOpts)
}

func (db *LevelDB) Flush() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if !db.enableBatch {
		return nil
	}
	batch := new(leveldb.Batch)

	for _, opt := range db.batchOpts {
		if opt.deleted {
			batch.Delete(opt.key)
		} else {
			batch.Put(opt.key, opt.value)
		}
	}
	db.batchOpts = make(map[string]*batchOpt)

	return db.ldb.Write(batch, nil)
}

func (db *LevelDB) NewIterator() Iterator {
	return db.NewIteratorWithPrefix(nil)
}

func (db *LevelDB) NewIteratorWithPrefix(prefix []byte) Iterator {
	return db.ldb.NewIterator(util.BytesPrefix(prefix), nil)
}

func (db *LevelDB) Compact(start []byte, limit []byte) error {
	return db.ldb.CompactRange(util.Range{Start: start, Limit: limit})
}
