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
	"errors"
	"github.com/boltdb/bolt"
)

var (
	ErrBucketNotExist = errors.New("bucket does not exist")
	ErrKeyNotExist    = errors.New("key does not exist")
)

// GtDB is a persistent key-value store.
type GtDB struct {
	fn string   // db filename
	db *bolt.DB // db
}

//
func NewGtDB(filename string) (*GtDB, error) {
	db, err := bolt.Open(filename, 0600, nil)
	if err != nil {
		return nil, err
	}
	cdb := &GtDB{
		fn: filename,
		db: db,
	}
	return cdb, nil
}

//
func (c *GtDB) Has(bucket, key []byte) bool {
	if err := c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrBucketNotExist
		}
		if data := b.Get(key); data == nil {
			return ErrKeyNotExist
		}
		return nil
	}); err != nil {
		return false
	}
	return true
}

//
func (c *GtDB) Get(bucket, key []byte) []byte {
	var data []byte
	if err := c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrBucketNotExist
		}
		if data = b.Get(key); data == nil {
			return ErrKeyNotExist
		}
		return nil
	}); err != nil {
		return nil
	}
	return data
}

//
func (c *GtDB) Put(bucket, key, value []byte) error {
	if err := c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			if newBucket, err := tx.CreateBucket(bucket); err == nil {
				return err
			} else {
				b = newBucket
			}
		}
		if err := b.Put(key, value); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

//
func (c *GtDB) Delete(bucket, key []byte) error {
	if err := c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return ErrBucketNotExist
		}
		if err := b.Delete(key); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
