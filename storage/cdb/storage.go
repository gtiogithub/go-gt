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
)

var (
	ErrKeyNotFound = errors.New("not found")
)

//
type Reader interface {
	Has(key []byte) (bool, error)
	Get(key []byte) ([]byte, error)
}

//
type Writer interface {
	Delete(key []byte) error
	Put(key, value []byte) error
}

//
type Stater interface {
	Stat(property string) (string, error)
}

//
type Compacter interface {
	Compact(start []byte, limit []byte) error
}

type Storage interface {
	Reader
	Writer
	Close() error
	Batcher
}
