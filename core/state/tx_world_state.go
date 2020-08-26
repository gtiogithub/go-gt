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
package state

import "gt.pro/gtio/go-gt/util/byteutils"

// txWorldState
type txWorldState struct {
	*states
	txid   interface{}
	parent *worldState
}

// check and update tx world state
func (txws *txWorldState) CheckAndUpdate() ([]interface{}, error) {
	dependencies, err := txws.states.CheckAndUpdateTo(txws.parent.states)
	if err != nil {
		return nil, err
	}
	txws.parent = nil
	return dependencies, nil
}

// reset tx world state
func (txws *txWorldState) Reset(addr byteutils.Hash, isResetChangeLog bool) error {
	if err := txws.states.Reset(addr, isResetChangeLog); err != nil {
		return err
	}
	return nil
}

// close tx world state
func (txws *txWorldState) Close() error {
	if err := txws.states.Close(); err != nil {
		return err
	}
	txws.parent = nil
	return nil
}

// return world state tx id
func (txws *txWorldState) TxID() interface{} {
	return txws.txid
}
