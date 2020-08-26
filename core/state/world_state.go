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

import (
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/byteutils"
)

// WorldState manages all current states in Blockchain.
type worldState struct {
	*states
	snapshot *states
}

// NewWorldState create a new empty WorldState
func NewWorldState(consensus Consensus, storage cdb.Storage) (WorldState, error) {
	states, err := newStates(consensus, storage)
	if err != nil {
		return nil, err
	}
	return &worldState{
		states:   states,
		snapshot: nil,
	}, nil
}

// Clone a new WorldState
func (ws *worldState) Copy() (WorldState, error) {
	s, err := ws.states.Copy()
	if err != nil {
		return nil, err
	}
	return &worldState{
		states:   s,
		snapshot: nil,
	}, nil
}

// begin world state
func (ws *worldState) Begin() error {
	snapshot, err := ws.states.Copy()
	if err != nil {
		return err
	}
	if err := ws.states.Begin(); err != nil {
		return err
	}
	ws.snapshot = snapshot
	return nil
}

// commit world state
func (ws *worldState) Commit() error {
	if err := ws.states.Commit(); err != nil {
		return err
	}
	ws.snapshot = nil
	return nil
}

// roll back world state
func (ws *worldState) RollBack() error {
	if err := ws.states.RollBack(); err != nil {
		return err
	}
	ws.states = ws.snapshot
	ws.snapshot = nil
	return nil
}

// prepare world state
func (ws *worldState) Prepare(txid interface{}) (TxWorldState, error) {
	s, err := ws.states.Prepare(txid)
	if err != nil {
		return nil, err
	}
	txState := &txWorldState{
		states: s,
		txid:   txid,
		parent: ws,
	}
	return txState, nil
}

func (ws *worldState) NextConsensusState(info []byte) (ConsensusState, []*ElectionEvent, error) {
	return ws.states.consensusState.NextConsensusState(info, ws)
}

func (ws *worldState) SetConsensusState(consensusState ConsensusState) {
	ws.states.consensusState = consensusState
}

func (ws *worldState) FetchElectionEvent(txHash byteutils.Hash) (*ElectionEvent, error) {
	return ws.states.consensusState.FetchElectionEvent(txHash)
}

func (ws *worldState) GetCouncil(termId uint64) (*corepb.Council, error) {
	return ws.states.consensusState.GetCouncil(termId)
}
