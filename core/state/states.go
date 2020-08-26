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
	consensuspb "gt.pro/gtio/go-gt/consensus/pb"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/storage/mvccdb"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"math/big"

	"encoding/json"
)

type states struct {
	accState       AccountState
	txsState       *trie.Trie
	eventsState    *trie.Trie
	consensusState ConsensusState

	consensus Consensus
	changelog *mvccdb.MVCCDB
	stateDB   *mvccdb.MVCCDB
	innerDB   cdb.Storage
	txid      interface{}

	gasConsumed map[string]*big.Int
	events      map[string][]*Event
}

// get or create an account by addr
func (s *states) GetOrCreateAccount(addr byteutils.Hash) (Account, error) {
	acc, err := s.accState.GetOrCreateAccount(addr)
	if err != nil {
		return nil, err
	}
	return s.recordAccount(acc)
}

// get contract account by addr
func (s *states) GetContractAccount(addr byteutils.Hash) (Account, error) {
	acc, err := s.accState.GetContractAccount(addr)
	if err != nil {
		return nil, err
	}

	if len(acc.BirthTransaction()) == 0 {
		return nil, ErrContractCheckFailed
	}

	return s.recordAccount(acc)
}

// create a contract account
func (s *states) CreateContractAccount(owner byteutils.Hash, createdTx byteutils.Hash, version string) (Account, error) {
	acc, err := s.accState.CreateContractAccount(owner, createdTx, version)
	if err != nil {
		return nil, err
	}

	return s.recordAccount(acc)
}

// return the tx by tx hash
func (s *states) GetTx(txHash byteutils.Hash) ([]byte, error) {
	bytes, err := s.txsState.Get(txHash)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// put a tx into txs state
func (s *states) PutTx(txHash byteutils.Hash, txBytes []byte) error {
	_, err := s.txsState.Put(txHash, txBytes)
	if err != nil {
		return err
	}
	return nil
}

func (s *states) JoinElection(joinInfo byteutils.Hash) error {
	return s.consensusState.JoinElection(joinInfo)
}

func (s *states) CancelElection(election byteutils.Hash) error {
	return s.consensusState.CancelElection(election)
}

func (s *states) RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error {
	return s.consensusState.RecordEvil(txHash, address, reportType, report)
}

func (s *states) GetCouncil(termId uint64) (*corepb.Council, error) {
	return s.consensusState.GetCouncil(termId)
}

// reset the states
func (s *states) Reset(addr byteutils.Hash, isResetChangeLog bool) error {
	if err := s.stateDB.Reset(); err != nil {
		return err
	}
	if err := s.Abort(); err != nil {
		return err
	}
	if isResetChangeLog {
		if err := s.changelog.Reset(); err != nil {
			return err
		}
		if addr != nil {
			// record dependency
			if err := s.changelog.Put(addr, addr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *states) RecordGas(from string, gas *big.Int) {
	consumed, ok := s.gasConsumed[from]
	if !ok {
		consumed = big.NewInt(0)
	}
	consumed = new(big.Int).Add(consumed, gas)
	s.gasConsumed[from] = consumed
}

func (s *states) GetGas() map[string]*big.Int {
	gasConsumed := make(map[string]*big.Int)
	for from, gas := range s.gasConsumed {
		gasConsumed[from] = gas
	}
	s.gasConsumed = make(map[string]*big.Int)
	return gasConsumed
}

// return the block hash by height
func (s *states) GetBlockHashByHeight(height uint64) ([]byte, error) {
	bytes, err := s.innerDB.Get(byteutils.FromUint64(height))
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// return the block by height
func (s *states) GetBlock(hash byteutils.Hash) ([]byte, error) {
	bytes, err := s.innerDB.Get(hash)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// close the states
func (s *states) Close() error {
	if err := s.changelog.Close(); err != nil {
		return err
	}
	if err := s.stateDB.Close(); err != nil {
		return err
	}
	if err := s.Abort(); err != nil {
		return err
	}

	return nil
}

// flush the states
func (s *states) Flush() error {
	return s.accState.Flush()
}

// replay the states
func (s *states) Replay(done *states) error {
	err := s.accState.Replay(done.accState)
	if err != nil {
		return err
	}
	_, err = s.txsState.Replay(done.txsState)
	if err != nil {
		return err
	}
	err = s.ReplayEvent(done)
	if err != nil {
		return err
	}
	err = s.consensusState.Replay(done.consensusState)
	if err != nil {
		return err
	}

	// replay gasconsumed
	for from, gas := range done.gasConsumed {
		consumed, ok := s.gasConsumed[from]
		if !ok {
			consumed = big.NewInt(0)
		}
		consumed = new(big.Int).Add(consumed, gas)
		s.gasConsumed[from] = consumed
	}
	return nil
}

// return the events root
func (s *states) EventsRoot() byteutils.Hash {
	return s.eventsState.RootHash()
}

// fetch the events by tx hash
func (s *states) FetchEvents(txHash byteutils.Hash) ([]*Event, error) {
	var events []*Event
	iter, err := s.eventsState.Iterator(txHash)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err == nil {
		exist, err := iter.Next()
		if err != nil {
			return nil, err
		}
		for exist {
			event := new(Event)
			err = json.Unmarshal(iter.Value(), event)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
			exist, err = iter.Next()
			if err != nil {
				return nil, err
			}
		}
	}
	return events, nil
}

// replay the event
func (s *states) ReplayEvent(done *states) error {
	tx := done.txid.(string)
	events, ok := done.events[tx]
	if !ok {
		return nil
	}

	//replay event
	txHash, err := byteutils.FromHex(tx)
	if err != nil {
		return err
	}
	for idx, event := range events {
		cnt := int64(idx + 1)

		key := append(txHash, byteutils.FromInt64(cnt)...)
		bytes, err := json.Marshal(event)
		if err != nil {
			return err
		}

		_, err = s.eventsState.Put(key, bytes)
		if err != nil {
			return err
		}
	}

	done.events = make(map[string][]*Event)

	return nil
}

// copy the states
func (s *states) Copy() (*states, error) {
	changelog, err := newChangeLog()
	if err != nil {
		return nil, err
	}
	stateDB, err := newStateDB(s.innerDB)
	if err != nil {
		return nil, err
	}

	accState, err := NewAccountState(s.accState.RootHash(), stateDB)
	if err != nil {
		return nil, err
	}

	txsState, err := trie.NewTrie(s.txsState.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	eventState, err := trie.NewTrie(s.eventsState.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	consensusState, err := s.consensus.NewState(s.consensusState.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	return &states{
		accState:       accState,
		txsState:       txsState,
		eventsState:    eventState,
		consensusState: consensusState,
		consensus:      s.consensus,
		changelog:      changelog,
		stateDB:        stateDB,
		innerDB:        s.innerDB,
		txid:           s.txid,
		gasConsumed:    make(map[string]*big.Int),
		events:         make(map[string][]*Event),
	}, nil
}

// begin the states
func (s *states) Begin() error {
	if err := s.changelog.Begin(); err != nil {
		return err
	}
	if err := s.stateDB.Begin(); err != nil {
		return err
	}
	return nil
}

// commit the states
func (s *states) Commit() error {
	if err := s.Flush(); err != nil {
		return err
	}
	// changelog is used to check conflict temporarily
	// we should rollback it when the transaction is over
	if err := s.changelog.RollBack(); err != nil {
		return err
	}
	if err := s.stateDB.Commit(); err != nil {
		return err
	}

	// clear
	s.events = make(map[string][]*Event)
	s.gasConsumed = make(map[string]*big.Int)
	return nil
}

// roll back the sta
func (s *states) RollBack() error {
	if err := s.Abort(); err != nil {
		return err
	}
	if err := s.changelog.RollBack(); err != nil {
		return err
	}
	if err := s.stateDB.RollBack(); err != nil {
		return err
	}

	//
	s.events = make(map[string][]*Event)
	s.gasConsumed = make(map[string]*big.Int)
	return nil
}

// prepare the states
func (s *states) Prepare(txid interface{}) (*states, error) {
	changelog, err := s.changelog.Prepare(txid)
	if err != nil {
		return nil, err
	}
	stateDB, err := s.stateDB.Prepare(txid)
	if err != nil {
		return nil, err
	}

	// Flush all changes in world state into merkle trie make a snapshot of world state
	if err := s.Flush(); err != nil {
		return nil, err
	}

	accState, err := NewAccountState(s.AccountsRoot(), stateDB)
	if err != nil {
		return nil, err
	}

	txsState, err := trie.NewTrie(s.TxsRoot(), stateDB, true)
	if err != nil {
		return nil, err
	}

	eventsState, err := trie.NewTrie(s.EventsRoot(), stateDB, true)
	if err != nil {
		return nil, err
	}

	consensusState, err := s.consensus.NewState(s.consensusState.RootHash(), stateDB, true)
	if err != nil {
		return nil, err
	}

	return &states{
		accState:       accState,
		txsState:       txsState,
		eventsState:    eventsState,
		consensusState: consensusState,
		changelog:      changelog,
		stateDB:        stateDB,
		innerDB:        s.innerDB,
		txid:           txid,
		gasConsumed:    make(map[string]*big.Int),
		events:         make(map[string][]*Event),
	}, nil
}

// check and update states
func (s *states) CheckAndUpdateTo(parent *states) ([]interface{}, error) {
	dependency, err := s.changelog.CheckAndUpdate()
	if err != nil {
		return nil, err
	}
	_, err = s.stateDB.CheckAndUpdate()
	if err != nil {
		return nil, err
	}
	if err := parent.Replay(s); err != nil {
		return nil, err
	}
	return dependency, nil
}

// abort states
func (s *states) Abort() error {
	return s.accState.Abort()
}

// return account root
func (s *states) AccountsRoot() byteutils.Hash {
	return s.accState.RootHash()
}

// return tx root
func (s *states) TxsRoot() byteutils.Hash {
	return s.txsState.RootHash()
}

// return consensus root
func (s *states) ConsensusRoot() *consensuspb.ConsensusRoot {
	return s.consensusState.RootHash()
}

// return accounts
func (s *states) Accounts() ([]Account, error) {
	return s.accState.Accounts()
}

// load account states by account root
func (s *states) LoadAccountsRoot(root byteutils.Hash) error {
	accState, err := NewAccountState(root, s.stateDB)
	if err != nil {
		return err
	}
	s.accState = accState
	return nil
}

// load event states by events root
func (s *states) LoadEventsRoot(root byteutils.Hash) error {
	eventsState, err := trie.NewTrie(root, s.stateDB, false)
	if err != nil {
		return err
	}
	s.eventsState = eventsState
	return nil
}

//load consensus state by consensus root
func (s *states) LoadConsensusRoot(root *consensuspb.ConsensusRoot) error {
	consensusState, err := s.consensus.NewState(root, s.stateDB, false)
	if err != nil {
		return err
	}
	s.consensusState = consensusState
	return nil
}

// load tx states by tx root
func (s *states) LoadTxsRoot(root byteutils.Hash) error {
	txsState, err := trie.NewTrie(root, s.stateDB, false)
	if err != nil {
		return err
	}
	s.txsState = txsState
	return nil
}

// record account
func (s *states) recordAccount(acc Account) (Account, error) {
	if err := s.changelog.Put(acc.Address(), acc.Address()); err != nil {
		return nil, err
	}
	return acc, nil
}

// record event
func (s *states) RecordEvent(txHash byteutils.Hash, event *Event) {
	events, ok := s.events[txHash.String()]
	if !ok {
		events = make([]*Event, 0)
	}
	s.events[txHash.String()] = append(events, event)
}

// new states
func newStates(consensus Consensus, storage cdb.Storage) (*states, error) {
	changelog, err := newChangeLog()
	if err != nil {
		return nil, err
	}
	stateDB, err := newStateDB(storage)
	if err != nil {
		return nil, err
	}

	accState, err := NewAccountState(nil, stateDB)
	if err != nil {
		return nil, err
	}

	txsState, err := trie.NewTrie(nil, stateDB, false)
	if err != nil {
		return nil, err
	}

	eventsState, err := trie.NewTrie(nil, stateDB, false)
	if err != nil {
		return nil, err
	}

	consensusState, err := consensus.NewState(&consensuspb.ConsensusRoot{}, stateDB, false)
	if err != nil {
		return nil, err
	}

	return &states{
		accState:       accState,
		txsState:       txsState,
		eventsState:    eventsState,
		consensusState: consensusState,
		consensus:      consensus,
		changelog:      changelog,
		stateDB:        stateDB,
		innerDB:        storage,
		txid:           nil,
		gasConsumed:    make(map[string]*big.Int),
		events:         make(map[string][]*Event),
	}, nil
}

// new change log
func newChangeLog() (*mvccdb.MVCCDB, error) {
	mem, err := cdb.NewMemoryStorage()
	if err != nil {
		return nil, err
	}
	db, err := mvccdb.NewMVCCDB(mem, false)
	if err != nil {
		return nil, err
	}

	db.SetStrictGlobalVersionCheck(true)
	return db, nil
}

// new state db
func newStateDB(storage cdb.Storage) (*mvccdb.MVCCDB, error) {
	return mvccdb.NewMVCCDB(storage, true)
}
