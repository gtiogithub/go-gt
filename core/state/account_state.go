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
	"fmt"
	"math/big"

	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

// accountState manages accounts state in Block.
type accountState struct {
	stateTrie    *trie.Trie
	dirtyAccount map[byteutils.HexHash]Account
	storage      cdb.Storage
}

// NewAccountState create a new account state
func NewAccountState(root byteutils.Hash, storage cdb.Storage) (AccountState, error) {
	stateTrie, err := trie.NewTrie(root, storage, false)
	if err != nil {
		return nil, err
	}

	return &accountState{
		stateTrie:    stateTrie,
		dirtyAccount: make(map[byteutils.HexHash]Account),
		storage:      storage,
	}, nil
}

// flush accounts
func (as *accountState) Flush() error {
	for addr, acc := range as.dirtyAccount {
		bytes, err := acc.ToBytes()
		if err != nil {
			return err
		}
		key, err := addr.Hash()
		if err != nil {
			return err
		}
		_, _ = as.stateTrie.Put(key, bytes)
	}
	as.dirtyAccount = make(map[byteutils.HexHash]Account)
	return nil
}

// abort
func (as *accountState) Abort() error {
	as.dirtyAccount = make(map[byteutils.HexHash]Account)
	return nil
}

// RootHash return root hash of account state
func (as *accountState) RootHash() byteutils.Hash {
	return as.stateTrie.RootHash()
}

// return accounts
func (as *accountState) Accounts() ([]Account, error) {
	var accounts []Account
	iter, err := as.stateTrie.Iterator(nil)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err != nil {
		return accounts, nil
	}
	exist, err := iter.Next()
	if err != nil {
		return nil, err
	}
	for exist {
		acc := new(account)
		err = acc.FromBytes(iter.Value(), as.storage)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
		exist, err = iter.Next()
		if err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

// DirtyAccounts return all changed accounts
func (as *accountState) DirtyAccounts() ([]Account, error) {
	var accounts []Account
	for _, account := range as.dirtyAccount {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// Relay merge the done account state
func (as *accountState) Replay(done AccountState) error {
	state := done.(*accountState)
	for addr, acc := range state.dirtyAccount {
		as.dirtyAccount[addr] = acc
	}
	return nil
}

// Clone an accountState
func (as *accountState) Copy() (AccountState, error) {
	stateTrie, err := as.stateTrie.Clone()
	if err != nil {
		return nil, err
	}

	dirtyAccount := make(map[byteutils.HexHash]Account)
	for addr, acc := range as.dirtyAccount {
		dirtyAccount[addr], err = acc.Copy()
		if err != nil {
			return nil, err
		}
	}

	return &accountState{
		stateTrie:    stateTrie,
		dirtyAccount: dirtyAccount,
		storage:      as.storage,
	}, nil
}

// GetOrCreateAccount according to the addr
func (as *accountState) GetOrCreateAccount(addr byteutils.Hash) (Account, error) {
	acc, err := as.getAccount(addr)
	if err != nil && err != ErrAccountNotFound {
		logging.CLog().WithFields(logrus.Fields{
			"addr": addr.String(),
			"err":  err,
		}).Error("as.getAccount failed")
		return nil, err
	}

	if err == ErrAccountNotFound {
		acc, err = as.newAccount(addr, nil, "")
		if err != nil {
			return nil, err
		}
		logging.CLog().WithFields(logrus.Fields{
			"addr": addr.String(),
		}).Debug("create acc success.")
		return acc, nil
	}

	return acc, nil
}

// get contract account
func (as *accountState) GetContractAccount(addr byteutils.Hash) (Account, error) {
	acc, err := as.getAccount(addr)
	if err != nil {
		if err == ErrAccountNotFound {
			err = ErrContractAccountNotFound
		}
		return nil, err
	}

	return acc, nil
}

// create a contract account
func (as *accountState) CreateContractAccount(addr byteutils.Hash, createdTx byteutils.Hash, version string) (Account, error) {
	return as.newAccount(addr, createdTx, version)
}

// return the string object of account state
func (as *accountState) String() string {
	return fmt.Sprintf("AccountState %p {RootHash:%s; dirtyAccount:%v; Storage:%p}",
		as,
		byteutils.Hex(as.stateTrie.RootHash()),
		as.dirtyAccount,
		as.storage,
	)
}

// new account
func (as *accountState) newAccount(addr byteutils.Hash, createdTx byteutils.Hash, version string) (Account, error) {
	variables, err := trie.NewTrie(nil, as.storage, false)
	if err != nil {
		return nil, err
	}

	contractFunAuths, err := trie.NewTrie(nil, as.storage, false)
	if err != nil {
		return nil, err
	}

	contractRoles, err := trie.NewTrie(nil, as.storage, false)
	if err != nil {
		return nil, err
	}

	contractCustomData, err := trie.NewTrie(nil, as.storage, false)
	if err != nil {
		return nil, err
	}

	txTrie, err := trie.NewTrie(nil, as.storage, false)
	if err != nil {
		return nil, err
	}
	acc := &account{
		address:            addr,
		balance:            big.NewInt(0),
		frozenFund:         big.NewInt(0),
		pledgeFund:         big.NewInt(0),
		nonce:              0,
		state:              AccountStateRunning,
		variables:          variables,
		creditIndex:        big.NewInt(0),
		birthTxHash:        createdTx,
		contractVersion:    version,
		permissions:        make([]*corepb.Permission, 0),
		integral:           make(map[uint64]*CreditIntegral),
		contractIntegral:   make(map[string]*ContractIntegral),
		contractFunAuths:   contractFunAuths,
		contractRoles:      contractRoles,
		contractCustomData: contractCustomData,
		txsCount:           0,
		txTrie:             txTrie,
		evil:               0,
		storage:            as.storage,
	}
	as.recordToDirty(addr, acc)
	return acc, nil
}

// record the account
func (as *accountState) recordToDirty(addr byteutils.Hash, acc Account) {
	as.dirtyAccount[addr.Hex()] = acc
}

// return an account by addr
func (as *accountState) getAccount(addr byteutils.Hash) (Account, error) {
	// search in dirty account
	if acc, ok := as.dirtyAccount[addr.Hex()]; ok {
		return acc, nil
	}

	// search in storage
	bytes, err := as.stateTrie.Get(addr)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err == nil {
		acc := new(account)
		err = acc.FromBytes(bytes, as.storage)
		if err != nil {
			return nil, err
		}
		as.recordToDirty(addr, acc)
		return acc, nil
	}

	return nil, ErrAccountNotFound
}
