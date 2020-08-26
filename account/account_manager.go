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
package account

import (
	"sync"
	"time"

	"gt.pro/gtio/go-gt/crypto/ed25519/vrf"
	"gt.pro/gtio/go-gt/crypto/hash"

	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/core/address"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/crypto"
	"gt.pro/gtio/go-gt/crypto/keystore"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	DefaultAddressUnlockedDuration = time.Second * 60
)

var (
	ErrInitDBError       = errors.New("Failure of database initialization")
	WorldStateIsNil      = errors.New("world state is nil")
	ErrPrivateHasExisted = errors.New("private key has existed")
	ErrAccountIsLocked   = errors.New("account is locked")
	// ErrInvalidSignerAddress sign addr not from
	ErrInvalidSignerAddress = errors.New("transaction sign not use from address")
)

type AccountManager struct {
	addrManger *address.AddressManager
	db         cdb.Storage
	watcher    *watcher
	mutex      sync.Mutex
}

func (am *AccountManager) GetAddrManager() *address.AddressManager { return am.addrManger }

func NewAccountManager(config *config.Config, db cdb.Storage) (*AccountManager, error) {
	if config == nil || db == nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": core.ErrInvalidArgument,
		}).Error("Failed to init AccountManager")
		return nil, core.ErrInvalidArgument
	}
	accMgr := new(AccountManager)
	var err error
	accMgr.addrManger, err = address.NewAddressManager(config)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to create address manager")
		return nil, err
	}
	accMgr.db = db

	if accMgr.db == nil {
		logging.CLog().WithFields(logrus.Fields{}).Error("Failed to init db")
		return nil, ErrInitDBError
	}

	accMgr.watcher = newWatcher(accMgr.addrManger)

	accMgr.init()

	return accMgr, nil
}

func (am *AccountManager) AddressManager() *address.AddressManager {
	return am.addrManger
}

// NewAccount return address, mnemonicWord
func (am *AccountManager) NewAccount(passphrase []byte) (*core.Address, string, error) {
	add, err := am.addrManger.NewAddress(passphrase)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to new account")
		return nil, "", err
	}
	memo, err := am.addrManger.GetMnemonic(add, passphrase)
	if err != nil {
		return nil, "", err
	}
	return add, memo, nil
}

func (am *AccountManager) AddressIsValid(address string) (*core.Address, error) {
	addr, err := core.AddressParse(address)
	if err != nil {
		return nil, err
	}
	return addr, err
}

func (am *AccountManager) UpdateAccount(address *core.Address, oldPassphrase, newPassphrase []byte) error {
	addr, err := am.AddressIsValid(address.String())
	if err != nil {
		return err
	}
	return am.addrManger.UpdatePassphrase(addr, oldPassphrase, newPassphrase)
}

func (am *AccountManager) ImportAccount(priKey, passphrase []byte) (*core.Address, error) {
	err := am.CheckRepeated(priKey)
	if err != nil {
		return nil, err
	}
	addr, err := am.addrManger.ImportByPrivateKey(priKey, passphrase)
	if err != nil {
		return nil, err
	}
	return addr, err
}

func (am *AccountManager) GetPrivateKey(address *core.Address, passphrase []byte) ([]byte, error) {
	err := am.addrManger.Unlock(address, passphrase, DefaultAddressUnlockedDuration)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to unlock private key ")
		return nil, ErrAccountIsLocked
	}
	key, err := am.addrManger.GetKeyStore().GetUnlocked(address.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to unlock private key ")
		return nil, ErrAccountIsLocked
	}
	bytes := make([]byte, 0)
	defer func() {
		key.Clear()
		am.addrManger.Lock(address)
	}()
	privateKey, err := key.(keystore.PrivateKey).Encoded()
	if err != nil {
		return nil, err
	}
	bytes = append(bytes, privateKey...)
	return bytes, nil
}

func (am *AccountManager) GetAllAddress() []*core.Address {
	return am.addrManger.Accounts()
}

func (am *AccountManager) Sign(address *core.Address, hash []byte) ([]byte, error) {
	signResult, err := am.addrManger.SignHash(address, hash)
	if err != nil {
		return nil, err
	}
	return signResult.GetData(), nil
}

func (am *AccountManager) SignBlock(address *core.Address, block *core.Block) error {
	return am.addrManger.SignBlock(address, block)
}

func (am *AccountManager) SignTx(addr *core.Address, tx *core.Transaction) error {
	return am.addrManger.SignTx(addr, tx)
}
func (am *AccountManager) SignTxWithPassphrase(addr *core.Address, tx *core.Transaction, passphrase []byte) error {
	// check sign addr is tx's from addr
	if !tx.From().Equals(addr) {
		return ErrInvalidSignerAddress
	}

	err := am.addrManger.Unlock(addr, passphrase, DefaultAddressUnlockedDuration)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"tx":  tx,
		}).Error("Failed to unlock private key to sign transaction")
		return ErrAccountIsLocked
	}
	key, err := am.addrManger.GetKeyStore().GetUnlocked(addr.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"tx":  tx,
		}).Error("Failed to unlock private key to sign transaction")
		return ErrAccountIsLocked
	}
	defer func() {
		key.Clear()
		am.addrManger.Lock(addr)
	}()

	signature, err := crypto.NewSignature()
	if err != nil {
		return err
	}
	err = signature.InitSign(key.(keystore.PrivateKey))
	if err != nil {
		return err
	}
	return tx.Sign(signature)
}

func (am *AccountManager) Verify(addr *core.Address, message, sig []byte) (bool, error) {
	return am.addrManger.VerifySign(addr, sig, message)
}

func (am *AccountManager) UnLock(address *core.Address, passphrase []byte, duration time.Duration) error {
	if duration == 0 {
		duration = DefaultAddressUnlockedDuration
	}
	return am.addrManger.Unlock(address, passphrase, duration)
}

func (am *AccountManager) Lock(address *core.Address) error {
	return am.addrManger.Lock(address)
}

func GetAccountByAddress(address string, worldState state.WorldState) (state.Account, error) {
	if worldState == nil {
		return nil, WorldStateIsNil
	}
	addr, err := core.AddressParse(address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"address": address,
			"error":   err,
		}).Error("address parse error")
		return nil, err
	}
	account, err := worldState.GetOrCreateAccount(addr.Bytes())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"address": address,
			"error":   err,
		}).Error("get account by address error")
		return nil, err
	}
	return account, nil
}

func (am *AccountManager) CheckRepeated(privKey []byte) error {
	key, err := crypto.NewPrivateKey(privKey)
	if err != nil {
		return err
	}
	pubKey, err := key.PublicKey().Encoded()
	if err != nil {
		return err
	}
	addr, err := core.NewAddressFromPublicKey(pubKey)
	if err != nil {
		return err
	}
	contains := am.addrManger.Contains(addr)
	if contains {
		return ErrPrivateHasExisted
	}
	return nil
}

// GenerateRandomSeed generate rand
func (am *AccountManager) GenerateRandomSeed(addr *core.Address, ancestorHash, parentSeed []byte) (vrfSeed, vrfProof []byte, err error) {

	key, err := am.addrManger.GetKeyStore().GetUnlocked(addr.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":  err,
			"addr": addr.String(),
		}).Error("Failed to get unlocked private key to generate block rand.")
		return nil, nil, ErrAccountIsLocked
	}

	secKey, _ := key.(keystore.PrivateKey).Encoded()
	sk := vrf.PrivateKey(secKey)
	data := hash.Sha3256(ancestorHash, parentSeed)
	seed, proof := sk.Prove(data, false)
	return seed[:], proof, nil
}

func (am *AccountManager) init() {
	am.mutex.Lock()
	if am.watcher.running {
		am.mutex.Unlock()
		return
	}
	am.watcher.start()
	am.mutex.Unlock()
	am.addrManger.RefreshAddresses()
}

func (am *AccountManager) Stop() {
	am.mutex.Lock()
	am.watcher.close()
	am.mutex.Unlock()
}
