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
package address

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gt.pro/gtio/go-gt/conf"
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/crypto"
	"gt.pro/gtio/go-gt/crypto/cipher"
	"gt.pro/gtio/go-gt/crypto/keystore"
	"gt.pro/gtio/go-gt/util"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

var (
	// ErrAddressNotFound address is not found.
	ErrAddressNotFound = errors.New("address is not found")
	// ErrAddressIsLocked address locked.
	ErrAddressIsLocked   = errors.New("address is locked")
	ErrInvalidPrivateKey = errors.New("private key is invalid")
	ErrInvalidMnemonic   = errors.New("mnemonic is invalid")
)

type addressInfo struct {
	// key address
	addr *core.Address
	// keystore save path
	path string
}

type AddressManager struct {
	ks        *keystore.Keystore // keystore
	keyDir    string             // key save path
	addresses []*addressInfo     // address slice
	mu        sync.Mutex
}

func NewAddressManager(config *config.Config) (*AddressManager, error) {
	am := new(AddressManager)
	am.ks = keystore.DefaultKS
	chainCfg := conf.GetChainConfig(config)

	tmpKeyDir, err := filepath.Abs(chainCfg.Keydir)
	if err != nil {
		return nil, err
	}
	am.keyDir = tmpKeyDir

	//if err := am.RefreshAddresses(); err != nil {
	//	return nil, err
	//}
	return am, err
}

func (am *AddressManager) GetKeyDir() string {
	return am.keyDir
}

func (am *AddressManager) GetKeyStore() *keystore.Keystore {
	return am.ks
}

// NewAccount returns a new address and keep it in keystore
func (am *AddressManager) NewAddress(passphrase []byte) (*core.Address, error) {
	privKey, err := crypto.NewPrivateKey(nil)
	if err != nil {
		return nil, err
	}

	addr, err := am.setKeyStore(privKey, passphrase)
	if err != nil {
		return nil, err
	}

	path, err := am.exportFile(addr, passphrase, false)
	if err != nil {
		return nil, err
	}

	am.updateAddressInfo(addr, path)

	return addr, nil
}

func (am *AddressManager) setKeyStore(privKey keystore.PrivateKey, passphrase []byte) (*core.Address, error) {
	pubKey, err := privKey.PublicKey().Encoded()
	if err != nil {
		return nil, err
	}
	addr, err := core.NewAddressFromPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	// set key to keystore
	err = am.ks.SetKey(addr.String(), privKey, passphrase)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// Contains returns if contains address
func (am *AddressManager) Contains(addr *core.Address) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, address := range am.addresses {
		if address.addr.Equals(addr) {
			return true
		}
	}
	return false
}

// Unlock unlock address with passphrase
func (am *AddressManager) Unlock(addr *core.Address, passphrase []byte, duration time.Duration) error {
	res, err := am.ks.ContainsAlias(addr.String())
	if err != nil || res == false {
		err = am.loadFile(addr, passphrase)
		if err != nil {
			return err
		}
	}
	return am.ks.Unlock(addr.String(), passphrase, duration)
}

// Lock lock address
func (am *AddressManager) Lock(addr *core.Address) error {
	return am.ks.Lock(addr.String())
}

// Accounts returns slice of address
func (am *AddressManager) Accounts() []*core.Address {
	_ = am.RefreshAddresses()

	am.mu.Lock()
	defer am.mu.Unlock()

	addrs := make([]*core.Address, len(am.addresses))
	for index, a := range am.addresses {
		addrs[index] = a.addr
	}
	return addrs
}

// loadFile import key to keystore in key dir
func (am *AddressManager) loadFile(addr *core.Address, passphrase []byte) error {
	address, err := am.GetAddressInfo(addr)
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadFile(address.path)
	if err != nil {
		return err
	}
	_, err = am.Load(raw, passphrase)
	return err
}

func (am *AddressManager) exportFile(addr *core.Address, passphrase []byte, overwrite bool) (path string, err error) {
	raw, err := am.Export(addr, passphrase)
	if err != nil {
		return "", err
	}

	acc, err := am.GetAddressInfo(addr)
	// acc not found
	if err != nil {
		path = filepath.Join(am.keyDir, addr.String())
	} else {
		path = acc.path
	}
	if err := util.FileWrite(path, raw, overwrite); err != nil {
		return "", err
	}
	return path, nil
}

func (am *AddressManager) ImportByPrivateKey(prikey, passphrase []byte) (*core.Address, error) {
	addr, err := am.LoadPrivate(prikey, passphrase)
	if err != nil {
		return nil, err
	}
	path, err := am.exportFile(addr, passphrase, false)
	if err != nil {
		return nil, err
	}

	am.updateAddressInfo(addr, path)
	return addr, nil
}

// Import import a key file to keystore, compatible ethereum keystore file, write to file
func (am *AddressManager) Import(keyjson, passphrase []byte) (*core.Address, error) {
	addr, err := am.Load(keyjson, passphrase)
	if err != nil {
		return nil, err
	}
	path, err := am.exportFile(addr, passphrase, false)
	if err != nil {
		return nil, err
	}
	am.updateAddressInfo(addr, path)

	return addr, nil
}

// Export export address to key file
func (am *AddressManager) Export(addr *core.Address, passphrase []byte) ([]byte, error) {
	key, err := am.ks.GetKey(addr.String(), passphrase)
	if err != nil {
		return nil, err
	}
	defer key.Clear()

	data, err := key.Encoded()
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(data)

	cpr := cipher.NewCipher(uint8(keystore.SCRYPT))
	out, err := cpr.EncryptKey(addr.String(), data, passphrase)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Remove remove address and encrypted private key from keystore
func (am *AddressManager) RemoveAddress(addr *core.Address, passphrase []byte) error {
	err := am.ks.Delete(addr.String(), passphrase)
	if err != nil {
		return err
	}

	return nil
}

func (am *AddressManager) GetAddressInfo(addr *core.Address) (*addressInfo, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, address := range am.addresses {
		if address.addr.Equals(addr) {
			return address, nil
		}
	}
	return nil, ErrAddressNotFound
}

func (am *AddressManager) updateAddressInfo(addr *core.Address, path string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var target *addressInfo
	for _, address := range am.addresses {
		if address.addr.Equals(addr) {
			target = address
			break
		}
	}
	if target != nil {
		target.path = path
	} else {
		target = &addressInfo{addr: addr, path: path}
		am.addresses = append(am.addresses, target)
	}
}

// Load load a key file to keystore, unable to write file
func (am *AddressManager) Load(keyjson, passphrase []byte) (*core.Address, error) {
	cpr := cipher.NewCipher(uint8(keystore.SCRYPT))
	data, err := cpr.DecryptKey(keyjson, passphrase)
	if err != nil {
		return nil, err
	}
	return am.LoadPrivate(data, passphrase)
}

// LoadPrivate load a private key to keystore, unable to write file
func (am *AddressManager) LoadPrivate(privkey, passphrase []byte) (*core.Address, error) {
	defer ZeroBytes(privkey)
	priv, err := crypto.NewPrivateKey(privkey)
	if err != nil {
		return nil, err
	}
	defer priv.Clear()

	addr, err := am.setKeyStore(priv, passphrase)
	if err != nil {
		return nil, err
	}

	if _, err := am.GetAddressInfo(addr); err != nil {
		am.mu.Lock()
		address := &addressInfo{addr: addr, path: filepath.Join(am.keyDir, addr.String())}
		am.addresses = append(am.addresses, address)
		am.mu.Unlock()
	}
	return addr, nil
}

// Update update addr locked passphrase
func (am *AddressManager) UpdatePassphrase(addr *core.Address, oldPassphrase, newPassphrase []byte) error {
	key, err := am.ks.GetKey(addr.String(), oldPassphrase)
	if err != nil {
		err = am.loadFile(addr, oldPassphrase)
		if err != nil {
			return err
		}
		key, err = am.ks.GetKey(addr.String(), oldPassphrase)
		if err != nil {
			return err
		}
	}
	defer key.Clear()

	if _, err := am.setKeyStore(key.(keystore.PrivateKey), newPassphrase); err != nil {
		return err
	}
	path, err := am.exportFile(addr, newPassphrase, true)
	if err != nil {
		return err
	}

	am.updateAddressInfo(addr, path)
	return nil
}

// SignHash sign hash
func (am *AddressManager) SignHash(addr *core.Address, hash byteutils.Hash) (keystore.SignResult, error) {
	key, err := am.ks.GetUnlocked(addr.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":  err,
			"addr": addr,
			"hash": hash,
		}).Error("Failed to get unlocked private key.")
		return nil, ErrAddressIsLocked
	}

	signature, err := crypto.NewSignature()
	if err != nil {
		return nil, err
	}

	if err := signature.InitSign(key.(keystore.PrivateKey)); err != nil {
		return nil, err
	}

	signData, err := signature.Sign(hash)
	if err != nil {
		return nil, err
	}
	return signData, nil
}

func (am *AddressManager) VerifySign(addr *core.Address, sign byteutils.Hash, msg byteutils.Hash) (bool, error) {
	key, err := am.ks.GetUnlocked(addr.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":  err,
			"addr": addr,
			"hash": byteutils.Hex(sign),
		}).Error("Failed to get unlocked private key.")
		return false, ErrAddressIsLocked
	}
	publicKey := key.(keystore.PrivateKey).PublicKey()
	verify := publicKey.Verify(msg, sign)
	return verify, nil
}

// GetMnemonic
func (am *AddressManager) GetMnemonic(addr *core.Address, passphrase []byte) (string, error) {
	key, err := am.ks.GetKey(addr.String(), passphrase)
	if err != nil {
		return "", err
	}
	defer key.Clear()

	seed, err := key.(keystore.PrivateKey).Seed()
	if err != nil {
		return "", err
	}

	return bip39.NewMnemonic(seed)
}

//
func (am *AddressManager) GetPrivateKeyBytMnemonic(memo string) ([]byte, error) {
	if !bip39.IsMnemonicValid(memo) {
		return nil, ErrInvalidMnemonic
	}
	seed, err := bip39.EntropyFromMnemonic(memo)
	if err != nil {
		return nil, ErrInvalidMnemonic
	}
	privKey, err := crypto.NewPrivateKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return privKey.Encoded()
}

//
func (am *AddressManager) RefreshAddresses() error {
	exist, err := util.FileExists(am.keyDir)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Can't find the path")
		return err
	}

	if !exist {
		if err := os.MkdirAll(am.keyDir, 0700); err != nil {
			panic("Failed to create keystore folder:" + am.keyDir + ". err:" + err.Error())
		}
	}

	files, err := ioutil.ReadDir(am.keyDir)
	if err != nil {
		return err
	}

	var (
		addresses []*addressInfo
	)

	for _, file := range files {
		acc, err := am.loadKeyFile(file)
		if err != nil {
			// errors have been recorded
			continue
		}
		addresses = append(addresses, acc)
	}
	am.addresses = addresses
	return nil
}

//
func (am *AddressManager) loadKeyFile(file os.FileInfo) (*addressInfo, error) {
	var (
		keyJSON struct {
			Address string `json:"address"`
		}
	)

	path := filepath.Join(am.keyDir, file.Name())

	if file.IsDir() || strings.HasPrefix(file.Name(), ".") || strings.HasSuffix(file.Name(), "~") {
		logging.VLog().WithFields(logrus.Fields{
			"path": path,
		}).Warn("Skipped this key file.")
		return nil, errors.New("file need skip")
	}

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to read the key file")
		return nil, errors.New("failed to read the key file")
	}

	keyJSON.Address = ""
	err = json.Unmarshal(raw, &keyJSON)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to parse the key file")
		return nil, errors.New("failed to parse the key file")
	}

	addr, err := core.AddressParse(keyJSON.Address)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":     err,
			"address": keyJSON.Address,
		}).Error("Failed to parse the address.")
		return nil, errors.New("failed to parse the address")
	}
	acc := &addressInfo{addr, path}
	return acc, nil
}

//
func ZeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

// SignBlock sign block with the specified algorithm
func (am *AddressManager) SignBlock(addr *core.Address, block *core.Block) error {
	key, err := am.ks.GetUnlocked(addr.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":   err,
			"block": block,
		}).Error("Failed to get unlocked private key to sign block.")
		return ErrAddressIsLocked
	}

	signature, err := crypto.NewSignature()
	if err != nil {
		return err
	}
	err = signature.InitSign(key.(keystore.PrivateKey))
	if err != nil {
		return err
	}

	return block.Sign(signature)
}

//
func (am *AddressManager) SignTx(addr *core.Address, tx *core.Transaction) error {
	key, err := am.ks.GetUnlocked(addr.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":         err,
			"transaction": tx,
		}).Error("Failed to get unlocked private key to sign block.")
		return ErrAddressIsLocked
	}
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
