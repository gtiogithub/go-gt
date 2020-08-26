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
package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"gt.pro/gtio/go-gt/crypto/hash"
	"gt.pro/gtio/go-gt/util/logging"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/scrypt"
	"io"
)

const (
	ScryptKDF = "scrypt"
	ScryptR   = 8
	ScryptN   = 1 << 12
	// LightScryptP is the P parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	ScryptP = 6
	// ScryptDKLen get derived key length
	ScryptDKLen = 32
	// cipher the name of cipher
	cipherName     = "aes-128-ctr"
	currentVersion = 1

	macHash = "sha3256"
)

var (
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
	// ErrKDFInvalid cipher not supported
	ErrKDFInvalid = errors.New("kdf not supported")
	// ErrVersionInvalid version not supported
	ErrVersionInvalid = errors.New("version not supported")
)

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
	MACHash      string                 `json:"machash"`
}

//
type cipherparamsJSON struct {
	IV string `json:"iv"`
}

//
type encryptedKeyJSON struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	ID      string     `json:"id"`
	Version int        `json:"version"`
}

//

type Scrypt struct {
}

func (s *Scrypt) Encrypt(data []byte, passphrase []byte) ([]byte, error) {
	return s.ScryptEncrypt(data, passphrase, ScryptN, ScryptR, ScryptP)
}

func (s *Scrypt) EncryptKey(addressStr string, data []byte, passPhrase []byte) ([]byte, error) {
	cryptoJson, err := s.encryptData(data, passPhrase, ScryptN, ScryptR, ScryptP)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to encryptkey.")
		return nil, err
	}
	encryptedKeyJSON := encryptedKeyJSON{
		addressStr,
		*cryptoJson,
		uuid.NewV4().String(),
		currentVersion,
	}
	return json.Marshal(encryptedKeyJSON)

}

func (s *Scrypt) ScryptEncrypt(data []byte, passphrase []byte, N, r, p int) ([]byte, error) {
	crypto, err := s.encryptData(data, passphrase, N, r, p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(crypto)
}

func (s *Scrypt) encryptData(data, passphrase []byte, scryptN, scryptR, scryptP int) (*cryptoJSON, error) {
	salt := RandomCSPRNG(ScryptDKLen)
	derivedKey, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, ScryptDKLen)
	if err != nil {
		return nil, err
	}
	encryptKey := derivedKey[:16]

	iv := RandomCSPRNG(aes.BlockSize) // 16
	cipherText, err := s.aesCTRXOR(encryptKey, data, iv)
	if err != nil {
		return nil, err
	}

	//mac := hash.Sha3256(derivedKey[16:32], cipherText) // version3: deprecated
	mac := hash.Sha3256(derivedKey[16:32], cipherText, iv, []byte(cipherName))

	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = scryptP
	scryptParamsJSON["dklen"] = ScryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	crypto := &cryptoJSON{
		Cipher:       cipherName,
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          ScryptKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
		MACHash:      macHash,
	}
	return crypto, nil
}

func (s *Scrypt) Decrypt(data []byte, passphrase []byte) ([]byte, error) {
	crypto := new(cryptoJSON)
	if err := json.Unmarshal(data, crypto); err != nil {
		return nil, err
	}
	return s.decryptData(crypto, passphrase, currentVersion)
}
func (s *Scrypt) DecryptKey(keyjson []byte, passPhrase []byte) ([]byte, error) {

	keyJSON := new(encryptedKeyJSON)
	if err := json.Unmarshal(keyjson, keyJSON); err != nil {
		return nil, err
	}
	version := keyJSON.Version
	if version != currentVersion {
		return nil, ErrVersionInvalid
	}
	return s.decryptData(&keyJSON.Crypto, passPhrase, version)
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

func (s *Scrypt) decryptData(crypto *cryptoJSON, passphrase []byte, version int) ([]byte, error) {
	if crypto.Cipher != cipherName {
		logging.CLog().WithFields(logrus.Fields{
			"data": crypto.Cipher,
		}).Error("Cipher not supported.")
		return nil, fmt.Errorf("Cipher not supported: %v", crypto.Cipher)
	}
	mac, err := hex.DecodeString(crypto.MAC)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(crypto.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(crypto.CipherText)
	if err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(crypto.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}

	dklen := ensureInt(crypto.KDFParams["dklen"])
	var derivedKey = []byte{}
	if crypto.KDF == ScryptKDF {
		n := ensureInt(crypto.KDFParams["n"])
		r := ensureInt(crypto.KDFParams["r"])
		p := ensureInt(crypto.KDFParams["p"])
		derivedKey, err = scrypt.Key(passphrase, salt, n, r, p, dklen)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, ErrKDFInvalid
	}

	var calculatedMAC []byte

	if version == currentVersion {
		calculatedMAC = hash.Sha3256(derivedKey[16:32], cipherText, iv, []byte(crypto.Cipher))
	} else {
		return nil, ErrVersionInvalid
	}

	if !bytes.Equal(calculatedMAC, mac) {
		return nil, ErrDecrypt
	}

	key, err := s.aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Scrypt) aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

// RandomCSPRNG a cryptographically secure pseudo-random number generator
func RandomCSPRNG(n int) []byte {
	buff := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buff)
	if err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return buff
}
