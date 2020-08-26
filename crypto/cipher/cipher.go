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

// Encrypt interface for encrypt
type Encrypt interface {
	Encrypt(data []byte, passphrase []byte) ([]byte, error)
	Decrypt(data []byte, passphrase []byte) ([]byte, error)
	EncryptKey(addressStr string, data []byte, passphrase []byte) ([]byte, error)
	DecryptKey(data []byte, passphrase []byte) ([]byte, error)
}

type Cipher struct {
	cipher Encrypt
}

func NewCipher(alg uint8) *Cipher {
	c := new(Cipher)
	switch alg {
	case 1 << 4: //keysotore.SCRYPT
		c.cipher = new(Scrypt)
	default:
		panic("cipher not support the algorithm")
	}
	return c
}

func (c *Cipher) Encrypt(data []byte, passPhrase []byte) ([]byte, error) {
	return c.cipher.Encrypt(data, passPhrase)
}
func (c *Cipher) Decrypt(data []byte, passPhrase []byte) ([]byte, error) {
	return c.cipher.Decrypt(data, passPhrase)
}
func (c *Cipher) EncryptKey(addressStr string, data []byte, passPhrase []byte) ([]byte, error) {
	return c.cipher.EncryptKey(addressStr, data, passPhrase)
}
func (c *Cipher) DecryptKey(data []byte, passPhrase []byte) ([]byte, error) {
	return c.cipher.DecryptKey(data, passPhrase)
}
