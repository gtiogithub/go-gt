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
package crypto

import (
	"errors"

	"gt.pro/gtio/go-gt/crypto/ed25519"
	"gt.pro/gtio/go-gt/crypto/keystore"
)

var (
	// ErrAlgorithmInvalid invalid Algorithm for sign.
	ErrAlgorithmInvalid = errors.New("invalid Algorithm")
)

// NewPrivateKey generate a privatekey
func NewPrivateKey(data []byte) (keystore.PrivateKey, error) {
	var (
		priv *ed25519.PrivateKey
		err  error
	)
	if len(data) == 0 {
		priv = ed25519.NewPrivateKey()
	} else {
		priv = new(ed25519.PrivateKey)
		err = priv.Decode(data)
	}
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func NewPrivateKeyFromSeed(seed []byte) (keystore.PrivateKey, error) {
	return ed25519.NewPrivateKeyFromSeed(seed)
}

// NewSignature returns a ed25519 signature
func NewSignature() (keystore.Signature, error) {
	return new(ed25519.Signature), nil
}
