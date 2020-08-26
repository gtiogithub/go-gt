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
package ed25519

import (
	"errors"
	"golang.org/x/crypto/ed25519"
)

var ( // ErrGetPublicKeyFailed private key to public failed
	ErrGetPublicKeyFailed = errors.New("private key to public failed")
	ErrGetSeedFailed      = errors.New("private key to seed failed")
)

// GetPublicKey private key to public key
func GetPublicKey(prikey []byte) ([]byte, error) {
	if len(prikey) != ed25519.PrivateKeySize {
		return nil, ErrGetPublicKeyFailed
	}
	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey, prikey[32:])
	return publicKey, nil
}

func GetSeed(prikey []byte) ([]byte, error) {
	if len(prikey) != ed25519.PrivateKeySize {
		return nil, ErrGetSeedFailed
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, prikey[:32])
	return seed, nil
}

// Verify verify with public key
func Verify(pubKey []byte, message, sig []byte) bool {
	return ed25519.Verify(pubKey, message, sig)
}

// Sign sign hash with private key
func Sign(priKey []byte, message []byte) []byte {
	return ed25519.Sign(priKey, message)
}
