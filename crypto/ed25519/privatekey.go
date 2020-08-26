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
	"crypto/rand"
	"gt.pro/gtio/go-gt/crypto/keystore"
	"gt.pro/gtio/go-gt/util/logging"
	"errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"io"
)

var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidSeed       = errors.New("invalid seed")
)

type PrivateKey struct {
	seckey []byte
}

func (k *PrivateKey) Algorithm() keystore.Algorithm {
	return keystore.ED25519
}

// Encoded encoded to byte
func (k *PrivateKey) Encoded() ([]byte, error) {
	return k.seckey, nil
}

// Decode decode data to key
func (k *PrivateKey) Decode(data []byte) error {
	if len(data) != ed25519.PrivateKeySize {
		return ErrInvalidPrivateKey
	}
	k.seckey = data
	return nil
}

func NewPrivateKey() *PrivateKey {
	keyseed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, keyseed); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	seckey := ed25519.NewKeyFromSeed(keyseed)
	return &PrivateKey{
		seckey,
	}
}

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidSeed
	}
	seckey := ed25519.NewKeyFromSeed(seed)
	return &PrivateKey{
		seckey,
	}, nil
}

// Clear clear key content
func (k *PrivateKey) Clear() {
	for i := range k.seckey {
		k.seckey[i] = 0
	}
}

// PublicKey returns publickey
func (k *PrivateKey) PublicKey() keystore.PublicKey {
	pub, err := GetPublicKey(k.seckey)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get public key.")
		return nil
	}
	return NewPublicKey(pub)
}

func (key *PrivateKey) Sign(hash []byte) []byte {
	return ed25519.Sign(key.seckey, hash)
}

// Seed returns seed
func (k *PrivateKey) Seed() ([]byte, error) {
	if len(k.seckey) != ed25519.PrivateKeySize {
		return nil, ErrGetSeedFailed
	}
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, k.seckey[:32])
	return seed, nil
}
