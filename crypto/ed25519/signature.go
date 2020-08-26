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
	"gt.pro/gtio/go-gt/crypto/keystore"
	"errors"
)

type Message struct {
	signer []byte
	data   []byte
}

func (m *Message) GetData() []byte {
	return m.data
}

func (m *Message) GetSigner() []byte {
	return m.signer
}

// Signature signature ecdsa
type Signature struct {
	privateKey *PrivateKey
	publicKey  *PublicKey
}

// Algorithm secp256k1 algorithm
func (s *Signature) Algorithm() keystore.Algorithm {
	return keystore.ED25519
}

// InitSign ed25519 init sign
func (s *Signature) InitSign(priv keystore.PrivateKey) error {
	s.privateKey = priv.(*PrivateKey)
	return nil
}

// Sign ed25519 sign
func (s *Signature) Sign(data []byte) (out keystore.SignResult, err error) {
	if s.privateKey == nil {
		return nil, errors.New("please get private key first")
	}
	signature := s.privateKey.Sign(data)
	signer, err := s.privateKey.PublicKey().Encoded()
	if err != nil {
		return nil, err
	}
	return &Message{
		signer,
		signature,
	}, nil
}

// InitVerify ed25519 verify init
func (s *Signature) InitVerify(pub keystore.PublicKey) error {
	s.publicKey = pub.(*PublicKey)
	return nil
}

// Verify ed25519 verify
func (s *Signature) Verify(data []byte, signature keystore.SignResult) (bool, error) {
	if signature.GetSigner() != nil {
		s.publicKey = NewPublicKey(signature.GetSigner())
	}
	if s.publicKey == nil {
		return false, errors.New("please give public key first")
	}
	return s.publicKey.Verify(data, signature.GetData()), nil
}
