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
package core

import (
	"github.com/btcsuite/btcutil/base58"
	"gt.pro/gtio/go-gt/crypto/hash"
	"gt.pro/gtio/go-gt/util/byteutils"
)

type AddressType byte

// UndefinedAddressType undefined
const UndefinedAddressType AddressType = 0x00

const (
	// AddressPaddingLength the length of headpadding in byte
	AddressPaddingLength = 1
	// AddressPaddingIndex the index of headpadding bytes
	AddressPaddingIndex = 0
	// AddressTypeLength the length of address type in byte
	AddressTypeLength = 1
	// AddressTypeIndex the index of address type bytes
	AddressTypeIndex = 1

	AddressVersionLength = 1
	// AddressVersionIndex the index of address version bytes
	AddressVersionIndex = 2

	// AddressDataLength the length of data of address in byte.
	AddressDataLength = 20

	// AddressChecksumLength the checksum of address in byte.
	AddressChecksumLength = 4

	AddressLength = AddressPaddingLength + AddressTypeLength + AddressVersionLength + AddressDataLength + AddressChecksumLength

	// AddressDataEnd the end of the address data
	AddressDataEnd = 23

	// AddressBase58Length length of base58(Address.address)
	AddressBase58Length = 37
	// PublicKeyDataLength length of public key
	PublicKeyDataLength = 32
)

// const
const (
	Padding byte = 0x72
)

const (
	AccountAddress AddressType = 0x4D + iota
	ContractAddress
)

const (
	AddressVersion = 0x86
	GtPrefix       = 'G'
)

type Address struct {
	address byteutils.Hash
}

func NewAddress(addr byteutils.Hash) *Address { return &Address{addr} }

func (a *Address) String() string {
	return base58.Encode(a.address)
}

func (a *Address) Bytes() []byte {
	return a.address
}

// Equals compare two Address. True is equal, otherwise false.
func (a *Address) Equals(b *Address) bool {
	if a == nil {
		return b == nil
	}
	if b == nil {
		return false
	}
	return a.address.Equals(b.address)
}

// Type return the type of address.
func (a *Address) Type() AddressType {
	if len(a.address) <= AddressTypeIndex {
		return UndefinedAddressType
	}
	return AddressType(a.address[AddressTypeIndex])
}

func (a *Address) IsContractAddress() bool {
	return a.Type() == ContractAddress
}

// NewAddressFromPublicKey return new address from publickey bytes
func NewAddressFromPublicKey(s []byte) (*Address, error) {
	if len(s) != PublicKeyDataLength {
		return nil, ErrInvalidArgument
	}
	return newAddress(AccountAddress, s)
}

// NewContractAddressFromData
func NewContractAddressFromData(from []byte, nonce []byte) (*Address, error) {
	if len(from) == 0 || len(nonce) == 0 {
		return nil, ErrInvalidArgument
	}

	return newAddress(ContractAddress, from, nonce)
}

func NewGaddress(t AddressType, v uint8, p uint8, args ...[]byte) (*Address, error) {
	if len(args) == 0 {
		return nil, ErrInvalidArgument
	}

	buffer := make([]byte, AddressLength)
	buffer[AddressPaddingIndex] = byte(p)
	buffer[AddressTypeIndex] = byte(t)

	buffer[AddressVersionIndex] = byte(v)
	sha := hash.Sha3256(args...)
	content := hash.Ripemd160(sha)
	copy(buffer[AddressVersionIndex+1:AddressDataEnd], content)

	cs := checkSum(buffer[:AddressDataEnd])
	copy(buffer[AddressDataEnd:], cs)

	return &Address{address: buffer}, nil
}

// NewAddress create new #Address according to data bytes.
func newAddress(t AddressType, args ...[]byte) (*Address, error) {
	if len(args) == 0 {
		return nil, ErrInvalidArgument
	}

	switch t {
	case AccountAddress, ContractAddress:
	default:
		return nil, ErrInvalidArgument
	}

	buffer := make([]byte, AddressLength)
	buffer[AddressPaddingIndex] = Padding
	buffer[AddressTypeIndex] = byte(t)

	buffer[AddressVersionIndex] = AddressVersion
	sha := hash.Sha3256(args...)
	content := hash.Ripemd160(sha)
	copy(buffer[AddressVersionIndex+1:AddressDataEnd], content)

	cs := checkSum(buffer[:AddressDataEnd])
	copy(buffer[AddressDataEnd:], cs)

	return &Address{address: buffer}, nil
}

func checkSum(data []byte) []byte {
	return hash.Sha3256(data)[:AddressChecksumLength]
}

func AddressParse(addStr string) (*Address, error) {
	if len(addStr) != AddressBase58Length || addStr[0] != GtPrefix {
		return nil, ErrInvalidAddressFormat
	}
	return AddressParseFromBytes(base58.Decode(addStr))
}

func AddressParseFromBytes(b []byte) (*Address, error) {
	if len(b) != AddressLength || b[AddressPaddingIndex] != Padding {
		return nil, ErrInvalidAddressFormat
	}

	switch AddressType(b[AddressTypeIndex]) {
	case AccountAddress, ContractAddress:
	default:
		return nil, ErrInvalidAddressType
	}

	if !byteutils.Equal(checkSum(b[:AddressDataEnd]), b[AddressDataEnd:]) {
		return nil, ErrInvalidAddressChecksum
	}

	return &Address{address: b}, nil
}
