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

package keystore

type SignResult interface {
	// GetSigner return signer public key
	GetSigner() []byte

	// Signature result
	GetData() []byte
}

// Signature interface of different signature algorithm
type Signature interface {

	// Algorithm returns the standard algorithm for this key.
	Algorithm() Algorithm

	// InitSign this object for signing. If this method is called
	// again with a different argument, it negates the effect
	// of this call.
	InitSign(privateKey PrivateKey) error

	// Sign returns the signature
	// The format of the signature depends on the underlying
	// signature scheme.
	Sign(data []byte) (out SignResult, err error)

	// InitVerify initializes this object for verification. If this method is called
	// again with a different argument, it negates the effect
	// of this call.
	InitVerify(publicKey PublicKey) error

	// Verify the passed-in signature.
	//
	// <p>A call to this method resets this signature object to the state
	// it was in when previously initialized for verification via a
	// call to <code>initVerify(PublicKey)</code>. That is, the object is
	// reset and available to verify another signature from the identity
	// whose public key was specified in the call to <code>initVerify</code>.
	Verify(data []byte, signature SignResult) (bool, error)
}
