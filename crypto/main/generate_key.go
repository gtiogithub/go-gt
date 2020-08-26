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
package main

import (
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/crypto"
	"fmt"
	"log"
	"os"
)

func main() {
	privateKey, err := crypto.NewPrivateKey(nil)
	if err != nil {
		log.Fatal("failed to create private key.")
	}

	pubKey, err := privateKey.PublicKey().Encoded()
	if err != nil {
		log.Fatal("failed to get public key.")
	}

	addr, err := core.NewAddressFromPublicKey(pubKey)
	if err != nil {
		log.Fatal("failed to generate address.")
	}

	data, err := privateKey.Encoded()
	if err != nil {
		log.Fatal("failed to encode private key.")
	}

	f, err := os.Create(addr.String())
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		fmt.Println("failed to write key to file.")
		return
	}

	fmt.Println("addr:", addr.String())
	fmt.Println("successful key generation...")
}
