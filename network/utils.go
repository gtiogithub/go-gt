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

package network

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Errors
var (
	ErrListenPortIsNotAvailable = errors.New("listen port is not available")
	ErrConfigLackNetWork        = errors.New("config.conf should has network")
)

func verifyListenAddress(listen []string) error {
	for _, v := range listen {
		_, err := net.ResolveTCPAddr("tcp", v)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkPathConfig(path string) bool {
	if path == "" {
		return true
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}

func verifyPortAvailable(listen []string) error {
	for _, v := range listen {
		conn, err := net.DialTimeout("tcp", v, time.Second*1)
		if err == nil {
			conn.Close()
			return ErrListenPortIsNotAvailable
		}
	}
	return nil
}

// ParseFromIPFSAddr return pid and address parsed from ipfs address
func ParseFromIPFSAddr(ipfsAddr ma.Multiaddr) (peer.ID, ma.Multiaddr, error) {
	addr, err := ma.NewMultiaddr(strings.Split(ipfsAddr.String(), "/ipfs/")[0])
	if err != nil {
		return "", nil, err
	}

	// TODO: @robin we should register cvm multicodecs.
	b58, err := ipfsAddr.ValueForProtocol(ma.P_IPFS)
	if err != nil {
		return "", nil, err
	}

	id, err := peer.IDB58Decode(b58)
	if err != nil {
		return "", nil, err
	}

	return id, addr, nil
}
