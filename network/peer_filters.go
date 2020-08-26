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
	"math"
	"math/rand"
)

// ChainSyncPeersFilter will filter some peers randomly
type ChainSyncPeersFilter struct {
}

// Filter implemets PeerFilterAlgorithm interface
func (filter *ChainSyncPeersFilter) Filter(peers PeersSlice) PeersSlice {
	if len(peers) == 0 {
		return peers
	}
	selection := int(math.Sqrt(float64(len(peers))))
	return peers[:selection]
}

// RandomPeerFilter will filter a peer randomly
type RandomPeerFilter struct {
}

// Filter implemets PeerFilterAlgorithm interface
func (filter *RandomPeerFilter) Filter(peers PeersSlice) PeersSlice {
	if len(peers) == 0 {
		return peers
	}

	selection := rand.Intn(len(peers))
	return peers[selection : selection+1]
}
