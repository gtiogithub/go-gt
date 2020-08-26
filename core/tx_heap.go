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

type timeHeap []*Transaction

func (h timeHeap) Len() int { return len(h) }

func (h timeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h timeHeap) Less(i, j int) bool {
	return h[i].Timestamp() < h[j].Timestamp()
}

// push a tx
func (h *timeHeap) Push(x interface{}) {
	*h = append(*h, x.(*Transaction))
}

// pop a tx
func (h *timeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// return txs in the slice
func (h *timeHeap) Transactions() []*Transaction {
	return *h
}
