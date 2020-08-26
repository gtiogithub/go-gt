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

package sync

import (
	"gt.pro/gtio/go-gt/metrics"
	"errors"
)

// Error Types
var (
	ErrTooSmallGapToSync        = errors.New("the gap between syncpoint and current tail is smaller than a dynasty interval, ignore the sync task")
	ErrCannotFindBlockByHeight  = errors.New("cannot find the block at given height")
	ErrCannotFindBlockByHash    = errors.New("cannot find the block with the given hash")
	ErrWrongChunkHeaderRootHash = errors.New("wrong chunk header root hash")
	ErrWrongChunkDataRootHash   = errors.New("wrong chunk data root hash")
	ErrWrongChunkDataSize       = errors.New("wrong chunk data size")
	ErrInvalidBlockHashInChunk  = errors.New("invalid block hash in chunk data")
	ErrWrongBlockHashInChunk    = errors.New("wrong block hash in chunk data compared with chunk header")
)

// Contants
const (
	MaxChunkPerSyncRequest       = 10
	ConcurrentSyncChunkDataCount = 10
	GetChunkDataTimeout          = 10
)

// Metrics
var (
	metricsCachedSync = metrics.NewGauge("gt.sync.cached")
)
