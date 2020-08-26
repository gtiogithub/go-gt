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

import "gt.pro/gtio/go-gt/metrics"

var (
	metricsDuplicatedBlock = metrics.NewCounter("gt.block.duplicated")
	metricsInvalidBlock    = metrics.NewCounter("gt.block.invalid")

	metricsTxVerifiedTime    = metrics.NewGauge("gt.tx.executed")
	metricsTxsInBlock        = metrics.NewGauge("gt.block.txs")
	metricsBlockVerifiedTime = metrics.NewGauge("gt.block.executed")

	metricsBlockOnchainTimer = metrics.NewTimer("gt.block.onchain")
	metricsTxOnchainTimer    = metrics.NewTimer("gt.transaction.onchain")

	// block_pool metrics
	metricsCachedNewBlock      = metrics.NewGauge("gt.block.new.cached")
	metricsCachedDownloadBlock = metrics.NewGauge("gt.block.download.cached")
	metricsLruPoolCacheBlock   = metrics.NewGauge("gt.block.lru.poolcached")
	metricsLruCacheBlock       = metrics.NewGauge("gt.block.lru.blocks")
	metricsLruTailBlock        = metrics.NewGauge("gt.block.lru.tailblock")

	// transaction metrics
	metricsTxSubmit     = metrics.NewMeter("gt.transaction.submit")
	metricsTxExecute    = metrics.NewMeter("gt.transaction.execute")
	metricsTxExeSuccess = metrics.NewMeter("gt.transaction.execute.success")
	metricsTxExeFailed  = metrics.NewMeter("gt.transaction.execute.failed")

	// unexpect behavior
	metricsUnexpectedBehavior = metrics.NewGauge("gt.unexpected")

	// event metrics
	metricsCachedEvent = metrics.NewGauge("gt.event.cached")
)
