// Copyright (C) 2018 go-gt authors
//
// This file is part of the go-gt library.
//
// the go-gt library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of t1he License, or
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
package gt

import (
	"net"
	"net/http"
	"sync"
	"time"

	"gt.pro/gtio/go-gt/consensus"

	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/account"
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/cvm"
	"gt.pro/gtio/go-gt/metrics"
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/rpc"
	"gt.pro/gtio/go-gt/storage/cdb"
	csync "gt.pro/gtio/go-gt/sync"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
	"gt.pro/gtio/go-gt/util/pprof"
)

// Gt
type Gt struct {
	networkId      uint64
	config         *config.Config
	chain          *core.BlockChain
	engine         core.Consensus
	accountManager core.AccountManager
	chainDb        cdb.Storage
	netService     network.Service
	rpcServer      rpc.GRPCServer
	syncService    core.Synchronize
	pprof          *pprof.Pprof
	cvm            core.CVM
	eventEmitter   *core.EventEmitter
	mu             sync.RWMutex
	quitChan       chan bool
	running        bool
}

// NewGt
func NewGt(gtConf *config.Config) (*Gt, error) {
	if gtConf == nil {
		logging.CLog().Error("Failed to load config file")
		return nil, nil
	}

	// gt
	app := &Gt{
		config:   gtConf,
		quitChan: make(chan bool),
	}

	//pprof
	pprofConf := pprof.GetPprofConfig(gtConf)
	pprof := &pprof.Pprof{
		Config: pprofConf,
	}
	// try enable profile.
	pprof.StartProfiling()
	app.pprof = pprof

	return app, nil
}

// Setup
func (c *Gt) Setup() {
	var err error
	logging.CLog().Info("Setuping Gt...")

	//db
	c.chainDb, err = cdb.NewDB(c.config)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to open disk storage.")
	}

	if c.accountManager, err = account.NewAccountManager(c.config, c.chainDb); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to new account manager.")
	}

	// net
	c.netService, err = network.NewGtService(c.config)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup net service.")
	}

	// cvm
	c.cvm = cvm.NewGtVM()

	c.eventEmitter = core.NewEventEmitter(40960)

	// block chain
	c.chain, err = core.NewBlockChain(c.config, c.netService, c.eventEmitter, c.chainDb)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup blockchain.")
	}

	// consensus
	//c.engine = psec.NewPsec(c.chainDb, c.config, c.chain)
	//if c.engine == nil {
	//	logging.CLog().Fatal("Failed to new psec.")
	//}

	c.engine, err = consensus.NewConsensus(consensus.CONSENSUS_PSEC, c.chainDb, c.config, c.chain)
	if err != nil {
		logging.CLog().Fatal("Failed to new consensus.")
	}
	if err := c.chain.Setup(c); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup blockchain.")
	}

	if err := c.engine.Setup(c); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup consensus.")
	}

	// sync
	c.syncService = csync.NewService(c.chain, c.netService)
	c.chain.SetSyncEngine(c.syncService)

	// rpc
	c.rpcServer = rpc.NewServer(c)

	logging.CLog().Info("Setuped Gt.")
}

// StartPprof start pprof http listen
func (c *Gt) StartPprof(listen string) error {
	if len(listen) > 0 {
		conn, err := net.DialTimeout("tcp", listen, time.Second*1)
		if err == nil {
			logging.CLog().WithFields(logrus.Fields{
				"listen": listen,
				"err":    err,
			}).Error("Failed to start pprof")
			_ = conn.Close()
			return err
		}

		go func() {
			logging.CLog().WithFields(logrus.Fields{
				"listen": listen,
			}).Info("Starting pprof...")
			_ = http.ListenAndServe(listen, nil)
		}()

	}
	return nil
}

// Run
func (c *Gt) Run() {
	c.mu.Lock()
	defer c.mu.Unlock()

	logging.CLog().Info("Starting Gt...")

	if c.running {
		logging.CLog().WithFields(logrus.Fields{
			"err": "gt is already running",
		}).Fatal("Failed to start gt.")
	}
	c.running = true

	//metrics
	statscfg := metrics.GetStatsConfig(c.config)
	if statscfg.EnableMetrics {
		metrics.Start(c.config)
	}
	// net
	if err := c.netService.Start(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to start net service.")
	}
	//rpc
	if err := c.rpcServer.Start(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to start api server.")
	}
	//gateway
	if err := c.rpcServer.RunGateway(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to start api gateway.")
	}

	c.chain.Start()
	c.chain.BlockPool().Start()
	c.chain.TxPool().Start()
	c.eventEmitter.Start()
	c.syncService.Start()
	c.engine.Start()
	//netcfg := network.GetNetConfig(c.config)
	//if len(netcfg.Seed) > 0 {
	//	c.BlockChain().StartActiveSync()
	//}

	select {
	case <-c.quitChan:
		logging.CLog().Info("Stopped Gt...")
	}
}

// Stop stops the services of the gt.
func (c *Gt) Stop() {

	logging.CLog().Info("Stopping Gt...")

	// try Stop Profiling.
	if c.pprof != nil {
		c.pprof.StopProfiling()
		c.pprof = nil
	}

	//sync
	if c.syncService != nil {
		c.syncService.Stop()
		c.syncService = nil
	}

	if c.eventEmitter != nil {
		c.eventEmitter.Stop()
		c.eventEmitter = nil
	}

	if c.chain != nil {

		c.chain.BlockPool().Stop()
		//c.chain.Stop()
		c.chain = nil
	}

	//rpc
	if c.rpcServer != nil {
		c.rpcServer.Stop()
		c.rpcServer = nil
	}
	//net
	if c.netService != nil {
		c.netService.Stop()
		c.netService = nil
	}
	//metrics
	statscfg := metrics.GetStatsConfig(c.config)
	if statscfg.EnableMetrics {
		metrics.Stop()
	}

	if c.accountManager != nil {
		c.accountManager.Stop()
		c.accountManager = nil
	}

	c.running = false

	logging.CLog().Info("Stopped Gt.")
	c.quitChan <- true
}

func (c *Gt) EventEmitter() *core.EventEmitter {
	return c.eventEmitter
}

// return blockchain
func (c *Gt) BlockChain() *core.BlockChain {
	return c.chain
}

// return account manager
func (c *Gt) AccountManager() core.AccountManager {
	return c.accountManager
}

// return consensus
func (c *Gt) Consensus() core.Consensus {
	return c.engine
}

// return config
func (c *Gt) Config() *config.Config {
	return c.config
}

// return storage
func (c *Gt) Storage() cdb.Storage {
	return c.chainDb
}

// return net service
func (c *Gt) NetService() network.Service {
	return c.netService
}

// return cvm
func (c *Gt) Cvm() core.CVM {
	return c.cvm
}
