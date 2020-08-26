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
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"

	//"gt.pro/gtio/go-gt/cvm/lmlx_core"
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/util/logging"
	"gt.pro/gtio/go-gt/util/sorted"
	"github.com/gogo/protobuf/proto"

	//"github.com/golang/snappy"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// transaction pool
	pendingSize = 4096
	poolSize    = 8192

	//
	txExpiredTime  = time.Minute * 60
	txScanInterval = time.Minute
)

var (
	ErrNoData = errors.New("the page size no data")
)

// TxPool
type TxPool struct {
	pending *sorted.Slice

	normalCache  map[string]*Transaction //to ignore transactions with the same priority as the nonce
	allNormalTxs map[string]*Transaction

	addrTxs           map[string]*sorted.Slice
	addressLastUpdate map[string]time.Time

	chain        *BlockChain
	eventEmitter *EventEmitter
	ns           network.Service

	quitCh chan int
	recvCh chan network.Message
	mu     sync.RWMutex
}

// NewTxPool
func NewTxPool() *TxPool {
	return &TxPool{
		pending:           sorted.NewSlice(timestampCmp),
		normalCache:       make(map[string]*Transaction, pendingSize),
		quitCh:            make(chan int),
		recvCh:            make(chan network.Message, poolSize),
		allNormalTxs:      make(map[string]*Transaction),
		addrTxs:           make(map[string]*sorted.Slice),
		addressLastUpdate: make(map[string]time.Time),
		mu:                sync.RWMutex{},
	}
}

// RegisterInNetwork
func (pool *TxPool) RegisterInNetwork(ns network.Service) {
	ns.Register(network.NewSubscriber(pool, pool.recvCh, true, MessageTypeNewTx, network.MessageWeightNewTx))
	pool.ns = ns
}

// loop process new message
func (pool *TxPool) loop() {
	removeChan := time.NewTicker(txScanInterval).C
	for {
		select {
		case <-removeChan:
			pool.removeExpiredTransactions()
		case <-pool.quitCh:
			logging.CLog().WithFields(logrus.Fields{}).Info("Stopped transaction pool")
			return
		case msg := <-pool.recvCh:
			if msg.MessageType() != MessageTypeNewTx {
				logging.VLog().WithFields(logrus.Fields{
					"messageType": msg.MessageType(),
					"message":     msg,
					"err":         "not new tx msg",
				}).Error("Received unregistered message")
				continue
			}
			tx := new(Transaction)
			pbTx := new(corepb.Transaction)
			if err := proto.Unmarshal(msg.Data(), pbTx); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"msgType": msg.MessageType(),
					"msg":     msg,
					"err":     err,
				}).Error("Failed to unmarshal data")
				continue
			}
			if err := tx.FromProto(pbTx); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"msgType": msg.MessageType(),
					"msg":     msg,
					"err":     err,
				}).Error("Failed to recover a transaction from proto data")
				continue
			}
			if err := pool.AddAndRelay(tx); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"func":        "TxPool.loop",
					"messageType": msg.MessageType(),
					"transaction": tx,
					"err":         err,
				}).Error("Failed to add a transaction into transaction pool")
				continue
			}
		}
	}
}

//
func (pool *TxPool) setBlockChain(bc *BlockChain) {
	pool.chain = bc
}

// Start starts tx pool loop.
func (pool *TxPool) Start() {
	logging.CLog().Info("Start Transaction Pool...")
	go pool.loop()
}

// Stop stops tx pool loop.
func (pool *TxPool) Stop() {
	logging.CLog().Info("Stop Transaction Pool...")
	pool.quitCh <- 0
}

// PendingIsEmpty pengding is empty
func (pool *TxPool) PendingIsEmpty() bool {
	return pool.pending.Len() == 0
}

//remove expired transactions
func (pool *TxPool) removeExpiredTransactions() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for addr := range pool.addrTxs {
		if timeLastDate, ok := pool.addressLastUpdate[addr]; ok {
			if time.Since(timeLastDate) > txExpiredTime {
				bucket := pool.addrTxs[addr]

				val := bucket.PopLeft()
				if tx := val.(*Transaction); tx != nil && tx.hash != nil {
					pool.pending.Del(tx)
				}
				for val != nil {
					if tx := val.(*Transaction); tx != nil && tx.hash != nil {
						delete(pool.allNormalTxs, tx.Hash().String())
						delete(pool.normalCache, tx.CalcCacheKey())

						logging.VLog().WithFields(logrus.Fields{
							"txHash":  tx.Hash().String(),
							"txNonce": tx.Nonce(),
						}).Debug("Remove expired transactions.")
						event := &state.Event{
							Topic: TopicDropTransaction,
							Data:  tx.JSONString(),
						}
						pool.eventEmitter.Trigger(event)
					}

					val = bucket.PopLeft()
				}
				delete(pool.addrTxs, addr)
				delete(pool.addressLastUpdate, addr)
			}
		}
	}
}

//remove normal transaction
func (pool *TxPool) removeNormalTransaction(tx *Transaction) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	nonce := tx.Nonce()
	slice, ok := pool.addrTxs[tx.From().String()]
	if ok && slice.Len() > 0 {
		oldTx := slice.Left()
		left := oldTx.(*Transaction)
		for left.Nonce() <= nonce {
			slice.PopLeft()
			delete(pool.allNormalTxs, left.Hash().String())
			event := &state.Event{
				Topic: TopicDropTransaction,
				Data:  tx.JSONString(),
			}
			pool.eventEmitter.Trigger(event)
			logging.VLog().WithFields(logrus.Fields{
				"txHash":  left.Hash(),
				"txNonce": left.Nonce(),
			}).Debug("Remove had packaged transactions")

			if slice.Len() > 0 {
				left = slice.Left().(*Transaction)
			} else {
				delete(pool.addrTxs, left.From().String())
				delete(pool.addressLastUpdate, left.From().String())
				break
			}
		}

		newTx := slice.Left()
		if oldTx != newTx {
			pool.pending.Del(oldTx)
			delete(pool.normalCache, tx.CalcCacheKey())
			delete(pool.addressLastUpdate, tx.From().String())
			if newTx != nil {
				pool.pending.Push(newTx)
				//update bucket update time when txs are put on chain
				pool.addressLastUpdate[tx.From().String()] = time.Now()
			}
		}
	} else {
		//remove key of bucketsLastUpdate when bucket is empty
		delete(pool.addressLastUpdate, tx.From().String())
	}
}

//get the address transactions num in tx pool to calc tx's nonce
func (pool *TxPool) GetTxsNumByAddr(addr string) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	slice, ok := pool.addrTxs[addr]
	if !ok {
		return 0
	}

	return slice.Len()
}

// GetPendingTransactions
func (pool *TxPool) GetPendingTransactions() ([]*Transaction, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	size := len(pool.allNormalTxs)
	txs := make([]*Transaction, size)
	index := 0
	for _, normalTx := range pool.allNormalTxs {
		txs[index] = normalTx
		index++
	}
	return txs, nil
}

// GetPendingTxSize
func (pool *TxPool) GetPendingTxSize() uint {
	if pool == nil {
		logging.VLog().Debug("transaction pool is nil")
		return 0
	}
	size := len(pool.allNormalTxs)
	return uint(size)
}

// take transaction from tx pool
func (pool *TxPool) takeTransaction(fromAccList *sync.Map, toAccList *sync.Map) *Transaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if fromAccList == nil {
		fromAccList = new(sync.Map)
	}
	if toAccList == nil {
		toAccList = new(sync.Map)
	}

	size := pool.pending.Len()
	if size == 0 {
		return nil
	}
	for i := 0; i < size; i++ {
		tx := pool.pending.Index(i).(*Transaction)
		if _, ok := fromAccList.Load(tx.from.address.Hex()); !ok {
			if _, ok := toAccList.Load(tx.to.address.Hex()); !ok {
				pool.pending.Del(tx)
				pool.handleNextTx(tx)
				return tx
			}
		}
	}
	return nil
}

func (pool *TxPool) handleNextTx(tx *Transaction) {
	slice := pool.addrTxs[tx.From().String()]
	delete(pool.allNormalTxs, tx.Hash().String())
	delete(pool.normalCache, tx.CalcCacheKey())
	slice.PopLeft()
	if slice.Len() != 0 {
		nextTx := slice.Left()
		pool.pending.Push(nextTx)
	} else {
		delete(pool.addrTxs, tx.From().String())
		delete(pool.addressLastUpdate, tx.From().String())
	}
}

// AddAndBroadcast adds a tx into pool and broadcast it.
func (pool *TxPool) AddAndBroadcast(tx *Transaction) error {
	if err := pool.Add(tx); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx.Hash(),
			"err": err,
		}).Debug("Failed to add transaction")
		return err
	}

	priority := network.MessagePriorityNormal
	if tx.Type() == ReportTx {
		priority = network.MessagePriorityHigh
	}

	pool.ns.Broadcast(MessageTypeNewTx, tx, priority)

	return nil
}

//add tx to tx pool
func (pool *TxPool) Add(tx *Transaction) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if _, ok := pool.allNormalTxs[tx.Hash().String()]; ok {
		return ErrDuplicatedTransaction
	}

	if len(pool.allNormalTxs) == poolSize {
		return ErrTxPoolFull
	}

	if err := tx.VerifyIntegrity(pool.chain.ChainId()); err != nil {
		return err
	}

	switch tx.Type() {
	case PledgeTx:
		pool.AddTransaction(tx)
	case ContractDeployTx:
		pool.AddTransaction(tx)
	case ContractInvokeTx:
		pool.AddTransaction(tx)
	case NormalTx:
		pool.AddTransaction(tx)
	case ComplexTx:
		pool.AddTransaction(tx)
	case AuthorizeTx:
		pool.AddTransaction(tx)
	case ContractChangeStateTx:
		pool.AddTransaction(tx)
	case ReportTx:
		pool.AddTransaction(tx)
	}

	event := &state.Event{
		Topic: TopicPendingTransaction,
		Data:  tx.JSONString(),
	}
	pool.eventEmitter.Trigger(event)
	return nil
}

// AddAndRelay adds a tx into pool and relay it.
func (pool *TxPool) AddAndRelay(tx *Transaction) error {
	if err := pool.Add(tx); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx.Hash(),
			"err": err,
		}).Error("Failed to add transaction")
		return err
	}

	pool.ns.Relay(MessageTypeNewTx, tx, network.MessagePriorityNormal)

	return nil
}

// AddTransaction
func (pool *TxPool) AddTransaction(tx *Transaction) {
	if pool.pending.Len() == pendingSize {
		logging.CLog().Warn("pending pool is full")
		return
	}

	key := tx.CalcCacheKey()
	if _, ok := pool.normalCache[key]; ok {
		logging.VLog().WithFields(logrus.Fields{
			"txHash":   tx.Hash(),
			"nonce":    tx.Nonce(),
			"priority": tx.Priority(),
		}).Warn("[AddTransaction] tx nonce equal and priority equal")
		return
	}

	// add tx into addrTxs
	from := tx.From().String()
	addrTxsMap, ok := pool.addrTxs[from]
	if !ok {
		addrTxsMap = sorted.NewSlice(noncePriorityCmp)
		pool.addrTxs[from] = addrTxsMap
	}

	oldTx := addrTxsMap.Left()
	addrTxsMap.Push(tx)
	// add tx to allNormalTxs
	pool.allNormalTxs[tx.Hash().String()] = tx

	pool.normalCache[key] = tx

	newTx := addrTxsMap.Left()
	if oldTx == nil {
		pool.pending.Push(newTx)
	} else if oldTx != newTx {
		pool.pending.Del(oldTx)
		pool.pending.Push(newTx)
	}

	//record the time when the first transaction was added so that it can be deleted over time
	if _, ok := pool.addressLastUpdate[from]; !ok {
		pool.addressLastUpdate[from] = time.Now()
	}
}

//Sort by nonce and priority
func noncePriorityCmp(a interface{}, b interface{}) int {
	txa := a.(*Transaction)
	txb := b.(*Transaction)
	if txa.Nonce() < txb.Nonce() {
		return -1
	} else if txa.Nonce() > txb.Nonce() {
		return 1
	}

	//Nonce equal
	if txa.Priority() < txb.Priority() {
		return 1
	} else if txa.Priority() > txb.Priority() {
		return -1
	}
	logging.VLog().WithFields(logrus.Fields{
		"txa": txa,
		"txb": txb,
	}).Error("tx nonce equal and priority equal")
	return 0
}

//Sort by transaction timestamp
func timestampCmp(a interface{}, b interface{}) int {
	txa := a.(*Transaction)
	txb := b.(*Transaction)
	if txa.Timestamp() < txb.Timestamp() {
		return -1
	}
	if txa.Timestamp() > txb.Timestamp() {
		return 1
	}
	return 0
}

func (pool *TxPool) setEventEmitter(emitter *EventEmitter) {
	pool.eventEmitter = emitter
}
