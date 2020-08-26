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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/util/logging"
)

const (
	// TopicPendingTransaction the topic of pending a transaction in transaction_pool.
	TopicPendingTransaction = "chain.pendingTransaction"
	// TopicFixedBlock the topic of latest fixed block.
	TopicFixedBlock = "chain.latestFixedBlock"
	// TopicTransactionExecutionResult the topic of transaction execution result
	TopicTransactionExecutionResult = "chain.transactionResult"
	// TopicTransferFromContract transfer from contract
	TopicTransferFromContract = "chain.transferFromContract"
	// TopicInnerTransferContract inner transfer
	TopicInnerContract = "chain.innerContract"

	// TopicNewTailBlock the topic of new tail block set
	TopicNewTailBlock = "chain.newTailBlock"
	// TopicRevertBlock the topic of revert block
	TopicRevertBlock = "chain.revertBlock"

	// TopicDropTransaction drop tx (1): smaller nonce (2) expire txLifeTime
	TopicDropTransaction = "chain.dropTransaction"

	TopicReportReward     = "chain.reportReward"
	TopicDoEvilPunishment = "chain.doEvilPunishment"
	TopicVoteResult       = "chain.voteResult"
)

// TransactionEvent transaction event
type TransactionEvent struct {
	Hash    string `json:"hash"`
	Status  int8   `json:"status"`
	GasUsed string `json:"gas_used"`
	Error   string `json:"error"`
}

//ContractTransactionEvent the event of contract transaction event
type ContractTransactionEvent struct {
	Hash          string `json:"hash"`
	Status        int8   `json:"status"`
	GasUsed       string `json:"gas_used"`
	Error         string `json:"error"`
	ExecuteResult string `json:"execute_result"`
}

// EventSubscriber subscriber object
type EventSubscriber struct {
	eventCh chan *state.Event
	topics  []string
}

// EventChan returns subscriber's eventCh
func (s *EventSubscriber) EventChan() chan *state.Event {
	return s.eventCh
}

// EventEmitter provide event functionality for Gt.
type EventEmitter struct {
	eventSubs *sync.Map
	eventCh   chan *state.Event
	quitCh    chan int
	size      int
}

// NewEventEmitter return new EventEmitter.
func NewEventEmitter(size int) *EventEmitter {
	return &EventEmitter{
		eventSubs: new(sync.Map),
		eventCh:   make(chan *state.Event, size),
		quitCh:    make(chan int, 1),
		size:      size,
	}
}

// Start start emitter.
func (emitter *EventEmitter) Start() {
	logging.CLog().WithFields(logrus.Fields{
		"size": emitter.size,
	}).Info("Starting EventEmitter...")

	go emitter.loop()
}

// Stop stop emitter.
func (emitter *EventEmitter) Stop() {
	logging.CLog().WithFields(logrus.Fields{
		"size": emitter.size,
	}).Info("Stopping EventEmitter...")

	emitter.quitCh <- 1
}

// Trigger trigger event.
func (emitter *EventEmitter) Trigger(e *state.Event) {
	emitter.eventCh <- e
}

func (emitter *EventEmitter) loop() {
	logging.CLog().Info("Started EventEmitter.")

	timerChan := time.NewTicker(time.Second).C
	for {
		select {
		case <-timerChan:
			metricsCachedEvent.Update(int64(len(emitter.eventCh)))
		case <-emitter.quitCh:
			logging.CLog().Info("Stopped EventEmitter.")
			return
		case e := <-emitter.eventCh:

			topic := e.Topic
			v, ok := emitter.eventSubs.Load(topic)
			if !ok {
				continue
			}

			m, _ := v.(*sync.Map)
			m.Range(func(key, value interface{}) bool {
				select {
				case key.(*EventSubscriber).eventCh <- e:
				default:
					logging.VLog().WithFields(logrus.Fields{
						"topic": topic,
					}).Warn("timeout to dispatch event.")
				}
				return true
			})
		}
	}
}

// Register register event chan.
func (emitter *EventEmitter) Register(subscribers ...*EventSubscriber) {

	for _, v := range subscribers {
		for _, topic := range v.topics {
			m, _ := emitter.eventSubs.LoadOrStore(topic, new(sync.Map))
			m.(*sync.Map).Store(v, true)
		}
	}
}

// Deregister deregister event chan.
func (emitter *EventEmitter) Deregister(subscribers ...*EventSubscriber) {
	for _, v := range subscribers {
		for _, topic := range v.topics {
			m, _ := emitter.eventSubs.Load(topic)
			if m == nil {
				continue
			}
			m.(*sync.Map).Delete(v)
		}
	}
}

// NewEventSubscriber returns an EventSubscriber
func NewEventSubscriber(size int, topics []string) *EventSubscriber {
	eventCh := make(chan *state.Event, size)
	subscriber := &EventSubscriber{
		eventCh: eventCh,
		topics:  topics,
	}
	return subscriber
}
