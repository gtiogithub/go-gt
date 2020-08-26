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
	"github.com/gogo/protobuf/proto"
	"gt.pro/gtio/go-gt/crypto/hash"
	"gt.pro/gtio/go-gt/util/byteutils"
)

// Message Priority.
const (
	MessagePriorityHigh = iota
	MessagePriorityNormal
	MessagePriorityLow
)

// Sync Message Type
const (
	ChunkHeadersRequest  = "sync"      // ChainSync
	ChunkHeadersResponse = "chunks"    // ChainChunks
	ChunkDataRequest     = "getchunk"  // ChainGetChunk
	ChunkDataResponse    = "chunkdata" // ChainChunkData
	// pbft
	Pbft = "pbft"
)

// Message interface for message.
type Message interface {
	MessageType() string
	MessageFrom() string
	Data() []byte
	Hash() string
}

// Service net Service interface
type Service interface {
	Start() error
	Stop()
	Node() *Node
	Register(...*Subscriber)
	Deregister(...*Subscriber)
	Broadcast(string, Serializable, int)
	Relay(string, Serializable, int)
	SendMessage(string, []byte, string, int) error
	SendMessageToPeers(messageName string, data []byte, priority int, filter PeerFilterAlgorithm) []string
	SendMessageToPeer(messageName string, data []byte, priority int, peerID string) error
	SendMessageToPeerOrBroadcast(messageName string, messageContent Serializable, priority int, peerID string) error
	ClosePeer(peerID string, reason error)
	AddPeer(peerID string)
}

// Serializable model
type Serializable interface {
	ToProto() (proto.Message, error)
	FromProto(proto.Message) error
}

// PeersSlice is a slice which contains peers
type PeersSlice []interface{}

// PeerFilterAlgorithm is the algorithm used to filter peers
type PeerFilterAlgorithm interface {
	Filter(PeersSlice) PeersSlice
}

// NewBaseMessage new base message
func NewBaseMessage(t string, from string, data []byte) Message {
	return &BaseMessage{t: t, from: from, data: data}
}

// BaseMessage base message
type BaseMessage struct {
	t    string
	from string
	data []byte
}

// MessageType get message type
func (msg *BaseMessage) MessageType() string {
	return msg.t
}

// MessageFrom get message who send
func (msg *BaseMessage) MessageFrom() string {
	return msg.from
}

// Data get the message data
func (msg *BaseMessage) Data() []byte {
	return msg.data
}

// Hash return the message hash
func (msg *BaseMessage) Hash() string {
	return byteutils.Hex(hash.Sha3256(msg.data))

}

// MessageWeight float64
type MessageWeight float64

// const
const (
	MessageWeightZero = MessageWeight(0)
	MessageWeightNewTx
	MessageWeightNewBlock = MessageWeight(0.5)
	MessageWeightRouteTable
	MessageWeightChainChunks
	MessageWeightChainChunkData
	MessageWeightPropose

	MessageWeightStandby
	MessageWeightPaxos
	MessageWeightPbft
)

// Subscriber subscriber.
type Subscriber struct {
	// id usually the owner/creator, used for troubleshooting .
	id interface{}

	// msgChan chan for subscribed message.
	msgChan chan Message

	// msgType message type to subscribe
	msgType string

	// msgWeight weight of msgType
	msgWeight MessageWeight

	// doFilter dup message
	doFilter bool
}

// NewSubscriber return new Subscriber instance.
func NewSubscriber(id interface{}, msgChan chan Message, doFilter bool, msgType string, weight MessageWeight) *Subscriber {
	return &Subscriber{id, msgChan, msgType, weight, doFilter}
}

// ID return id.
func (s *Subscriber) ID() interface{} {
	return s.id
}

// MessageType return msgTypes.
func (s *Subscriber) MessageType() string {
	return s.msgType
}

// MessageChan return msgChan.
func (s *Subscriber) MessageChan() chan Message {
	return s.msgChan
}

// MessageWeight return weight of msgType
func (s *Subscriber) MessageWeight() MessageWeight {
	return s.msgWeight
}

// DoFilter return doFilter
func (s *Subscriber) DoFilter() bool {
	return s.doFilter
}
