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
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
)

// GtService service for Gt p2p network
type GtService struct {
	node       *Node
	dispatcher *Dispatcher
}

// NewGtService create netService
func NewGtService(conf *config.Config) (*GtService, error) {
	netcfg := GetNetConfig(conf)

	if netcfg == nil {
		logging.CLog().Fatal("Failed to find network config in config file")
		return nil, ErrConfigLackNetWork
	}

	node, err := NewNode(NewP2PConfig(conf))
	if err != nil {
		return nil, err
	}

	ns := &GtService{
		node:       node,
		dispatcher: NewDispatcher(),
	}
	node.SetGtService(ns)

	return ns, nil
}

// PutMessage put message to dispatcher.
func (ns *GtService) PutMessage(msg Message) {
	ns.dispatcher.PutMessage(msg)
}

// Start start p2p manager.
func (ns *GtService) Start() error {
	logging.CLog().Info("Starting GtService...")

	// start dispatcher.
	ns.dispatcher.Start()

	// start node.
	if err := ns.node.Start(); err != nil {
		ns.dispatcher.Stop()
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to start GtService.")
		return err
	}

	logging.CLog().Info("Started GtService.")
	return nil
}

// Stop stop p2p manager.
func (ns *GtService) Stop() {
	logging.CLog().Info("Stopping GtService...")

	ns.node.Stop()
	ns.dispatcher.Stop()
}

// Register register the subscribers.
func (ns *GtService) Register(subscribers ...*Subscriber) {
	ns.dispatcher.Register(subscribers...)
}

// Deregister Deregister the subscribers.
func (ns *GtService) Deregister(subscribers ...*Subscriber) {
	ns.dispatcher.Deregister(subscribers...)
}

// Broadcast message.
func (ns *GtService) Broadcast(name string, msg Serializable, priority int) {
	ns.node.BroadcastMessage(name, msg, priority)
}

// Relay message.
func (ns *GtService) Relay(name string, msg Serializable, priority int) {
	ns.node.RelayMessage(name, msg, priority)
}

// SendMessage send message to a peer.
func (ns *GtService) SendMessage(msgName string, msg []byte, target string, priority int) error {
	return ns.node.SendMessageToPeer(msgName, msg, priority, target)
}

// SendMessageToPeers send message to peers.
func (ns *GtService) SendMessageToPeers(messageName string, data []byte, priority int, filter PeerFilterAlgorithm) []string {
	return ns.node.streamManager.SendMessageToPeers(messageName, data, priority, filter)
}

// SendMessageToPeer send message to a peer.
func (ns *GtService) SendMessageToPeer(messageName string, data []byte, priority int, peerID string) error {
	return ns.node.SendMessageToPeer(messageName, data, priority, peerID)
}

// SendMessageToPeer send message to a peer.
func (ns *GtService) SendMessageToPeerOrBroadcast(messageName string, messageContent Serializable, priority int, peerID string) error {
	return ns.node.SendMessageToPeerOrBroadcast(messageName, messageContent, priority, peerID)
}

// ClosePeer close the stream to a peer.
func (ns *GtService) ClosePeer(peerID string, reason error) {
	ns.node.streamManager.CloseStream(peerID, reason)
}

func (ns *GtService) AddPeer(peerID string) {
	id, err := peer.IDB58Decode(peerID)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Invalid PeerID")
		return
	}
	ns.node.routeTable.SyncWithPeer(id)
}

// Node return the peer node
func (ns *GtService) Node() *Node {
	return ns.node
}
