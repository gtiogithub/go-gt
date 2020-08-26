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
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/gogo/protobuf/proto"
	csms "github.com/libp2p/go-conn-security-multistream"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/metrics"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	secio "github.com/libp2p/go-libp2p-secio"
	swarm "github.com/libp2p/go-libp2p-swarm"
	tptu "github.com/libp2p/go-libp2p-transport-upgrader"
	yamux "github.com/libp2p/go-libp2p-yamux"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	msmux "github.com/libp2p/go-stream-muxer-multistream"
	"github.com/libp2p/go-tcp-transport"
	"github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/util/logging"
)

const MemberSize int = 3

// Error types
var (
	ErrPeerIsNotConnected = errors.New("peer is not connected")
)

// Node the node can be used as both the client and the server
type Node struct {
	synchronizing bool
	quitCh        chan bool
	netService    *GtService
	config        *Config
	context       context.Context
	id            peer.ID
	networkKey    crypto.PrivKey
	network       network.Network
	host          *basichost.BasicHost
	streamManager *StreamManager
	routeTable    *RouteTable
	members       []peer.ID
}

//
func (node *Node) AddPeer(id peer.ID) {
	if id.String() == "" {
		logging.CLog().Error("Peer id is nil")
		return
	}

	if len(node.members) == MemberSize {
		logging.CLog().Error("Members are full")
		return
	}

	node.members = append(node.members, id)
}

//
func (node *Node) RemovePeer(id peer.ID) {
	res := make([]peer.ID, 0)
	for _, m := range node.members {
		if m.String() == id.String() {
			continue
		}
		res = append(res, m)
	}

	node.members = res
}

//
func (node *Node) Members() []peer.ID {
	res := make([]peer.ID, 0)
	copy(res, node.members)
	res = append(res, node.id)

	return res
}

// NewNode return new Node according to the config.
func NewNode(config *Config) (*Node, error) {
	// verify Listen port.
	if err := verifyPortAvailable(config.Listen); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err":    err,
			"listen": config.Listen,
		}).Error("Failed to check port.")
		return nil, err
	}

	node := &Node{
		quitCh:        make(chan bool, 10),
		config:        config,
		context:       context.Background(),
		streamManager: NewStreamManager(config),
		synchronizing: false,
		members:       make([]peer.ID, 0),
	}

	initP2PNetworkKey(config, node)
	_ = initP2PRouteTable(config, node)

	if err := initP2PSwarmNetwork(config, node); err != nil {
		return nil, err
	}

	return node, nil
}

func initP2PNetworkKey(config *Config, node *Node) {
	// init p2p network key.
	networkKey, err := LoadNetworkKeyFromFileOrCreateNew(config.PrivateKeyPath)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err":     err,
			"Network": config.PrivateKeyPath,
		}).Warn("Failed to load network private key from file.")
	}

	node.networkKey = networkKey
	node.id, err = peer.IDFromPublicKey(networkKey.GetPublic())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err":     err,
			"Network": config.PrivateKeyPath,
		}).Warn("Failed to generate ID from network key file.")
	}
}

func initP2PRouteTable(config *Config, node *Node) error {
	// init p2p route table.
	node.routeTable = NewRouteTable(config, node)
	return nil
}

func (node *Node) startHost() error {
	// add nat manager
	options := &basichost.HostOpts{}
	options.NATManager = basichost.NewNATManager
	host, err := basichost.NewHost(node.context, node.network, options)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err":            err,
			"listen address": node.config.Listen,
		}).Error("Failed to start node.")
		return err
	}

	host.SetStreamHandler(GtProtocolID, node.onStreamConnected)
	node.host = host

	return nil
}

// GenUpgrader creates a new connection upgrader for use with this swarm.
func GenUpgrader(n *swarm.Swarm) *tptu.Upgrader {
	id := n.LocalPeer()
	pk := n.Peerstore().PrivKey(id)
	secMuxer := new(csms.SSMuxer)
	secMuxer.AddTransport(secio.ID, &secio.Transport{
		LocalID:    id,
		PrivateKey: pk,
	})

	stMuxer := msmux.NewBlankTransport()
	stMuxer.AddTransport(GtProtocolID, yamux.DefaultTransport)

	return &tptu.Upgrader{
		Secure:  secMuxer,
		Muxer:   stMuxer,
		Filters: n.Filters,
	}

}

func initP2PSwarmNetwork(config *Config, node *Node) error {
	// init p2p multiaddr and swarm network.
	swarm := swarm.NewSwarm(
		node.context,
		node.id,
		node.routeTable.peerStore,
		metrics.NewBandwidthCounter(),
	)

	tcpTransport := tcp.NewTCPTransport(GenUpgrader(swarm))
	if err := swarm.AddTransport(tcpTransport); err != nil {
		panic(err)
	}

	for _, v := range node.config.Listen {
		tcpAddr, err := net.ResolveTCPAddr("tcp", v)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err":    err,
				"listen": v,
			}).Error("Failed to bind node socket.")
			return err
		}

		addr, err := multiaddr.NewMultiaddr(
			fmt.Sprintf(
				"/ip4/%s/tcp/%d",
				tcpAddr.IP,
				tcpAddr.Port,
			),
		)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err":    err,
				"listen": v,
			}).Error("Failed to bind node socket.")
			return err
		}
		swarm.Listen(addr)
	}
	swarm.Peerstore().AddAddrs(node.id, swarm.ListenAddresses(), peerstore.PermanentAddrTTL)
	node.network = swarm
	return nil
}

// Start host & route table discovery
func (node *Node) Start() error {
	logging.CLog().Info("Starting GtService Node...")

	node.streamManager.Start()

	if err := node.startHost(); err != nil {
		return err
	}

	node.routeTable.Start()

	logging.CLog().WithFields(logrus.Fields{
		"id":                node.ID(),
		"listening address": node.host.Addrs(),
	}).Info("Started GtService Node.")

	return nil
}

// Stop stop a node.
func (node *Node) Stop() {
	logging.CLog().WithFields(logrus.Fields{
		"id":                node.ID(),
		"listening address": node.host.Addrs(),
	}).Info("Stopping GtService Node...")

	node.routeTable.Stop()
	node.stopHost()
	node.streamManager.Stop()
}

func (node *Node) stopHost() {
	node.network.Close()

	if node.host == nil {
		return
	}

	node.host.Close()
}

// BroadcastMessage broadcast message.
func (node *Node) BroadcastMessage(messageName string, data Serializable, priority int) {
	// node can not broadcast or relay message if it is in synchronizing.
	if node.synchronizing {
		return
	}

	node.streamManager.BroadcastMessage(messageName, data, priority)
}

// RelayMessage relay message.
func (node *Node) RelayMessage(messageName string, data Serializable, priority int) {
	// node can not broadcast or relay message if it is in synchronizing.
	if node.synchronizing {
		return
	}

	node.streamManager.RelayMessage(messageName, data, priority)
}

// SendMessageToPeer send message to a peer.
func (node *Node) SendMessageToPeer(messageName string, data []byte, priority int, peerID string) error {
	stream := node.streamManager.GetStreamByPeerID(peerID)
	if stream == nil {
		logging.VLog().WithFields(logrus.Fields{
			"pid": peerID,
			"err": ErrPeerIsNotConnected,
		}).Debug("Failed to locate peer's stream")
		return ErrPeerIsNotConnected
	}

	return stream.SendMessage(messageName, data, priority)
}

// SendMessageToPeer send message to a peer by peerId
func (node *Node) SendMessageToPeerOrBroadcast(messageName string, messageContent Serializable, priority int, peerID string) error {
	pb, _ := messageContent.ToProto()
	data, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	stream := node.streamManager.GetStreamByPeerID(peerID)
	if stream != nil {
		return stream.SendMessage(messageName, data, priority)
	}

	logging.VLog().WithFields(logrus.Fields{
		"pid":     peerID,
		"mgsName": messageName,
		"err":     ErrPeerIsNotConnected,
	}).Debug("no connected, broadcast the data")

	node.BroadcastMessage(messageName, messageContent, priority)
	return nil
}

// SetGtService set netService
func (node *Node) SetGtService(ns *GtService) {
	node.netService = ns
}

// ID return node ID.
func (node *Node) ID() string {
	return node.id.Pretty()
}

//Synchronized return node synchronized status
func (node *Node) Synchronized() bool {
	return node.synchronizing
}

//BucketSize return node routeTable's bucket size
func (node *Node) BucketSize() int {
	return len(node.routeTable.routeTable.Buckets)
}

// StreamManager return node streamManager
func (node *Node) StreamManager() *StreamManager {
	return node.streamManager
}

func (node *Node) onStreamConnected(s network.Stream) {
	node.streamManager.Add(s, node)
}

func (node *Node) AllPeerIds() []string {
	if node == nil {
		return nil
	}
	allStreams := node.streamManager.allStreams

	ids := make([]string, 0)
	allStreams.Range(func(id, value interface{}) bool {
		if value == nil {
			return true
		}
		stream := value.(*Stream)
		if stream.IsHandshakeSucceed() {
			ids = append(ids, id.(string))
		}
		return true
	})
	return ids
}
