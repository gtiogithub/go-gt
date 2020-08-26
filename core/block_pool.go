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
	"errors"
	"sync"
	"time"

	corepb "gt.pro/gtio/go-gt/core/pb"
	net "gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/gogo/protobuf/proto"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

// constants
const (
	NoSender = ""
)

type BlockPool struct {
	size                int
	recvBlockCh         chan net.Message
	recvDownloadBlockCh chan net.Message
	quitCh              chan int
	bc                  *BlockChain
	cache               *lru.Cache
	ns                  net.Service
	mu                  sync.RWMutex
}

// NewBlockPool return new BlockPool instance.
func NewBlockPool(size int) (*BlockPool, error) {
	bp := &BlockPool{
		size:                size,
		recvBlockCh:         make(chan net.Message, size),
		recvDownloadBlockCh: make(chan net.Message, size),
		quitCh:              make(chan int, 1),
		//voteeCache:          make(map[uint64]map[int32]*VoteeRealState),
	}
	var err error
	bp.cache, err = lru.NewWithEvict(size, func(key interface{}, value interface{}) {
		lb := value.(*linkedBlock)
		if lb != nil {
			lb.Dispose()
		}
	})

	if err != nil {
		return nil, err
	}

	return bp, nil
}

// RegisterInNetwork register message subscriber in network.
func (blkp *BlockPool) RegisterInNetwork(ns net.Service) {
	ns.Register(net.NewSubscriber(blkp, blkp.recvBlockCh, true, MessageTypeNewBlock, net.MessageWeightNewBlock))
	ns.Register(net.NewSubscriber(blkp, blkp.recvBlockCh, false, MessageTypeBlockDownloadResponse, net.MessageWeightZero))
	ns.Register(net.NewSubscriber(blkp, blkp.recvDownloadBlockCh, false, MessageTypeParentBlockDownloadRequest, net.MessageWeightZero))
	blkp.ns = ns
}

// Start start loop.
func (blkp *BlockPool) Start() {
	logging.CLog().WithFields(logrus.Fields{
		"size": blkp.size,
	}).Info("Starting BlockPool...")

	go blkp.loop()
}

// Stop stop loop.
func (blkp *BlockPool) Stop() {
	logging.CLog().WithFields(logrus.Fields{
		"size": blkp.size,
	}).Info("Stopping BlockPool...")

	blkp.quitCh <- 0
}

// Add block into block pool
func (blkp *BlockPool) Add(block *Block) error {
	if block == nil {
		return ErrNilArgument
	}
	blkp.mu.Lock()
	defer blkp.mu.Unlock()
	block, err := mockBlockFromNetwork(block)
	if err != nil {
		return err
	}
	pushErr := blkp.add(NoSender, block)
	if pushErr != nil && pushErr != ErrDuplicatedBlock {
		return pushErr
	}
	return nil
}

// AddAndBroadcast adds block into block pool and broadcast it.
func (blkp *BlockPool) AddAndBroadcast(block *Block) error {
	if block == nil {
		return ErrNilArgument
	}
	blkp.mu.Lock()
	defer blkp.mu.Unlock()

	block, err := mockBlockFromNetwork(block)
	if err != nil {
		return err
	}

	blkp.ns.Broadcast(MessageTypeNewBlock, block, net.MessagePriorityHigh)
	return blkp.add(NoSender, block)
}

// AddAndRelay adds block into block pool and relay it.
func (blkp *BlockPool) AddAndRelay(sender string, block *Block) error {
	if block == nil {
		return ErrNilArgument
	}
	blkp.mu.Lock()
	defer blkp.mu.Unlock()

	block, err := mockBlockFromNetwork(block)
	if err != nil {
		return err
	}

	return blkp.add(sender, block)
}

// handle loop
func (blkp *BlockPool) loop() {
	logging.CLog().Info("Started BlockPool...")
	timerChan := time.NewTicker(time.Second).C

	myId := blkp.ns.Node().ID()
	for {
		select {
		case <-timerChan:
			metricsCachedNewBlock.Update(int64(len(blkp.recvBlockCh)))
			metricsCachedDownloadBlock.Update(int64(len(blkp.recvDownloadBlockCh)))
			metricsLruPoolCacheBlock.Update(int64(blkp.cache.Len()))

		case <-blkp.quitCh:
			logging.CLog().Info("Stopped BlockPool.")
			return

		case msg := <-blkp.recvBlockCh:
			if myId != msg.MessageFrom() {
				go blkp.handleReceivedBlock(msg)
			}
		case msg := <-blkp.recvDownloadBlockCh:
			go blkp.handleParentDownloadRequest(msg)
		}
	}
}

// handle received block
func (blkp *BlockPool) handleReceivedBlock(msg net.Message) {
	if msg.MessageType() != MessageTypeNewBlock && msg.MessageType() != MessageTypeBlockDownloadResponse {
		logging.VLog().WithFields(logrus.Fields{
			"msgType": msg.MessageType(),
			"msg":     msg,
			"err":     "neither new block nor download block response msg",
		}).Error("Received unregistered message.")
		return
	}

	block := new(Block)
	pbblock := new(corepb.Block)
	if err := proto.Unmarshal(msg.Data(), pbblock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"msgType": msg.MessageType(),
			"msg":     msg,
			"err":     err,
		}).Error("Failed to unmarshal data.")
		return
	}
	if err := block.FromProto(pbblock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"msgType": msg.MessageType(),
			"msg":     msg,
			"err":     err,
		}).Error("Failed to recover a block from proto data.")
		return
	}

	if msg.MessageType() == MessageTypeNewBlock &&
		blkp.bc.consensus.CheckDoubleMint(block) {
		return
	}

	logging.VLog().WithFields(logrus.Fields{
		"block": block,
		"type":  msg.MessageType(),
	}).Debug("Received a new block.")

	if err := blkp.AddAndRelay(msg.MessageFrom(), block); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("add and relay received block failed")
	}

}

// handle parent download request
func (blkp *BlockPool) handleParentDownloadRequest(msg net.Message) {
	if msg.MessageType() != MessageTypeParentBlockDownloadRequest {
		logging.VLog().WithFields(logrus.Fields{
			"messageType": msg.MessageType(),
			"message":     msg,
			"err":         "wrong msg type",
		}).Debug("Failed to received a download request.")
		return
	}

	pbDownloadBlock := new(corepb.DownloadBlock)
	if err := proto.Unmarshal(msg.Data(), pbDownloadBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"msgType": msg.MessageType(),
			"msg":     msg,
			"err":     err,
		}).Debug("Failed to unmarshal data.")
		return
	}

	if byteutils.Equal(pbDownloadBlock.Hash, blkp.bc.genesisBlock.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"download.hash": byteutils.Hex(pbDownloadBlock.Hash),
		}).Debug("Asked to download genesis's parent, ignore it.")
		return
	}

	block := blkp.bc.GetBlock(pbDownloadBlock.Hash)
	if block == nil {
		logging.VLog().WithFields(logrus.Fields{
			"download.hash": byteutils.Hex(pbDownloadBlock.Hash),
		}).Debug("Failed to find the block asked for.")
		return
	}

	if !block.SignHash().Equals(pbDownloadBlock.GetSign().Data) {
		logging.VLog().WithFields(logrus.Fields{
			"download.hash": byteutils.Hex(pbDownloadBlock.Hash),
			"download.sign": byteutils.Hex(pbDownloadBlock.GetSign().Data),
			"expect.sign":   block.SignHash().Hex(),
		}).Debug("Failed to check the block's signature.")
		return
	}

	parent := blkp.bc.GetBlock(block.header.parentHash)
	if parent == nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
		}).Debug("Failed to find the block's parent.")
		return
	}

	pbBlock, err := parent.ToProto()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"parent": parent,
			"err":    err,
		}).Debug("Failed to convert the block's parent to proto data.")
		return
	}
	bytes, err := proto.Marshal(pbBlock)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"parent": parent,
			"err":    err,
		}).Debug("Failed to marshal the block's parent.")
		return
	}
	_ = blkp.ns.SendMessage(MessageTypeBlockDownloadResponse, bytes, msg.MessageFrom(), net.MessagePriorityNormal)

	logging.VLog().WithFields(logrus.Fields{
		"block":  block,
		"parent": parent,
	}).Debug("Responsed to the download request.")
}

// set blockchain
func (blkp *BlockPool) setBlockChain(bc *BlockChain) {
	blkp.bc = bc
}

// add block into block pool
func (blkp *BlockPool) add(sender string, block *Block) error {
	// verify non-dup block
	if blkp.cache.Contains(block.Hash().Hex()) || blkp.bc.GetBlock(block.Hash()) != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
		}).Error("Found duplicated block.")
		return ErrDuplicatedBlock
	}
	//logging.CLog().WithFields(logrus.Fields{
	//	"block pool add block height": block.Height(),
	//}).Info("block pool add block height")
	// verify block integrity
	if block.Height() == 1 {
		if !CheckGenesisBlock(blkp.bc.genesisBlock, block) {
			logging.VLog().WithFields(logrus.Fields{
				"block": block,
			}).Error("Failed to check block integrity.")
			return errors.New("invalid genesis block")
		}
	} else if err := block.VerifyIntegrity(blkp.bc.chainId, blkp.bc.consensus); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("Failed to check block integrity.")
		return err
	}

	bc := blkp.bc
	cache := blkp.cache

	var plb *linkedBlock
	lb := newLinkedBlock(block, blkp.bc)
	cache.Add(lb.hash.Hex(), lb)

	// find child block in pool.
	for _, k := range cache.Keys() {
		v, _ := cache.Get(k)
		c := v.(*linkedBlock)
		if c.parentHash.Equals(lb.hash) {
			// found child block and continue.
			c.LinkParent(lb)
		}
	}

	// find parent block in cache.
	gap := 0
	v, _ := cache.Get(lb.parentHash.Hex())
	if v != nil {
		// found in cache.
		plb = v.(*linkedBlock)
		lb.LinkParent(plb)
		lb = plb
		gap++

		for lb.parentBlock != nil {
			lb = lb.parentBlock
			gap++
		}

		logging.VLog().WithFields(logrus.Fields{
			"block": plb.block,
		}).Warn("Found unlinked ancestor.")

		if sender == NoSender {
			return ErrMissingParentBlock
		}
	}

	// find parent in Chain.
	var parentBlock *Block
	if parentBlock = bc.GetBlock(lb.parentHash); parentBlock == nil {
		// still not found, wait to parent block from network.
		if sender == NoSender {
			return ErrMissingParentBlock
		}

		// do sync if there are so many empty slots.
		if gap > ChunkSize {
			if bc.StartActiveSync() {
				logging.CLog().WithFields(logrus.Fields{
					"tail":    bc.tailBlock,
					"block":   block,
					"offline": gap,
					"limit":   ChunkSize,
				}).Warn("Offline too long, pend mining and restart sync from others.")
			}
			return ErrInvalidBlockCannotFindParentInLocalAndTrySync
		}
		if !bc.IsActiveSyncing() {
			if err := blkp.downloadParent(sender, lb.block); err != nil {
				return err
			}
		}
		return ErrInvalidBlockCannotFindParentInLocalAndTryDownload
	}

	if sender != NoSender {
		blkp.ns.Relay(MessageTypeNewBlock, block, net.MessagePriorityHigh)
	}

	// found in BlockChain, then we can verify the state root, and tell the Consensus all the tails.
	// performance depth-first search to verify state root, and get all tails.
	allBlocks, tailBlocks, err := lb.travelToLinkAndReturnAllValidBlocks(parentBlock)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"parent.hash":  parentBlock.Hash().Hex(),
			"block.hash":   lb.block.Hash().Hex(),
			"block.height": lb.block.Height(),
			"err":          err,
		}).Error("failed link travelToLinkAndReturnAllValidBlocks")
		cache.Remove(lb.hash.Hex())
		return err
	}

	if err := bc.putVerifiedNewBlocks(parentBlock, allBlocks, tailBlocks); err != nil {
		cache.Remove(lb.hash.Hex())
		return err
	}
	// remove allBlocks from cache.
	for _, v := range allBlocks {
		cache.Remove(v.Hash().Hex())
	}

	return blkp.bc.Consensus().HandleFork()
}

// download parent
func (blkp *BlockPool) downloadParent(sender string, block *Block) error {
	downloadMsg := &corepb.DownloadBlock{
		Hash: block.Hash(),
		Sign: block.Signature(),
	}
	bytes, err := proto.Marshal(downloadMsg)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Debug("Failed to send download request.")
		return err
	}

	_ = blkp.ns.SendMessage(MessageTypeParentBlockDownloadRequest, bytes, sender, net.MessagePriorityNormal)

	logging.VLog().WithFields(logrus.Fields{
		"target": sender,
		"block":  block,
		"tail":   blkp.bc.TailBlock(),
		"gap":    block.Height() - blkp.bc.TailBlock().Height(),
		"limit":  ChunkSize,
	}).Info("Send download request.")

	return nil
}

// mock block
func mockBlockFromNetwork(block *Block) (*Block, error) {
	pbBlock, err := block.ToProto()
	if err != nil {
		return nil, err
	}
	bytes, err := proto.Marshal(pbBlock)
	if err := proto.Unmarshal(bytes, pbBlock); err != nil {
		return nil, err
	}
	block = new(Block)
	err = block.FromProto(pbBlock)
	return block, err
}

// return the recv channel
func (blkp *BlockPool) RecvBlockCh() chan net.Message {
	return blkp.recvBlockCh
}

// check the genesis block
func CheckGenesisBlock(localGenesis, remoteGenesis *Block) bool {
	if remoteGenesis == nil {
		return false
	}

	hash := localGenesis.Hash()
	//txs := localGenesis.Transactions()
	if hash.Equals(remoteGenesis.Hash()) {
		//logging.VLog().Error("[Verify Genesis] Genesis hash error")
		return true
	}

	//geneTxs := remoteGenesis.Transactions()
	//if len(txs) != len(geneTxs) {
	//	logging.VLog().Error("[Verify Genesis] Genesis txs amount error")
	//	return false
	//}
	//
	//for i := 0; i < len(txs); i++ {
	//	if !txs[i].hash.Equals(geneTxs[i].hash) {
	//		logging.VLog().WithFields(logrus.Fields{
	//			"local_tx_hash":   txs[i].hash.String(),
	//			"receive_tx_hash": geneTxs[i].hash.String(),
	//		}).Error("[Verify Genesis] Genesis txs hash error")
	//		return false
	//	}
	//}
	//
	//logging.VLog().Debug("[Verify Genesis] Verify genesis block succeed.")

	return false
}
