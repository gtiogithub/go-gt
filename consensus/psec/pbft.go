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
package psec

import (
	"encoding/json"
	"errors"
	lru "github.com/hashicorp/golang-lru"
	"gt.pro/gtio/go-gt/crypto"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"math/big"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/account"
	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
)

var (
	PBFTSignMessageError = errors.New("PBFT sign msg error")
)

//
type PbftContext struct {
	timestamp  int64
	ppVoteFlag bool
	ppMsg      *corepb.PbftMsg
	paVoteFlag bool
	paMsgs     map[string]*corepb.PbftMsg
	cmVoteFlag bool
	cmMsgs     map[string]*corepb.PbftMsg
	submitFlag bool
	maxFault   int32
	peers      []string
}

// Pbft
type PBFT struct {
	chain     *core.BlockChain
	consensus core.Consensus
	ns        network.Service
	storage   cdb.Storage

	slot                 *lru.Cache
	context              map[int64]*PbftContext
	messageCh            chan network.Message
	historyCollectBlocks map[uint64]map[string]*core.Block

	quitCh chan bool
}

type Digest struct {
	Hash     string
	PrevHash string
}

// NewPbft
func NewPbft(consensus core.Consensus, ns network.Service, chain *core.BlockChain) (*PBFT, error) {
	slot, err := lru.New(128)
	if err != nil {
		return nil, err
	}
	return &PBFT{
		consensus:            consensus,
		chain:                chain,
		ns:                   ns,
		storage:              chain.Storage(),
		messageCh:            make(chan network.Message, 128),
		slot:                 slot,
		context:              make(map[int64]*PbftContext),
		historyCollectBlocks: make(map[uint64]map[string]*core.Block),
		quitCh:               make(chan bool),
	}, nil
}

func (pbft *PBFT) handleMessage(msg network.Message) {
	if !pbft.consensus.IsEnable() {
		return
	}
	if pbft.consensus.IsSuspend() {
		return
	}
	if msg.MessageType() == network.Pbft {
		pbftMsg := new(corepb.PbftMsg)
		err := proto.Unmarshal(msg.Data(), pbftMsg)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("unmarshal pbft msg error")
			return
		}
		switch pbftMsg.Type {
		case PP:
			logging.VLog().WithFields(logrus.Fields{
				"received": msg.MessageFrom(),
				"stage":    pbftMsg.Type,
				"view_id":  pbftMsg.ViewId,
				"seqid":    pbftMsg.SeqId,
			}).Debug("[PBFT] received PP message")
			if err := pbft.handlePreprepare(pbftMsg); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("[PBFT] invalid preprepare message")
			}
		case PA:
			logging.VLog().WithFields(logrus.Fields{
				"received": msg.MessageFrom(),
				"stage":    pbftMsg.Type,
				"view_id":  pbftMsg.ViewId,
				"seqid":    pbftMsg.SeqId,
			}).Debug("[PBFT] received PA message")
			if err := pbft.handlePrepare(pbftMsg); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("[PBFT] invalid prepare message")
			}
		case CM:
			logging.VLog().WithFields(logrus.Fields{
				"received": msg.MessageFrom(),
				"stage":    pbftMsg.Type,
				"view_id":  pbftMsg.ViewId,
				"seqid":    pbftMsg.SeqId,
			}).Debug("[PBFT] received CM message")
			if err := pbft.handleCommit(pbftMsg); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("[PBFT] invalid commit message")
			}
		}
	}
}
func (pbft *PBFT) Run() {
	timeChan := time.NewTicker(time.Second)
	for {
		select {
		case now := <-timeChan.C:
			pbft.mineBlock(now.Unix()+3, now.Unix())
		case msg := <-pbft.messageCh:
			pbft.handleMessage(msg)
		case <-pbft.quitCh:
			logging.CLog().Info("Stopped Mining...")
			return
		}
	}
}

func (pbft *PBFT) Stop() {
	pbft.quitCh <- true
}

func (pbft *PBFT) checkProposer(council *Council, timestamp int64) bool {

	if council.council.Panels == nil || len(council.council.Panels) == 0 {
		return false
	}

	timeDiff := timestamp - council.council.Meta.Timestamp
	multiple := timeDiff / int64(council.council.Meta.Config.BlockInterval)
	offset := multiple % int64(council.council.Meta.Config.WitnessCount)

	panel := council.council.Panels[offset]
	if panel.Leader.Address == pbft.consensus.Coinbase().String() {
		return true
	}

	return false
}

func (pbft *PBFT) loadCouncil(prevHash byteutils.Hash) (*Council, error) {
	prevBlock := pbft.chain.GetBlock(prevHash)
	if prevBlock == nil {
		return nil, core.ErrNotFoundBlockByHash
	}
	periodRoot := &PeriodRoot{}
	if prevBlock.ConsensusRoot().PeriodRoot != nil && len(prevBlock.ConsensusRoot().PeriodRoot) > 0 {
		if err := json.Unmarshal(prevBlock.ConsensusRoot().PeriodRoot, periodRoot); err != nil {
			return nil, err
		}
	}

	councilTrie, err := trie.NewTrie(periodRoot.CouncilRoot, pbft.storage, false)
	if err != nil {
		return nil, err
	}

	termId := prevBlock.TermId()
	pbCouncil, err := prevBlock.WorldState().GetCouncil(prevBlock.TermId())
	if pbCouncil.Meta.TenureEndHeight == prevBlock.Height() {
		termId++
	}
	byteCouncil, err := councilTrie.Get(byteutils.FromUint64(termId))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	council, _ := NewCouncil(pbft.chain, core.GenesisTimestamp, false)
	if byteCouncil != nil {
		if err := council.FromBytes(byteCouncil, pbft.storage, false); err != nil {
			return nil, err
		}
	}
	return council, nil
}

// mine new block
func (pbft *PBFT) mineBlock(deadline int64, mineTime int64) error {

	if !pbft.consensus.IsEnable() {
		return ErrCannotMintWhenDisable
	}
	if pbft.consensus.IsSuspend() {
		return ErrCannotMintWhenPending
	}

	tail := pbft.chain.TailBlock()

	council, err := pbft.loadCouncil(tail.Hash())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"hash": tail.Hash().String(),
			"err":  err,
		}).Error("Load council failed")
		return err
	}

	timeDiff := mineTime - council.council.Meta.Timestamp

	remainder := timeDiff % int64(council.council.Meta.Config.BlockInterval)
	if remainder != 0 {
		return nil
	}

	pbft.context = make(map[int64]*PbftContext)
	go pbft.clearInvalidCollectBlocks()

	if !pbft.checkProposer(council, mineTime) {
		return nil
	}

	block, err := pbft.consensus.NewBlock(tail, deadline, mineTime)
	if err != nil {
		return err
	}

	if err := pbft.SendPreprepareMsg(block); err != nil {
		go block.PutBackTxs()
		return err
	}

	return nil
}

func (pbft *PBFT) clearHistoryCollectBlocks(block *core.Block, tail *core.Block) {
	if collectBlocks, ok := pbft.historyCollectBlocks[block.Height()]; ok {
		hash := byteutils.Hex(block.Hash())
		if _, ok = collectBlocks[hash]; ok {
			block.SetTxPool(tail)
			go block.PutBackTxs()
			delete(collectBlocks, hash)
		}
	}
}

func (pbft *PBFT) clearInvalidCollectBlocks() {
	tail := pbft.chain.TailBlock()
	if pbft.historyCollectBlocks == nil || len(pbft.historyCollectBlocks) == 0 {
		return
	}
	for height, collectBlocks := range pbft.historyCollectBlocks {
		if height > tail.Height() {
			continue
		}
		for hash, block := range collectBlocks {
			validBlock := pbft.chain.GetBlockOnCanonicalChainByHeight(block.Height())
			if byteutils.Hex(validBlock.Hash()) != hash {
				block.SetTxPool(tail)
				go block.PutBackTxs()
			}
			logging.VLog().WithFields(logrus.Fields{
				"hash": hash,
			}).Debug("[PBFT Block] Clear Invalid Collect Blocks")
			delete(collectBlocks, hash)
		}
		delete(pbft.historyCollectBlocks, height)
	}
}

func (pbft *PBFT) AddHistoryCollectBlock(block *core.Block) {

	if _, ok := pbft.historyCollectBlocks[block.Height()]; !ok {
		pbft.historyCollectBlocks[block.Height()] = make(map[string]*core.Block)
	}
	pbft.historyCollectBlocks[block.Height()][byteutils.Hex(block.Hash())] = block
}

// preprepare
func (pbft *PBFT) SendPreprepareMsg(block *core.Block) error {
	pbft.AddHistoryCollectBlock(block)

	pbBlock, err := block.ToProto()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("[PBFT Preprepare] convert block to pb error")
		return err
	}

	dataBytes, err := proto.Marshal(pbBlock)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("[PBFT Preprepare] block marsha1 error")
	}
	coinbase := pbft.consensus.Coinbase().String()
	ppMsg := &corepb.PbftMsg{
		Timestamp: block.Timestamp(),
		Type:      PP,
		ViewId:    coinbase,
		SeqId:     block.Height(),
		Data:      dataBytes,
	}

	// sign pre-prepare message
	if err := pbft.SignPbftMsg(ppMsg); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("[PBFT Preprepare] sign preprepare msg error")
		return err
	}

	digest := &Digest{
		Hash:     block.Hash().String(),
		PrevHash: block.ParentHash().String(),
	}

	if err := pbft.AddPrePrepareMsg(digest, ppMsg); err != nil {
		return err
	}
	// record msg
	key := ppMsg.Timestamp
	if err := pbft.sendMessageToPeers(network.Pbft, ppMsg, pbft.context[key].peers); err != nil {
		return err
	}

	digestBytes, err := json.Marshal(digest)
	if err != nil {
		return err
	}
	paMsg := &corepb.PbftMsg{
		Timestamp: ppMsg.Timestamp,
		Type:      PA,
		ViewId:    ppMsg.ViewId,
		SeqId:     ppMsg.SeqId,
		Data:      digestBytes,
	}

	// sign pre-prepare message
	if err := pbft.SignPbftMsg(paMsg); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("[PBFT Preprepare] sign prepare msg error")
		return err
	}

	if err := pbft.AddPrepareMsg(paMsg, true); err != nil {
		return err
	}

	if err := pbft.sendMessageToPeers(network.Pbft, paMsg, pbft.context[key].peers); err != nil {
		return err
	}
	return nil
}

func (pbft *PBFT) newPbftContext(pervHash string) (*PbftContext, error) {
	context := &PbftContext{
		timestamp:  0,
		paVoteFlag: false,
		ppMsg:      nil,
		ppVoteFlag: false,
		paMsgs:     make(map[string]*corepb.PbftMsg),
		cmVoteFlag: false,
		cmMsgs:     make(map[string]*corepb.PbftMsg),
		submitFlag: false,
		peers:      make([]string, 0),
	}
	bytes, err := byteutils.FromHex(pervHash)
	if err != nil {
		return nil, err
	}
	peers := make([]string, 0)
	council, err := pbft.loadCouncil(bytes)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"hash": pervHash,
			"err":  err,
		}).Error("[PBFT ] load Council failed")
		return nil, err
	}
	for _, panel := range council.council.Panels {
		peers = append(peers, panel.Leader.PeerId)
	}
	context.peers = append(context.peers, peers...)
	context.maxFault = council.council.Meta.Config.WitnessCount / 3
	return context, nil
}

// add pre-prepare msg
func (pbft *PBFT) AddPrePrepareMsg(digest *Digest, prePrepareMsg *corepb.PbftMsg) error {
	key := prePrepareMsg.Timestamp
	var context *PbftContext
	var err error
	var ok bool
	if context, ok = pbft.context[key]; !ok {
		if context, err = pbft.newPbftContext(digest.PrevHash); err != nil {
			return err
		}
		context.ppVoteFlag = true
	}
	if context.ppMsg == nil {
		context.timestamp = prePrepareMsg.Timestamp
		context.ppMsg = prePrepareMsg
	}
	pbft.context[key] = context
	return nil
}

// add prepare msg
func (pbft *PBFT) AddPrepareMsg(prepareMsg *corepb.PbftMsg, self bool) error {
	digest := &Digest{}
	err := json.Unmarshal(prepareMsg.Data, digest)
	if err != nil {
		return err
	}
	key := prepareMsg.Timestamp
	var context *PbftContext
	var ok bool
	if context, ok = pbft.context[key]; !ok {
		if context, err = pbft.newPbftContext(digest.PrevHash); err != nil {
			return err
		}
		if self {
			context.paVoteFlag = true
		}
	}
	signer := byteutils.Hex(prepareMsg.Sign.Signer)
	oldPrepare, ok := context.paMsgs[signer]
	if !ok {
		context.paMsgs[signer] = prepareMsg
	} else {
		if !byteutils.Equal(oldPrepare.Data, prepareMsg.Data) {
			go pbft.reportTwoWayEvil(oldPrepare, prepareMsg)
		}
	}
	pbft.context[key] = context
	return nil
}

// add commit msg
func (pbft *PBFT) AddCommitMsg(commitMsg *corepb.PbftMsg, self bool) error {
	digest := &Digest{}
	err := json.Unmarshal(commitMsg.Data, digest)
	if err != nil {
		return err
	}
	key := commitMsg.Timestamp
	var context *PbftContext
	var ok bool
	if context, ok = pbft.context[key]; !ok {
		if context, err = pbft.newPbftContext(digest.PrevHash); err != nil {
			return err
		}
		if self {
			context.cmVoteFlag = true
		}
	}
	signer := byteutils.Hex(commitMsg.Sign.Signer)
	oldCommit, ok := context.cmMsgs[signer]
	if !ok {
		context.cmMsgs[signer] = commitMsg
	} else {
		if !byteutils.Equal(oldCommit.Data, commitMsg.Data) {
			go pbft.reportTwoWayEvil(oldCommit, commitMsg)
		}
	}
	pbft.context[key] = context
	return nil
}

func (pbft *PBFT) sendMessageToPeers(messageName string, pbftMsg *corepb.PbftMsg, peers []string) error {
	data, err := proto.Marshal(pbftMsg)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("PbftMsg marshal error")
		return err
	}
	for _, peer := range peers {
		if peer == pbft.ns.Node().ID() {
			continue
		}
		if err = pbft.ns.SendMessageToPeer(messageName, data, network.MessagePriorityHigh, peer); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"messageName": messageName,
				"err":         err,
			}).Info("send pbft message failed ")
		}
		logging.VLog().WithFields(logrus.Fields{
			"messageName": messageName,
			"stage":       pbftMsg.Type,
			"viewId":      pbftMsg.ViewId,
			"seqid":       pbftMsg.SeqId,
			"peer":        peer,
		}).Debug("send pbft message success ")
	}
	return nil
}

// handle preprepare message
func (pbft *PBFT) handlePreprepare(ppMsg *corepb.PbftMsg) error {

	// verify msg
	paMsg, err := pbft.verifyPreprepare(ppMsg)
	if err != nil {
		return err
	}

	if paMsg == nil {
		return nil
	}
	digest := &Digest{}
	if err := json.Unmarshal(paMsg.Data, digest); err != nil {
		return err
	}

	if err := pbft.AddPrePrepareMsg(digest, ppMsg); err != nil {
		return err
	}

	key := ppMsg.Timestamp
	context, _ := pbft.context[key]
	if len(context.cmMsgs) >= int(context.maxFault*2)+1 {
		if err := pbft.doSubmitBlock(context); err != nil {
			return err
		}
		logging.VLog().WithFields(logrus.Fields{
			"view_id": ppMsg.ViewId,
			"seq_id":  ppMsg.SeqId,
		}).Debug("[PBFT Preprepare] add new block.")
		context.submitFlag = true
		pbft.context[key] = context
	}

	if err := pbft.AddPrepareMsg(paMsg, true); err != nil {
		return err
	}

	if err := pbft.sendMessageToPeers(network.Pbft, paMsg, pbft.context[key].peers); err != nil {
		return err
	}

	return nil
}

// handle prepare message
func (pbft *PBFT) handlePrepare(paMsg *corepb.PbftMsg) error {

	if err := pbft.verifyPrepare(paMsg); err != nil {
		return err
	}

	if err := pbft.AddPrepareMsg(paMsg, false); err != nil {
		return err
	}

	digest := &Digest{}
	if err := json.Unmarshal(paMsg.Data, digest); err != nil {
		return err
	}

	key := paMsg.Timestamp
	context, _ := pbft.context[key]

	if context.cmVoteFlag {
		return nil
	}
	if len(context.paMsgs) >= int(context.maxFault*2)+1 {
		cmMsg := &corepb.PbftMsg{
			Timestamp: paMsg.Timestamp,
			Type:      CM,
			ViewId:    paMsg.ViewId,
			SeqId:     paMsg.SeqId,
			Data:      paMsg.Data[:],
		}

		if err := pbft.SignPbftMsg(cmMsg); err != nil {
			return err
		}

		pbft.AddCommitMsg(cmMsg, true)

		if err := pbft.sendMessageToPeers(network.Pbft, cmMsg, context.peers); err != nil {
			return err
		}
	}

	return nil
}

// handle reply message
func (pbft *PBFT) handleReply(paMsg *corepb.PbftMsg) error {

	if err := pbft.verifyPrepare(paMsg); err != nil {
		return err
	}

	if err := pbft.AddPrepareMsg(paMsg, false); err != nil {
		return err
	}

	digest := &Digest{}
	if err := json.Unmarshal(paMsg.Data, digest); err != nil {
		return err
	}

	key := paMsg.Timestamp
	context, _ := pbft.context[key]

	if context.cmVoteFlag {
		return nil
	}
	if len(context.paMsgs) >= int(context.maxFault*2)+1 {
		cmMsg := &corepb.PbftMsg{
			Timestamp: paMsg.Timestamp,
			Type:      CM,
			ViewId:    paMsg.ViewId,
			SeqId:     paMsg.SeqId,
			Data:      paMsg.Data[:],
		}

		if err := pbft.SignPbftMsg(cmMsg); err != nil {
			return err
		}

		pbft.AddCommitMsg(cmMsg, true)

		if err := pbft.sendMessageToPeers(network.Pbft, cmMsg, context.peers); err != nil {
			return err
		}
	}

	return nil
}

func (pbft *PBFT) doSubmitBlock(pbftContext *PbftContext) error {
	pbBlock := &corepb.Block{}
	if err := proto.Unmarshal(pbftContext.ppMsg.Data, pbBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"seqid":  pbftContext.ppMsg.SeqId,
			"viewid": pbftContext.ppMsg.ViewId,
			"err":    err,
		}).Debug("Failed to unmarsha1 block data")
		return err
	}

	// check block
	block := new(core.Block)
	if err := block.FromProto(pbBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"seqid":  pbftContext.ppMsg.SeqId,
			"viewid": pbftContext.ppMsg.ViewId,
			"err":    err,
		}).Debug("Failed to recover a block from proto data.")
		return err
	}

	tail := pbft.chain.TailBlock()
	if tail.Height() >= block.Height() {
		logging.CLog().WithFields(logrus.Fields{
			"termId":       block.TermId(),
			"block.height": block.Height(),
			"tail.height":  tail.Height(),
		}).Info("commit block height is low.")
		return errors.New("commit block height is low ")
	}
	_ = pbft.addAndBroadcast(tail, block)
	return nil
}

// handle commit message
func (pbft *PBFT) handleCommit(cmMsg *corepb.PbftMsg) error {
	if err := pbft.verifyCommit(cmMsg); err != nil {
		return err
	}

	if err := pbft.AddCommitMsg(cmMsg, false); err != nil {
		return err
	}

	digest := &Digest{}
	if err := json.Unmarshal(cmMsg.Data, digest); err != nil {
		return err
	}

	key := cmMsg.Timestamp
	context, _ := pbft.context[key]
	if context.submitFlag {
		return nil
	}
	if len(context.cmMsgs) >= int(context.maxFault*2)+1 {
		if context.ppMsg != nil {
			if err := pbft.doSubmitBlock(context); err != nil {
				return err
			}
			logging.VLog().WithFields(logrus.Fields{
				"view_id": cmMsg.ViewId,
				"seq_id":  cmMsg.SeqId,
			}).Debug("[PBFT Commit] add new block.")
			context.submitFlag = true
			pbft.context[key] = context
		}
	}

	return nil
}

// verify preprepare message
func (pbft *PBFT) verifyPreprepare(msg *corepb.PbftMsg) (*corepb.PbftMsg, error) {

	if !pbft.verifyPbftMsg(msg) {
		return nil, ErrVerifyPreprepareMsgError
	}

	pbBlock := &corepb.Block{}
	if err := proto.Unmarshal(msg.Data, pbBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"seqid":  msg.SeqId,
			"viewid": msg.ViewId,
			"err":    err,
		}).Debug("Failed to unmarsha1 block data")
		return nil, err
	}

	// check block
	block := new(core.Block)
	if err := block.FromProto(pbBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"seqid":  msg.SeqId,
			"viewid": msg.ViewId,
			"err":    err,
		}).Debug("Failed to recover a block from proto data.")
		return nil, err
	}

	tail := pbft.chain.TailBlock()
	if tail.Height() >= block.Height() {
		logging.CLog().WithFields(logrus.Fields{
			"termId":       block.TermId(),
			"block.height": block.Height(),
			"tail.height":  tail.Height(),
		}).Info("preprepare block height is low.")
		return nil, ErrBlockHeightTooLow
	}

	council, err := pbft.loadCouncil(block.ParentHash())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"tail.height": tail.Height(),
		}).Info("get tail block council failed.")
		return nil, err
	}

	timeDiff := block.Timestamp() - council.council.Meta.Timestamp
	multiple := timeDiff / int64(council.council.Meta.Config.BlockInterval)
	offset := multiple % int64(council.council.Meta.Config.WitnessCount)
	panel := council.council.Panels[offset]

	if panel.Leader.Address != block.Coinbase().String() {
		logging.VLog().WithFields(logrus.Fields{
			"seqid":  msg.SeqId,
			"viewid": msg.ViewId,
			"hash":   byteutils.Hex(block.Header().Hash()),
			"err":    err,
		}).Debug("Failed to verify preprepare block, collect block time not match.")
		return nil, ErrInvalidBlockProposer
	}

	key := block.Timestamp()
	var context *PbftContext
	var ok bool
	if context, ok = pbft.context[key]; ok {
		if context.ppVoteFlag {
			return nil, nil
		}
	}

	if err := block.VerifyIntegrity(pbft.chain.ChainId(), pbft.consensus); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"seqid":  msg.SeqId,
			"viewid": msg.ViewId,
			"hash":   byteutils.Hex(block.Header().Hash()),
			"err":    err,
		}).Debug("Failed to verify preprepare block.")
		return nil, err
	}

	digest := &Digest{
		Hash:     block.Hash().String(),
		PrevHash: block.ParentHash().String(),
	}

	digestBytes, err := json.Marshal(digest)
	if err != nil {
		return nil, err
	}
	paMsg := &corepb.PbftMsg{
		Timestamp: msg.Timestamp,
		Type:      PA,
		ViewId:    msg.ViewId,
		SeqId:     msg.SeqId,
		Data:      digestBytes,
	}

	// sign pre-prepare message
	if err := pbft.SignPbftMsg(paMsg); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("[PBFT verifyPreprepare] sign prepare msg error")
		return nil, err
	}
	return paMsg, nil
}

func (pbft *PBFT) verifyPrepare(paMsg *corepb.PbftMsg) error {

	digest := &Digest{}
	if err := json.Unmarshal(paMsg.Data, digest); err != nil {
		return err
	}
	bytes, err := byteutils.FromHex(digest.PrevHash)
	if err != nil {
		return err
	}
	council, err := pbft.loadCouncil(bytes)
	if err != nil {
		return err
	}

	signer, err := core.NewAddressFromPublicKey(paMsg.Sign.Signer)
	if !council.isWitness(signer.String()) {
		return ErrInvalidPaSender
	}

	if !pbft.verifyPbftMsg(paMsg) {
		return ErrVerifyprepareMsgError
	}
	return nil
}

func (pbft *PBFT) verifyCommit(cmMsg *corepb.PbftMsg) error {

	digest := &Digest{}
	if err := json.Unmarshal(cmMsg.Data, digest); err != nil {
		return err
	}
	bytes, err := byteutils.FromHex(digest.PrevHash)
	if err != nil {
		return err
	}
	council, err := pbft.loadCouncil(bytes)
	if err != nil {
		return err
	}

	signer, err := core.NewAddressFromPublicKey(cmMsg.Sign.Signer)
	if !council.isWitness(signer.String()) {
		return ErrInvalidPaSender
	}

	if !pbft.verifyPbftMsg(cmMsg) {
		return ErrVerifyprepareMsgError
	}
	return nil
}

// verify vote message
func (pbft *PBFT) verifyPbftMsg(msg *corepb.PbftMsg) bool {
	targetHash := msg.CalcHash()
	sign, err := crypto.NewSignature()
	if err != nil {
		return false
	}
	if ok, err := sign.Verify(targetHash, msg.Sign); err != nil || !ok {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("verify response sign error.")
		return false
	}

	return true
}

// sign the preprepare message
func (pbft *PBFT) SignPbftMsg(msg *corepb.PbftMsg) error {
	coinbase := pbft.consensus.Coinbase()
	hash := msg.CalcHash()
	addrManager := pbft.consensus.(*Psec).am.(*account.AccountManager).GetAddrManager()
	signResult, err := addrManager.SignHash(coinbase, hash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"coinbase": coinbase.String(),
			"hash":     byteutils.Hex(hash),
			"type":     msg.Type,
			"err":      err,
		}).Debug("[PBFT] sign pbft message error")
		return PBFTSignMessageError
	}

	sign := &corepb.Signature{
		Signer: signResult.GetSigner(),
		Data:   signResult.GetData(),
	}

	msg.Sign = sign
	return nil
}

// add block into block pool and broadcast it
func (pbft *PBFT) addAndBroadcast(tail *core.Block, block *core.Block) error {
	//spendTime := time.Now().Unix() - block.Timestamp()
	//if spendTime > core.MaximumMiningTime {
	//	logging.CLog().WithFields(logrus.Fields{
	//		"tail":  tail,
	//		"block": block,
	//	}).Error(ErrMiningBlockTimeOut)
	//	return ErrMiningBlockTimeOut
	//}
	if err := pbft.chain.BlockPool().AddAndBroadcast(block); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"tail":  tail,
			"block": block,
			"err":   err,
		}).Error("Failed to push new minted block into block pool")
		return err
	}

	if !pbft.chain.TailBlock().Hash().Equals(block.Hash()) {
		return ErrAppendNewBlockFailed
	}

	logging.CLog().WithFields(logrus.Fields{
		"tail":  tail,
		"block": block,
	}).Info("Broadcasted new block")
	return nil
}

type DoubleMintEvil struct {
	PreHash string
	Hash    string
}

type TwoWayEvil struct {
	State     uint32
	PreDigest string
	Digest    string
}

func (pbft *PBFT) reportTwoWayEvil(preMsg *corepb.PbftMsg, msg *corepb.PbftMsg) error {
	// check mining enable
	if !pbft.consensus.IsEnable() || pbft.consensus.IsSuspend() {
		return nil
	}
	digest := &Digest{}
	err := json.Unmarshal(preMsg.Data, digest)
	if err != nil {
		return err
	}
	bytes, err := byteutils.FromHex(digest.PrevHash)
	if err != nil {
		return err
	}
	council, err := pbft.loadCouncil(bytes)
	if err != nil {
		return err
	}
	if council.isWitness(pbft.consensus.Coinbase().String()) {
		evil := &TwoWayEvil{
			State:     preMsg.Type,
			PreDigest: byteutils.Hex(preMsg.Data),
			Digest:    byteutils.Hex(msg.Data),
		}
		byteEvil, err := json.Marshal(evil)
		if err != nil {
			return err
		}

		address, err := core.NewAddressFromPublicKey(preMsg.Sign.Signer[:])
		if err != nil {
			return err
		}
		report := core.Report{
			Timestamp:  preMsg.Timestamp,
			Malefactor: address.String(),
			Evil:       byteutils.Hex(byteEvil),
		}
		bytes, err := report.ToBytes()
		if err != nil {
			return err
		}
		err = pbft.sendTransaction(core.TwoWayVote, bytes)
		logging.VLog().WithFields(logrus.Fields{
			"timestamp": preMsg.Timestamp,
			"height":    preMsg.SeqId,
			"miner":     pbft.consensus.Coinbase().String(),
			"curMsg":    msg,
			"preMsg":    preMsg,
			"error":     err,
		}).Info("Send report evil tx.")
		if err != nil {
			return err
		}
	}
	return nil
}

func (pbft *PBFT) reportDoubleMintEvil(preBlock, block *core.Block) error {
	// check mining enable
	if !pbft.consensus.IsEnable() || pbft.consensus.IsSuspend() {
		return nil
	}
	council, err := pbft.loadCouncil(preBlock.ParentHash())
	if err != nil {
		return err
	}
	if council.isWitness(pbft.consensus.Coinbase().String()) {
		if preBlock.Coinbase().Equals(block.Coinbase()) {
			evil := &DoubleMintEvil{
				PreHash: preBlock.Hash().String(),
				Hash:    block.Hash().String(),
			}
			byteEvil, err := json.Marshal(evil)
			if err != nil {
				return err
			}

			report := core.Report{
				Timestamp:  block.Timestamp(),
				Malefactor: preBlock.Coinbase().String(),
				Evil:       byteutils.Hex(byteEvil),
			}

			bytes, err := report.ToBytes()
			if err != nil {
				return err
			}
			err = pbft.sendTransaction(core.DoubleMint, bytes)
			logging.VLog().WithFields(logrus.Fields{
				"timestamp": block.Timestamp(),
				"termId":    block.TermId(),
				"miner":     pbft.consensus.Coinbase().String(),
				"curBlock":  block.Hash(),
				"preBlock":  preBlock.Hash(),
				"error":     err,
			}).Info("Send report evil tx.")
			if err != nil {
				return err
			}
		}
	} else {
		logging.VLog().WithFields(logrus.Fields{
			"timestamp": block.Timestamp(),
			"termId":    block.TermId(),
			"miner":     pbft.consensus.Coinbase().String(),
			"curBlock":  block.Hash(),
			"preBlock":  preBlock.Hash(),
		}).Info("Not the epoch council member for report evil.")
	}
	return nil
}

// sendTransaction send pod consensus transaction
func (pbft *PBFT) sendTransaction(reportType string, data []byte) error {
	handler := core.NewReportHandler(reportType, data)

	bytes, err := handler.ToBytes()
	if err != nil {
		return err
	}
	acc, err := pbft.chain.TailBlock().GetAccount(pbft.consensus.Coinbase().Bytes())
	if err != nil {
		return err
	}

	pool := pbft.chain.TxPool()
	nonce := acc.Nonce() + uint64(pool.GetTxsNumByAddr(acc.Address().String())) + 1
	tx, err := core.NewTransaction(pbft.chain.ChainId(), pbft.consensus.Coinbase(), pbft.consensus.Coinbase(), big.NewInt(0), nonce, 255, core.ReportTx, bytes, "", core.TransactionMaxGas, nil)
	if err != nil {
		return err
	}
	addrManager := pbft.consensus.(*Psec).am.(*account.AccountManager).GetAddrManager()
	err = addrManager.SignTx(pbft.consensus.Coinbase(), tx)
	if err != nil {
		return err
	}

	return pbft.chain.TxPool().AddAndBroadcast(tx)
}
