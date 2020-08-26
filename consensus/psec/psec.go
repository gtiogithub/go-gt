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
	"math/big"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/conf"
	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
)

// Psec
type Psec struct {
	coinbase *core.Address
	//voted    map[uint64]int64
	//termId        uint64
	db    cdb.Storage
	am    core.AccountManager
	ns    network.Service
	chain *core.BlockChain
	// pbft
	pbft *PBFT

	// mine flag
	enable  bool
	suspend bool

	// quit channel
	//quitStandby   chan bool
	//quitBlockLoop chan bool
}

//
func NewMockPsec(chain *core.BlockChain) *Psec {
	psec := &Psec{
		enable:  false,
		suspend: false,
		//voted:    make(map[uint64]int64),
	}
	psec.chain = chain
	psec.db = chain.Storage()
	return psec
}

//
func NewPsec(db cdb.Storage, cfg *config.Config, chain *core.BlockChain) *Psec {
	psec := &Psec{
		db:      db,
		enable:  false,
		suspend: false,
	}
	psec.chain = chain

	return psec
}

// Setup the psec
func (psec *Psec) Setup(gt core.Gt) error {
	var err error

	psec.chain = gt.BlockChain()
	psec.ns = gt.NetService()
	psec.am = gt.AccountManager()
	chainConfig := conf.GetChainConfig(gt.Config())
	if len(chainConfig.Coinbase) > 0 {
		if psec.coinbase, err = core.AddressParse(chainConfig.Coinbase); err != nil {
			return err
		}
	}

	psec.pbft, err = NewPbft(psec, psec.ns, psec.chain)
	if err != nil {
		return err
	}
	// register pbft message
	psec.pbft.ns.Register(network.NewSubscriber(psec.pbft, psec.pbft.messageCh, true, network.Pbft, network.MessageWeightPbft))

	return nil
}

// Stop mining and exit consensus
func (psec *Psec) Stop() {
	logging.CLog().Info("Stopping Psec Consensus...")
	if psec.pbft != nil {
		psec.pbft.Stop()
	}
	psec.DisableMining()
}

// IsEnable return wether the psec is enable
func (psec *Psec) IsEnable() bool { return psec.enable }

// return wether the psec is suspend
func (psec *Psec) IsSuspend() bool { return psec.suspend }

// return coinbase
func (psec *Psec) Coinbase() *core.Address { return psec.coinbase }

// set psec's enable
func (psec *Psec) EnableMining(passphrase string) error {
	if err := psec.unlock(passphrase); err != nil {
		return err
	}
	psec.enable = true
	logging.CLog().Info("Enabled psec Mining...")
	return nil
}

// set psec's disable
func (psec *Psec) DisableMining() error {
	psec.enable = false
	if err := psec.am.Lock(psec.coinbase); err != nil {
		return err
	}
	logging.CLog().Info("Disable psec Mining...")
	return nil
}

// set psec's suspend
func (psec *Psec) SuspendMining() { psec.suspend = true }

// set psec resume
func (psec *Psec) ResumeMining() { psec.suspend = false }

// update the chain's fixed block
func (psec *Psec) UpdateFixedBlock() {
	fixed := psec.chain.FixedBlock()
	tail := psec.chain.TailBlock()
	cur := tail

	miners := make(map[string]bool)
	round := uint64(0)
	for !cur.Hash().Equals(fixed.Hash()) {
		if cur.Height() <= 2 {
			return
		}

		config := cur.GetChainConfig()

		consensusSize := int(config.WitnessCount*2/3 + 1)
		curRound := (cur.Height() - 2) / uint64(config.WitnessCount)
		if (cur.Height()-2)%uint64(config.WitnessCount) > 0 {
			curRound++
		}
		if round != curRound {
			miners = make(map[string]bool)
			round = curRound
		}
		// fast prune
		if int(cur.Height())-int(fixed.Height()) < consensusSize-len(miners) {
			return
		}
		miners[cur.Coinbase().String()] = true
		if len(miners) >= consensusSize {
			if err := psec.chain.StoreFixedHashToStorage(cur); err != nil {
				logging.CLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("Failed to store fixed to storage.")
			}
			logging.CLog().WithFields(logrus.Fields{
				"fixed.new": cur,
				"fixed.old": fixed,
				"tail":      tail,
			}).Info("Succeed to update latest fixed block.")
			psec.chain.SetFixedBlock(cur)
			e := &state.Event{
				Topic: core.TopicFixedBlock,
				Data:  psec.chain.FixedBlock().String(),
			}
			psec.chain.EventEmitter().Trigger(e)
			return
		}
		tmp := cur
		cur = psec.chain.GetBlock(cur.ParentHash())
		if cur == nil || core.CheckGenesisBlock(psec.chain.GenesisBlock(), cur) {
			logging.VLog().WithFields(logrus.Fields{
				"tail": tail,
				"cur":  tmp,
			}).Debug("Failed to find latest irreversible block.")
			return
		}
	}
}

func (psec *Psec) generateRandomSeed(block *core.Block) error {

	ancestorHash, parentSeed, err := psec.chain.GetInputForVRFSigner(block.ParentHash(), block.Height())
	if err != nil {
		return err
	}

	// generate VRF hash,proof
	vrfSeed, vrfProof, err := psec.am.GenerateRandomSeed(psec.coinbase, ancestorHash, parentSeed)
	if err != nil {
		return err
	}
	block.SetRandomSeed(vrfSeed, vrfProof)

	return nil
}

// start psec service
func (psec *Psec) Start() {
	logging.CLog().Info("Starting Psec Consensus...")
	go psec.pbft.Run()
}

// handle fork
func (psec *Psec) HandleFork() error {
	chain := psec.chain
	tail := chain.TailBlock()
	detachedTails := chain.DetachedTailBlocks()
	newTail := tail

	for _, v := range detachedTails {
		if less(newTail, v) {
			newTail = v
		}
	}

	if newTail.Hash().Equals(tail.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"old tail": tail,
			"new tail": newTail,
		}).Info("Current tail is best, no need to change.")
		return nil
	}

	err := chain.SetTailBlock(newTail)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"new tail": newTail,
			"old tail": tail,
			"err":      err,
		}).Error("Failed to set new tail block.")
		return err
	}

	logging.VLog().WithFields(logrus.Fields{
		"new tail": newTail,
		"old tail": tail,
	}).Info("change to new tail.")

	return nil
}

// new block
func (psec *Psec) NewBlock(tail *core.Block, deadline int64, mineTime int64) (*core.Block, error) {
	return psec.newBlock(tail, psec.coinbase, deadline, mineTime)
}

// build a new block
func (psec *Psec) newBlock(tail *core.Block, coinbase *core.Address, deadline int64, mineTime int64) (*core.Block, error) {
	block, err := core.NewBlock(psec.chain.ChainId(), coinbase, tail, mineTime)
	if err != nil {
		return nil, err
	}

	//miner reward
	if err := block.IssueBonus(tail); err != nil {
		return nil, err
	}

	council, err := tail.WorldState().GetCouncil(tail.TermId())
	if err != nil {
		return nil, err
	}
	if tail.Height() == council.Meta.TenureEndHeight {
		block.SetTermId(tail.TermId() + 1)
	} else {
		block.SetTermId(tail.TermId())
	}

	// pack transactions
	block.PackTransactions(deadline, tail)

	err = psec.generateRandomSeed(block)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("Failed to generate random seed.")
		return nil, err
	}
	info, err := json.Marshal(block.GetStatistics())
	if err != nil {
		return nil, err
	}
	conState, events, err := block.WorldState().NextConsensusState(info)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block.height": block.Height(),
			"err":          err,
		}).Error("get next consensus state failed")
		return nil, err
	}
	block.WorldState().SetConsensusState(conState)

	if events != nil && len(events) > 0 {
		for _, event := range events {
			amount, _ := core.CUintStringToNcUintBigInt(event.PledgeFund)
			block.AddPledgeFund(event.Address, amount, big.NewInt(0), new(big.Int).Neg(amount))
		}
	}

	if err = block.Seal(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("Failed to seal new block")
		go block.PutBackTxs()
		return nil, err
	}

	if err := psec.am.SignBlock(psec.coinbase, block); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"miner": psec.coinbase,
			"err":   err,
		}).Error("Failed to sign new block.")
		go block.PutBackTxs()
		return nil, err
	}

	logging.CLog().Info("-----⚒️mined new block----- ", " Height:", block.Height(), " timestamp:", deadline, " Proposer:", psec.coinbase.String())

	return block, nil
}

// CheckDoubleMint if double mint exists
func (psec *Psec) CheckDoubleMint(block *core.Block) bool {
	if preBlock, exist := psec.pbft.slot.Get(block.Timestamp()); exist {
		if preBlock.(*core.Block).Hash().Equals(block.Hash()) == false {

			logging.VLog().WithFields(logrus.Fields{
				"curBlock": block,
				"preBlock": preBlock.(*core.Block),
			}).Warn("Found someone minted multiple blocks at same time.")
			go psec.pbft.reportDoubleMintEvil(preBlock.(*core.Block), block)
			return true
		}
	}
	return false
}

// verify the block
func (psec *Psec) VerifyBlock(parentBlock *core.Block, block *core.Block) error {
	periodRoot := &PeriodRoot{}
	if parentBlock.ConsensusRoot().PeriodRoot != nil && len(parentBlock.ConsensusRoot().PeriodRoot) > 0 {
		if err := json.Unmarshal(parentBlock.ConsensusRoot().PeriodRoot, periodRoot); err != nil {
			return err
		}
	}
	councilTrie, err := trie.NewTrie(periodRoot.CouncilRoot, psec.db, false)
	if err != nil {
		return err
	}

	termId := parentBlock.TermId()
	pbCouncil, err := parentBlock.WorldState().GetCouncil(parentBlock.TermId())
	if pbCouncil.Meta.TenureEndHeight == parentBlock.Height() {
		termId++
	}
	byteCouncil, err := councilTrie.Get(byteutils.FromUint64(termId))
	if err != nil && err != cdb.ErrKeyNotFound {
		return err
	}
	council, _ := NewCouncil(psec.chain, core.GenesisTimestamp, false)
	if byteCouncil != nil {
		if err := council.FromBytes(byteCouncil, psec.db, false); err != nil {
			return err
		}
	}

	miners := make(map[string]bool)
	if council.council.Panels != nil && len(council.council.Panels) > 0 {
		timeDiff := block.Timestamp() - council.council.Meta.Timestamp
		multiple := timeDiff / int64(council.council.Meta.Config.BlockInterval)
		offset := multiple % int64(council.council.Meta.Config.WitnessCount)
		panel := council.council.Panels[offset]
		miners[panel.Leader.Address] = true
	}

	if _, ok := miners[block.Coinbase().String()]; !ok {
		return ErrInvalidBlockProposer
	}
	if err := block.VerifySign(); err != nil {
		return err
	}

	psec.pbft.slot.Add(block.Timestamp(), block)
	return nil
}

// sort block
func less(a *core.Block, b *core.Block) bool {
	if a.Height() != b.Height() {
		return a.Height() < b.Height()
	}
	//the same height selection time is small
	return a.Timestamp() > b.Timestamp()
}

func (psec *Psec) GenesisConsensusState(chain *core.BlockChain, sysConfig *corepb.SystemConfig, genesisCouncil *corepb.GenesisCouncil) (state.ConsensusState, error) {
	councilTrie, err := trie.NewTrie(nil, chain.Storage(), false)
	if err != nil {
		return nil, err
	}

	council, err := NewCouncil(psec.chain, core.GenesisTimestamp, false)
	if err != nil {
		return nil, err
	}
	council.council.Meta.Config = sysConfig

	tenure := sysConfig.WitnessCount * sysConfig.WitnessCount * sysConfig.FloatingCycle
	council.council.Meta.TenureStartHeight = 1
	council.council.Meta.TenureEndHeight = uint64(tenure)

	voteTrie, err := trie.NewTrie(nil, chain.Storage(), false)
	if err != nil {
		return nil, err
	}

	overdueTrie, err := trie.NewTrie(nil, chain.Storage(), false)
	if err != nil {
		return nil, err
	}

	forbidVoteTrie, err := trie.NewTrie(nil, chain.Storage(), false)
	if err != nil {
		return nil, err
	}

	cycleCount := uint64(council.council.Meta.Config.WitnessCount * council.council.Meta.Config.WitnessCount * council.council.Meta.Config.FloatingCycle)
	joinHeight := uint64(1)
	expiryHeight := joinHeight + cycleCount*2
	relieveHeight := expiryHeight + cycleCount*1

	for _, member := range genesisCouncil.Members {
		panel := &corepb.Panel{}
		panel.Leader = &corepb.Member{
			PeerId:     member.PeerId,
			Address:    member.Address,
			PledgeFund: member.PledgeFund[:],
		}
		council.council.Panels = append(council.council.Panels, panel)

		pledgeFund := new(big.Int).SetBytes(member.PledgeFund)
		campaignInfo := &CampaignInfo{
			PeerId:        member.PeerId,
			Address:       member.Address,
			PledgeFund:    core.NcUnitToCUnitString(pledgeFund),
			JoinHeight:    joinHeight,
			ExpiryHeight:  expiryHeight,
			RelieveHeight: relieveHeight,
			ElectStatus:   0,
			TxHashes:      make([]string, 0),
		}
		bytesElection, err := json.Marshal(campaignInfo)
		if err != nil {
			return nil, err
		}
		_, err = voteTrie.Put([]byte(campaignInfo.Address), bytesElection)
		if err != nil {
			return nil, err
		}

		//process forbid vote
		_, err = forbidVoteTrie.Put([]byte(campaignInfo.Address), byteutils.FromUint64(campaignInfo.RelieveHeight))
		if err != nil {
			return nil, err
		}

		//process
		overdueBytes, err := overdueTrie.Get(byteutils.FromUint64(campaignInfo.ExpiryHeight))
		if err != nil && err != cdb.ErrKeyNotFound {
			return nil, err
		}

		overdueAddresses := make([]string, 0)
		if overdueBytes != nil {
			if err := json.Unmarshal(overdueBytes, &overdueAddresses); err != nil {
				return nil, err
			}
		}
		overdueAddresses = append(overdueAddresses, campaignInfo.Address)
		sort.Strings(overdueAddresses)
		logging.CLog().WithFields(logrus.Fields{
			"overdueAddresses": overdueAddresses,
		}).Info("all addresses")
		newAddressesBytes, err := json.Marshal(overdueAddresses)
		if err != nil {
			return nil, err
		}
		_, err = overdueTrie.Put(byteutils.FromUint64(campaignInfo.ExpiryHeight), newAddressesBytes)
		if err != nil {
			return nil, err
		}
	}

	byteCouncil, err := council.ToBytes()
	if err != nil {
		return nil, err
	}
	councilTrie.Put(byteutils.FromUint64(1), byteCouncil)

	eventTrie, err := trie.NewTrie(nil, chain.Storage(), false)
	if err != nil {
		return nil, err
	}
	reportTrie, err := trie.NewTrie(nil, chain.Storage(), false)
	if err != nil {
		return nil, err
	}
	cState := &State{
		termId:         1,
		councilTrie:    councilTrie,
		eventTrie:      eventTrie,
		reportTrie:     reportTrie,
		voteTrie:       voteTrie,
		overdueTrie:    overdueTrie,
		forbidVoteTrie: forbidVoteTrie,
		chain:          psec.chain,
		council:        council,
		consensus:      psec,
	}

	return cState, nil
}

func (psec *Psec) unlock(passphrase string) error {
	return psec.am.UnLock(psec.coinbase, []byte(passphrase), time.Duration(MaxMiningDuration*int64(time.Second)))
}
