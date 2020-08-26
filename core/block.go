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
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"sync"
	"time"

	"gt.pro/gtio/go-gt/crypto"

	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	consensuspb "gt.pro/gtio/go-gt/consensus/pb"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/crypto/keystore"
	"gt.pro/gtio/go-gt/dag"
	dagpb "gt.pro/gtio/go-gt/dag/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
)

const (
	MiningScale    = int64(10000)
	WitnessScale   = int64(0)
	CandidateScale = int64(0)
	BlockReward    = int64(23000000000)
	ReduceCycle    = uint64(6307200)
	ReduceScale    = int64(50)
)

var (
	// parallel number
	PackedParallelNum = 4
	// verify thread parallel num
	VerifyParallelNum = 4
	// VerifyExecutionTimeout 0 means unlimited
	VerifyExecutionTimeout = 0
)

// Block
type Block struct {
	header       *BlockHeader
	transactions []*Transaction
	dependency   *dag.Dag

	sealed       bool
	txPool       *TxPool
	blkPool      *BlockPool
	cvm          CVM
	worldState   state.WorldState
	db           cdb.Storage
	eventEmitter *EventEmitter
	statistics   *state.ChangeStateInfo
	txExeStatus  *sync.Map
}

func (block *Block) UpdateBlockTxStatistics(tx *Transaction) {
	block.statistics.Participators[tx.from.String()] = tx.from.String()
	if tx.IsContractTransaction() {
		block.statistics.ContractTxCnt++
	} else if tx.IsTransferTransaction() {
		block.statistics.NormalTxCnt++
	}
}

func (block *Block) GetStatistics() *state.ChangeStateInfo {
	return block.statistics
}

func (block *Block) UpdateAccountTxStatistics(tx *Transaction) {
	ws := block.WorldState()
	fromAcc, _ := ws.GetOrCreateAccount(tx.from.address)
	if tx.IsContractTransaction() {
		fromAcc.IncreaseIntegral(block.TermId(), state.Contract)
		if tx.Type() == ContractDeployTx {
			contractAddr, _ := tx.GenerateContractAddress()
			contractAcc, _ := ws.GetOrCreateAccount(contractAddr.address)
			contractAcc.IncreaseContractIntegral(contractAddr.String(), block.Height())
			fromAcc.IncreaseContractIntegral(contractAddr.String(), block.Height())
		} else if tx.Type() == ContractInvokeTx || tx.Type() == ContractChangeStateTx {
			contractAcc, _ := ws.GetOrCreateAccount(tx.to.address)
			contractAcc.IncreaseContractIntegral(tx.to.String(), 0)
		}
	} else if tx.IsTransferTransaction() {
		fromAcc.IncreaseIntegral(block.TermId(), state.Normal)
	}
}

// NewBlock
func NewBlock(chainID uint32, coinbase *Address, parent *Block, mineTime int64) (*Block, error) {
	ws, err := parent.worldState.Copy()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Debug("copy parent's world state error")
		return nil, err
	}

	block := &Block{
		header: &BlockHeader{
			chainId:    chainID,
			coinbase:   coinbase,
			parentHash: parent.Hash(),
			height:     parent.Height() + 1,
			timestamp:  mineTime,
			memo: &BlockMemo{
				rewards: make([]*corepb.BlockFundEntity, 0),
				pledge:  make([]*corepb.BlockFundEntity, 0),
			},
			random: &corepb.Random{},
		},

		sealed:       false,
		transactions: make([]*Transaction, 0),
		dependency:   dag.NewDag(),

		txPool:       parent.txPool,
		blkPool:      parent.blkPool,
		eventEmitter: parent.eventEmitter,
		cvm:          parent.cvm,
		db:           parent.db,
		worldState:   ws,
		statistics: &state.ChangeStateInfo{
			Height:        parent.Height() + 1,
			Miner:         coinbase.String(),
			Timestamp:     mineTime,
			NormalTxCnt:   0,
			ContractTxCnt: 0,
			Participators: make(map[string]string),
		},
		txExeStatus: new(sync.Map),
	}

	if err := block.Begin(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Debug("new block's world state begins error")
		return nil, err
	}

	return block, nil
}

// CalcHash
func (block *Block) CalcHash() error {
	h, err := block.calcHash()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Calc block hash error")
		return err
	}
	block.header.hash = h
	return nil
}

// return block header
func (block *Block) Header() *BlockHeader {
	return block.header
}

func (block *Block) SetTxPool(tail *Block) {
	block.txPool = tail.txPool
}

// return block hash
func (block *Block) Hash() byteutils.Hash {
	return block.header.hash
}

// return memo
func (block *Block) Memo() *BlockMemo {
	return block.header.memo
}

// return timestamp
func (block *Block) Timestamp() int64 {
	return block.header.Timestamp()
}

// return height
func (block *Block) Height() uint64 {
	return block.header.Height()
}

// return sealed flag
func (block *Block) Sealed() bool {
	return block.sealed
}

// return term id
func (block *Block) TermId() uint64 {
	return block.header.termId
}

// set term id
func (block *Block) SetTermId(id uint64) {
	block.header.termId = id
}

// set height
func (block *Block) SetHeight(height uint64) {
	block.header.height = height
}

// set parent hash
func (block *Block) SetParent(hash byteutils.Hash) {
	block.header.parentHash = hash
}

// return chain id
func (block *Block) ChainId() uint32 {
	return block.header.chainId
}

// set world state
func (block *Block) SetWorldState(parent *Block) {
	ws, err := parent.WorldState().Copy()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to set world state.")
		return
	}

	block.worldState = ws
}

// put back txs
func (block *Block) PutBackTxs() {
	for _, tx := range block.transactions {
		_ = block.txPool.Add(tx)
	}
}

// put back transactions when error
func (block *Block) putBackTxsWhenPackError(txs []*Transaction) {
	for _, tx := range txs {
		_ = block.txPool.Add(tx)
	}
}

func (block *Block) CheckStandByCollectBlock(nodes []*corepb.Node) bool {
	for _, val := range nodes {
		if val.Address == block.Coinbase().String() {
			return true
		}
	}
	return false
}

// pack transactions
func (block *Block) PackTransactions(deadline int64, parent *Block) {
	logging.CLog().Debug("Start packing transactions....")
	if block.sealed {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
		}).Fatal("Sealed block can't be changed.")
	}
	dag := dag.NewDag()
	txs := make([]*Transaction, 0)
	fromAccList := new(sync.Map)
	toAccList := new(sync.Map)

	elapse := deadline - time.Now().Unix()
	logging.VLog().WithFields(logrus.Fields{
		"elapse": elapse,
	}).Debug("Time to pack transfer transactions")

	if elapse <= 0 {
		logging.CLog().Warn("pack transactions elapse less than 0")
		return
	}

	pool := block.txPool
	timer := time.NewTimer(time.Duration(elapse) * time.Second)
	over := false

	// parallelCh is used as access tokens here
	parallelCh := make(chan bool, PackedParallelNum)

	// mergeCh is used as lock here
	mergeCh := make(chan bool, 1)

	//var txws state.TxWorldState
	//var err error
	config := parent.GetChainConfig()
	// collect txs in tx pool
	go func() {
		for {
			mergeCh <- true // lock
			if over {
				<-mergeCh // unlock
				return
			}
			tx := pool.takeTransaction(fromAccList, toAccList)
			if tx == nil {
				<-mergeCh // unlock
				continue
			}

			fromAccList.Store(tx.from.address.Hex(), true)
			fromAccList.Store(tx.to.address.Hex(), true)
			toAccList.Store(tx.from.address.Hex(), true)
			toAccList.Store(tx.to.address.Hex(), true)
			<-mergeCh // lock

			parallelCh <- true
			go func() {
				defer func() {
					<-parallelCh // release access token
				}()

				// 1. prepare execution environment
				mergeCh <- true // lock
				if over {
					<-mergeCh // unlock
					if err := pool.Add(tx); err != nil {
						logging.VLog().WithFields(logrus.Fields{
							"block": block,
							"tx":    tx,
							"err":   err,
						}).Error("[over] Failed to giveback the tx.")
					}
					return
				}

				txws, err := block.WorldState().Prepare(tx.Hash().String())
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"block": block,
						"tx":    tx,
						"err":   err,
					}).Error("Prepare transfer transaction error")

					if err := pool.Add(tx); err != nil {
						logging.VLog().WithFields(logrus.Fields{
							"block": block,
							"tx":    tx,
							"err":   err,
						}).Error("[Prepare] Failed to giveback the tx.")
					}

					fromAccList.Delete(tx.from.address.Hex())
					fromAccList.Delete(tx.to.address.Hex())
					toAccList.Delete(tx.from.address.Hex())
					toAccList.Delete(tx.to.address.Hex())
					<-mergeCh // unlock
					return
				}
				<-mergeCh // unlock

				defer func() {
					if err := txws.Close(); err != nil {
						logging.VLog().WithFields(logrus.Fields{
							"block": block,
							"tx":    tx,
							"err":   err,
						}).Error("[defer] Failed to close tx.")
					}
				}()

				// 2. execute transaction
				if giveback, err := block.ExecuteTransaction(tx, txws, config); err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"block":    block,
						"tx":       tx,
						"err":      err,
						"giveback": giveback,
					}).Error("Execute transaction error")

					if giveback {
						if err := pool.Add(tx); err != nil {
							logging.VLog().WithFields(logrus.Fields{
								"block": block,
								"tx":    tx,
								"err":   err,
							}).Error("[ExecuteTransaction] Failed to giveback the tx.")
						}
					}

					if err == ErrLargeTransactionNonce {
						if !byteutils.Equal(tx.to.address, tx.from.address) {
							fromAccList.Delete(tx.to.address.Hex())
						}
						toAccList.Delete(tx.to.address.Hex())
						toAccList.Delete(tx.from.address.Hex())
					} else {
						fromAccList.Delete(tx.from.address.Hex())
						fromAccList.Delete(tx.to.address.Hex())
						toAccList.Delete(tx.from.address.Hex())
						toAccList.Delete(tx.to.address.Hex())
					}
					return
				}

				// 3. check and update transaction
				mergeCh <- true // lock
				if over {
					<-mergeCh // unlock
					if err := pool.Add(tx); err != nil {
						logging.VLog().WithFields(logrus.Fields{
							"block": block,
							"tx":    tx,
							"err":   err,
						}).Error("[over] Failed to giveback the tx.")
					}
					return
				}

				dependency, err := txws.CheckAndUpdate()
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"block":      block,
						"tx":         tx,
						"err":        err,
						"dependency": dependency,
					}).Error("CheckAndUpdate invalid transfer transaction")

					if err := pool.Add(tx); err != nil {
						logging.VLog().WithFields(logrus.Fields{
							"block": block,
							"tx":    tx,
							"err":   err,
						}).Error("[CheckAndUpdate] Failed to giveback the tx.")
					}

					fromAccList.Delete(tx.from.address.Hex())
					fromAccList.Delete(tx.to.address.Hex())
					toAccList.Delete(tx.from.address.Hex())
					toAccList.Delete(tx.to.address.Hex())
					<-mergeCh // unlock
					return
				}

				// 4. record statistics info
				block.UpdateBlockTxStatistics(tx)
				//block.UpdateAccountTxStatistics(tx)

				logging.VLog().WithFields(logrus.Fields{
					"tx": tx,
				}).Debug("packed tx.")

				txs = append(txs, tx)

				txid := tx.Hash().String()
				dag.AddNode(txid)

				for _, node := range dependency {
					dag.AddEdge(node, txid)
				}
				fromAccList.Delete(tx.from.address.Hex())
				fromAccList.Delete(tx.to.address.Hex())
				toAccList.Delete(tx.from.address.Hex())
				toAccList.Delete(tx.to.address.Hex())

				<-mergeCh // unlock
				return
			}()

			if over {
				return
			}
		}
	}()

	<-timer.C
	mergeCh <- true // lock
	over = true
	block.transactions = txs
	block.dependency = dag
	<-mergeCh //lock

	logging.VLog().WithFields(logrus.Fields{
		"txs_amount": len(txs),
	}).Info("Finished to pack transfer transactions")

}

func (block *Block) recordTxExeStatus(txHash byteutils.Hash, status int8) {

	if block.txExeStatus == nil {
		block.txExeStatus = new(sync.Map)
	}
	//logging.CLog().WithFields(logrus.Fields{
	//	"tx.hash":   txHash.String(),
	//	"tx.status": status,
	//}).Debug("tx execute status ")
	block.txExeStatus.Store(txHash.String(), status)
}

// seal a block
func (block *Block) Seal() error {
	if block.sealed {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
		}).Debug("Cannot seal a block twice")
		return errors.New("cannot seal a block twice")
	}

	defer block.RollBack()
	if err := block.WorldState().Flush(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Debug("Flush block's world state error when seal")
		return err
	}

	block.CalcBlockReward()

	block.header.stateRoot = block.WorldState().AccountsRoot()
	block.header.txsRoot = block.WorldState().TxsRoot()
	block.header.eventsRoot = block.WorldState().EventsRoot()
	block.header.consensusRoot, _ = proto.Marshal(block.WorldState().ConsensusRoot())
	log.Printf("pack new block :%s", byteutils.Hex(block.header.consensusRoot))
	hash, err := block.calcHash()
	if err != nil {
		return err
	}

	block.header.hash = hash
	block.sealed = true

	logging.VLog().WithFields(logrus.Fields{
		"block": block,
	}).Info("Sealed Block")

	return nil
}

// return contract account by address
func (block *Block) CheckContract(addr *Address) (state.Account, error) {
	ws, err := block.worldState.Copy()
	if err != nil {
		return nil, err
	}

	return GetContract(addr, ws)
}

// return tx by tx hash
func (block *Block) GetTransaction(txHash byteutils.Hash) (*Transaction, error) {
	ws, err := block.worldState.Copy()
	if err != nil {
		return nil, err
	}

	return GetTransaction(txHash, ws)
}

// LoadBlockFromStorage return a block from storage
func LoadBlockFromStorage(hash byteutils.Hash, chain *BlockChain) (*Block, error) {
	if chain == nil {
		return nil, ErrNilArgument
	}

	value, err := chain.db.Get(hash)
	if err != nil {
		return nil, err
	}
	pbBlock := new(corepb.Block)
	block := new(Block)
	if err = proto.Unmarshal(value, pbBlock); err != nil {
		return nil, err
	}
	if err = block.FromProto(pbBlock); err != nil {
		return nil, err
	}

	block.worldState, err = state.NewWorldState(chain.consensus, chain.db)
	if err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadAccountsRoot(block.StateRoot()); err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadTxsRoot(block.TxsRoot()); err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadEventsRoot(block.EventsRoot()); err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadConsensusRoot(block.ConsensusRoot()); err != nil {
		return nil, err
	}

	block.sealed = true
	block.db = chain.db
	block.txPool = chain.txPool
	block.blkPool = chain.bkPool
	block.eventEmitter = chain.eventEmitter
	block.cvm = chain.cvm
	return block, nil
}

// ToProto converts domain Block into proto Block
func (block *Block) ToProto() (proto.Message, error) {
	header, err := block.header.ToProto()
	if err != nil {
		return nil, err
	}
	if header, ok := header.(*corepb.BlockHeader); ok {
		txs := make([]*corepb.Transaction, len(block.transactions))
		for idx, v := range block.transactions {
			tx, err := v.ToProto()
			if err != nil {
				return nil, err
			}
			if tx, ok := tx.(*corepb.Transaction); ok {
				txs[idx] = tx
			} else {
				return nil, ErrInvalidProtoToTransaction
			}
		}
		dependency, err := block.dependency.ToProto()
		if err != nil {
			return nil, err
		}
		if dependency, ok := dependency.(*dagpb.Dag); ok {
			return &corepb.Block{
				Hash:       block.Hash(),
				Header:     header,
				Body:       txs,
				Dependency: dependency,
			}, nil
		}
		return nil, dag.ErrInvalidProtoToDag
	}
	return nil, ErrInvalidProtoToBlock
}

// HashPbBlock return the hash of pb block.
func HashPbBlock(pbBlock *corepb.Block) (byteutils.Hash, error) {
	block := new(Block)
	if err := block.FromProto(pbBlock); err != nil {
		return nil, err
	}
	return block.calcHash()
}

// CalcHash calculate the hash of block.
func (block *Block) calcHash() (byteutils.Hash, error) {
	hasher := sha3.New256()
	hasher.Write(block.ParentHash())
	hasher.Write(block.Coinbase().Bytes())
	hasher.Write(byteutils.FromUint32(block.header.chainId))
	hasher.Write(byteutils.FromInt64(block.header.timestamp))
	hasher.Write(byteutils.FromUint64(block.header.termId))
	hasher.Write(block.header.output.Bytes())
	hasher.Write(block.StateRoot())
	hasher.Write(block.TxsRoot())
	hasher.Write(block.EventsRoot())
	consensusRoot, err := proto.Marshal(block.ConsensusRoot())
	if err != nil {
		return nil, err
	}
	hasher.Write(consensusRoot)
	pbDep, err := block.dependency.ToProto()
	if err != nil {
		return nil, err
	}
	dependency, err := proto.Marshal(pbDep)
	if err != nil {
		return nil, err
	}
	hasher.Write(dependency)

	memo := block.Memo()
	if memo != nil {
		if memo.rewards != nil && len(memo.rewards) > 0 && memo.rewards[0] != nil {
			for _, entity := range memo.rewards {
				hasher.Write(entity.Address)
				hasher.Write(entity.Balance)
				hasher.Write(entity.FrozenFund)
				hasher.Write(entity.PledgeFund)
			}
		}
		if memo.pledge != nil && len(memo.pledge) > 0 && memo.pledge[0] != nil {
			for _, entity := range memo.pledge {
				hasher.Write(entity.Address)
				hasher.Write(entity.Balance)
				hasher.Write(entity.FrozenFund)
				hasher.Write(entity.PledgeFund)
			}
		}

	}

	for _, tx := range block.transactions {
		hasher.Write(tx.Hash())
	}
	randomBytes, err := proto.Marshal(block.header.random)
	if err != nil {
		return nil, err
	}
	hasher.Write(randomBytes)

	return hasher.Sum(nil), nil
}

// FromProto converts proto Block to domain Block
func (block *Block) FromProto(msg proto.Message) error {
	if msg, ok := msg.(*corepb.Block); ok {
		if msg != nil {
			block.header = new(BlockHeader)
			if err := block.header.FromProto(msg.Header); err != nil {
				return err
			}
			block.transactions = make(Transactions, len(msg.Body))
			for idx, v := range msg.Body {
				if v != nil {
					tx := new(Transaction)
					if err := tx.FromProto(v); err != nil {
						return err
					}
					block.transactions[idx] = tx
				} else {
					return ErrInvalidProtoToTransaction
				}
			}
			block.dependency = dag.NewDag()
			if err := block.dependency.FromProto(msg.Dependency); err != nil {
				return err
			}
			block.statistics = &state.ChangeStateInfo{
				Height:        block.header.height,
				Timestamp:     block.header.timestamp,
				Miner:         block.header.coinbase.String(),
				NormalTxCnt:   0,
				ContractTxCnt: 0,
				Participators: make(map[string]string),
			}

			block.txExeStatus = new(sync.Map)
			return nil
		}
		return ErrInvalidProtoToBlock
	}
	return ErrInvalidProtoToBlock
}

// VerifyIntegrity verify block's hash, txs' integrity and consensus acceptable.
func (block *Block) VerifyIntegrity(chainId uint32, consensus Consensus) error {
	if consensus == nil {
		return ErrNilArgument
	}

	// check ChainID.
	if block.header.chainId != chainId {
		logging.VLog().WithFields(logrus.Fields{
			"expect": chainId,
			"actual": block.header.chainId,
		}).Error("Failed to check chain id")
		//metricsInvalidBlock.Inc(1)
		return ErrInvalidBlockHeaderChainID
	}

	// verify transactions integrity.
	for _, tx := range block.transactions {
		if err := tx.VerifyIntegrity(block.header.chainId); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"tx":  tx,
				"err": err,
			}).Error("Failed to verify tx's integrity")
			return err
		}
	}

	// verify block hash.
	wantedHash, err := block.calcHash()
	if err != nil {
		return err
	}
	if !wantedHash.Equals(block.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": wantedHash,
			"actual": block.Hash(),
			"err":    err,
		}).Info("Failed to check block's hash")
		return ErrInvalidBlockHash
	}

	if err := block.VerifySign(); err != nil {
		return nil
	}

	return nil
}

// LinkParentBlock link parent block, return true if hash is the same; false otherwise.
func (block *Block) LinkParentBlock(chain *BlockChain, parentBlock *Block) error {
	if !block.ParentHash().Equals(parentBlock.Hash()) {
		return ErrLinkToWrongParentBlock
	}

	if err := chain.consensus.VerifyBlock(parentBlock, block); err != nil {
		return err
	}

	var err error
	if block.worldState, err = parentBlock.WorldState().Copy(); err != nil {
		return ErrCloneAccountState
	}

	block.db = parentBlock.db
	block.txPool = parentBlock.txPool
	block.blkPool = parentBlock.blkPool
	block.cvm = parentBlock.cvm
	block.eventEmitter = parentBlock.eventEmitter
	block.header.height = parentBlock.header.height + 1

	return nil
}

// ExecuteTx
func (block *Block) ExecuteTransaction(tx *Transaction, ws WorldState, chainConfig *ChainConfig) (bool, error) {
	var giveback bool
	var err error

	if giveback, err = CheckTransaction(tx, ws); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx,
			"err": err,
		}).Info("Failed to check transaction")
		return giveback, err
	}

	if giveback, err := VerifyExecution(tx, block, ws, chainConfig); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx,
			"err": err,
		}).Info("Failed to verify transaction execution")
		return giveback, err
	}

	if giveback, err := AcceptTransaction(tx, block, ws); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx,
			"err": err,
		}).Info("Failed to accept transaction")
		return giveback, err
	}
	return false, nil
}

// VerifyExecution execute the block and verify the execution result.
func (block *Block) VerifyExecution(parent *Block) error {
	if err := block.Begin(); err != nil {
		return err
	}
	if err := block.execute(parent); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("execute block error")
		block.RollBack()
		return err
	}

	hashes, err := block.calcHash()
	if !block.Hash().Equals(hashes) {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("verify hash error")
		return ErrInvalidBlockHash
	}

	if err := block.verifyState(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("verify block's state error")
		block.RollBack()
		return err
	}

	block.Commit()

	logging.VLog().WithFields(logrus.Fields{
		"block": block,
		"txs":   len(block.Transactions()),
	}).Info("Verify txs succeed")
	return nil
}

func (block *Block) verifyBlockCouncil(parent *Block) error {
	info, err := json.Marshal(block.statistics)
	if err != nil {
		return err
	}
	conState, events, err := block.worldState.NextConsensusState(info)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block.height": block.Height(),
			"err":          err,
		}).Error("get next consensus state failed")
		return err
	}
	block.worldState.SetConsensusState(conState)

	if events != nil && len(events) > 0 {
		for _, event := range events {
			amount, _ := CUintStringToNcUintBigInt(event.PledgeFund)
			block.addPledgeFund(event.Address, amount, big.NewInt(0), new(big.Int).Neg(amount))
		}
	}
	return nil
}

func (block *Block) AddRewardFund(address string, balance *big.Int, frozenFund *big.Int, pledgeFund *big.Int) {
	block.addRewardFund(address, balance, frozenFund, pledgeFund)
}

func (block *Block) addRewardFund(address string, balance *big.Int, frozenFund *big.Int, pledgeFund *big.Int) {
	memo := block.Memo()
	if memo == nil {
		memo = new(BlockMemo)
	}
	if memo.rewards == nil {
		memo.rewards = make([]*corepb.BlockFundEntity, 0)
	}
	memo.rewards = append(memo.rewards, &corepb.BlockFundEntity{
		Address:    []byte(address),
		Balance:    byteutils.FromBigInt(balance),
		FrozenFund: byteutils.FromBigInt(frozenFund),
		PledgeFund: byteutils.FromBigInt(pledgeFund),
	})
	block.header.memo = memo
}

func (block *Block) AddPledgeFund(address string, balance *big.Int, frozenFund *big.Int, pledgeFund *big.Int) {
	block.addPledgeFund(address, balance, frozenFund, pledgeFund)
}

func (block *Block) addPledgeFund(address string, balance *big.Int, frozenFund *big.Int, pledgeFund *big.Int) {
	memo := block.Memo()
	if memo == nil {
		memo = new(BlockMemo)
	}
	if memo.pledge == nil {
		memo.pledge = make([]*corepb.BlockFundEntity, 0)
	}
	memo.pledge = append(memo.pledge, &corepb.BlockFundEntity{
		Address:    []byte(address),
		Balance:    byteutils.FromBigInt(balance),
		FrozenFund: byteutils.FromBigInt(frozenFund),
		PledgeFund: byteutils.FromBigInt(pledgeFund),
	})
	block.header.memo = memo
}

func (block *Block) IssueBonus(parent *Block) error {
	if block.Height() <= 2 {
		return nil
	}

	ws := block.WorldState()
	council, _ := parent.worldState.GetCouncil(parent.TermId())
	panels := council.Panels
	if council.Panels == nil {
		logging.VLog().WithFields(logrus.Fields{
			"parent.height": parent.Height(),
			"parent.hash":   parent.Hash().String(),
		}).Error("Error get panels for parent block")
		return errors.New("Error get panels for parent block")
	}

	//Exclusion of miner
	output := parent.header.output
	minerReward := new(big.Int).Div(new(big.Int).Mul(output, big.NewInt(MiningScale)), big.NewInt(10000))
	witnessReward := new(big.Int).Div(new(big.Int).Mul(output, big.NewInt(WitnessScale)), big.NewInt(10000))
	candidateReward := new(big.Int).Div(new(big.Int).Mul(output, big.NewInt(CandidateScale)), big.NewInt(10000))
	// reward for witnesses and candidates
	for _, panel := range panels {
		addr, err := AddressParse(panel.Leader.Address)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("New witness address error")
			return err
		}

		acc, err := ws.GetOrCreateAccount(addr.Bytes())
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("Get witness account error")
			return err
		}

		//Exclusion of miner
		if addr.Equals(parent.Coinbase()) {
			err = acc.AddBalance(minerReward)
			if err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("add proposer reward err")
				return err
			}
			block.addRewardFund(addr.String(), minerReward, big.NewInt(0), big.NewInt(0))
		} else {
			err = acc.AddBalance(witnessReward)
			if err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("add witness reward err")
				return err
			}
			block.addRewardFund(addr.String(), witnessReward, big.NewInt(0), big.NewInt(0))
		}

		if panel.Members != nil && len(panel.Members) > 0 {
			for _, candidate := range panel.Members {
				addrCandidate, err := AddressParse(candidate.Address)
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("New candidate address error")
					return err
				}
				accCandidate, err := ws.GetOrCreateAccount(addrCandidate.Bytes())
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("Get candidate account error")
					return err
				}

				err = accCandidate.AddBalance(candidateReward)
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("add candidate reward err")
					return err
				}

				block.addRewardFund(addrCandidate.String(), candidateReward, big.NewInt(0), big.NewInt(0))
			}
		}
	}
	return nil
}

type verifyCtx struct {
	mergeCh     chan bool
	block       *Block
	chainConfig *ChainConfig
}

// Execute block and return result.
func (block *Block) execute(parent *Block) error {
	startTime := time.Now().UnixNano()

	//miner reward
	block.header.memo.rewards = make([]*corepb.BlockFundEntity, 0)
	if err := block.IssueBonus(parent); err != nil {
		return err
	}

	config := parent.GetChainConfig()
	block.header.memo.pledge = make([]*corepb.BlockFundEntity, 0)

	context := &verifyCtx{
		mergeCh:     make(chan bool, 1),
		block:       block,
		chainConfig: config,
	}

	parallelNum := VerifyParallelNum

	dispatcher := dag.NewDispatcher(block.dependency, parallelNum, int64(VerifyExecutionTimeout), context, func(node *dag.Node, context interface{}) error {
		ctx := context.(*verifyCtx)
		block := ctx.block
		mergeCh := ctx.mergeCh
		chainConfig := ctx.chainConfig

		idx := node.Index()
		if idx < 0 || idx > len(block.transactions)-1 {
			return ErrInvalidDagBlock
		}
		tx := block.transactions[idx]

		logging.VLog().WithFields(logrus.Fields{
			"tx.hash": tx.hash,
		}).Debug("execute tx.")

		metricsTxExecute.Mark(1)

		mergeCh <- true
		txws, err := block.WorldState().Prepare(tx.Hash().String())
		if err != nil {
			<-mergeCh
			return err
		}
		<-mergeCh

		if _, err = block.ExecuteTransaction(tx, txws, chainConfig); err != nil {
			return err
		}

		mergeCh <- true
		if _, err := txws.CheckAndUpdate(); err != nil {
			return err
		}
		<-mergeCh

		mergeCh <- true
		block.UpdateBlockTxStatistics(tx)
		//block.UpdateAccountTxStatistics(tx)
		<-mergeCh

		return nil
	})

	if err := dispatcher.Run(); err != nil {
		transactions := []string{}
		for k, tx := range block.transactions {
			txInfo := fmt.Sprintf("{Index: %d, Tx: %s}", k, tx.String())
			transactions = append(transactions, txInfo)
		}
		logging.VLog().WithFields(logrus.Fields{
			"dag": block.dependency.String(),
			"txs": transactions,
			"err": err,
		}).Info("Failed to verify txs in block.")
		return err
	}

	block.CalcBlockReward()

	if err := block.verifyBlockCouncil(parent); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Debug("verify block period error")
		return err
	}

	if err := block.WorldState().Flush(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("flush state error when execute block's transactions")
		return err
	}
	endTime := time.Now().UnixNano()
	metricsBlockVerifiedTime.Update(endTime - startTime)
	return nil
}

func (block *Block) CalcBlockReward() {
	i := block.Height() % ReduceCycle
	j := block.Height() / ReduceCycle
	var year int
	if i > 0 {
		year = int(j) + 1
	} else {
		year = int(j)
	}
	if year > 30 {
		block.header.output = big.NewInt(0)
		return
	}
	curBlockReward := BlockReward
	for k := 1; k < year; k++ {
		curBlockReward = (curBlockReward * ReduceScale) / 100
	}
	output := big.NewInt(curBlockReward)

	worldState := block.WorldState()
	gasConsumed := worldState.GetGas()
	for _, gas := range gasConsumed {
		output = new(big.Int).Add(output, gas)
	}
	block.header.output = output
}

// FetchEvents fetch events by txHash.
func (block *Block) FetchEvents(txHash byteutils.Hash) ([]*state.Event, error) {
	worldState, err := block.WorldState().Copy()
	if err != nil {
		return nil, err
	}
	return worldState.FetchEvents(txHash)
}

// FetchExecutionResultEvent fetch execution result event by txHash.
func (block *Block) FetchExecutionResultEvent(txHash byteutils.Hash) (*state.Event, error) {
	worldState, err := block.WorldState().Copy()
	if err != nil {
		return nil, err
	}
	events, err := worldState.FetchEvents(txHash)
	if err != nil {
		return nil, err
	}

	if events != nil && len(events) > 0 {
		idx := len(events) - 1
		event := events[idx]
		if event.Topic != TopicTransactionExecutionResult {
			logging.VLog().WithFields(logrus.Fields{
				"tx":     txHash,
				"events": events,
			}).Info("Failed to locate the result event")
			return nil, ErrInvalidTransactionResultEvent
		}
		return event, nil
	}
	return nil, ErrNotFoundTransactionResultEvent
}

// FetchElectionResultEvent fetch execution result event by txHash.
func (block *Block) FetchElectionResultEvent(txHash byteutils.Hash) (string, error) {
	worldState, err := block.WorldState().Copy()
	if err != nil {
		return "", err
	}
	event, err := worldState.FetchElectionEvent(txHash)
	if err != nil {
		return "", err
	}
	selected := "false"
	if event.Selected == 1 {
		selected = "true"
	}
	return fmt.Sprintf(`{"selected":%s,"role":"%s","creditIndex":%d}`, selected, event.Role, event.Score), err
}

// RollBack a batch task
func (block *Block) RollBack() {
	if err := block.WorldState().RollBack(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to rollback the block")
	}
}

// verifyState return state verify result.
func (block *Block) verifyState() error {
	// verify state root.
	if !byteutils.Equal(block.WorldState().AccountsRoot(), block.StateRoot()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": block.StateRoot(),
			"actual": block.WorldState().AccountsRoot(),
		}).Info("Failed to verify account state")
		return ErrInvalidBlockStateRoot
	}

	// verify transaction root.
	if !byteutils.Equal(block.WorldState().TxsRoot(), block.TxsRoot()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": block.TxsRoot(),
			"actual": block.WorldState().TxsRoot(),
		}).Info("Failed to verify txs state")
		return ErrInvalidBlockTxsRoot
	}

	// verify events root.
	if !byteutils.Equal(block.WorldState().EventsRoot(), block.EventsRoot()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": block.EventsRoot(),
			"actual": block.WorldState().EventsRoot(),
		}).Info("Failed to verify events.")
		return ErrInvalidBlockEventsRoot
	}

	// verify witness root.
	if !reflect.DeepEqual(block.WorldState().ConsensusRoot(), block.ConsensusRoot()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": block.ConsensusRoot(),
			"actual": block.WorldState().ConsensusRoot(),
		}).Info("Failed to verify psec context")
		return ErrInvalidBlockConsensusRoot
	}

	return nil
}

// Commit a batch task
func (block *Block) Commit() {
	if err := block.WorldState().Commit(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to commit the block")
	}
}

// Begin a batch task
func (block *Block) Begin() error {
	return block.WorldState().Begin()
}

// WorldState return the world state of the block
func (block *Block) WorldState() state.WorldState {
	return block.worldState
}

// StateRoot return state root hash.
func (block *Block) StateRoot() byteutils.Hash {
	return block.header.stateRoot
}

// TxsRoot return txs root hash.
func (block *Block) TxsRoot() byteutils.Hash {
	return block.header.txsRoot
}

// TxsRoot return events root.
func (block *Block) EventsRoot() byteutils.Hash {
	return block.header.eventsRoot
}

// ConsensusRoot returns block's consensus root.
func (block *Block) ConsensusRoot() *consensuspb.ConsensusRoot {
	pb := new(consensuspb.ConsensusRoot)
	proto.Unmarshal(block.header.consensusRoot, pb)
	return pb
}

// ParentHash return parent hash.
func (block *Block) ParentHash() byteutils.Hash {
	return block.header.parentHash
}

// Coinbase return coinbase
func (block *Block) Coinbase() *Address {
	return block.header.coinbase
}

// Transactions returns block transactions
func (block *Block) Transactions() Transactions {
	return block.transactions
}

// Signature return block's signature
func (block *Block) Signature() *corepb.Signature {
	return block.header.sign
}

// SignHash return block's sign hash
func (block *Block) SignHash() byteutils.Hash {
	return block.header.sign.GetData()
}

// sign block
func (block *Block) Sign(signature keystore.Signature) error {
	if signature == nil {
		return ErrNilArgument
	}
	sign, err := signature.Sign(block.header.hash)
	if err != nil {
		return err
	}
	block.header.sign = &corepb.Signature{
		Signer: sign.GetSigner(),
		Data:   sign.GetData(),
	}
	return nil
}

func (block *Block) VerifySign() error {
	signature, err := crypto.NewSignature()
	if err != nil {
		return err
	}
	result, err := signature.Verify(block.Hash(), block.header.sign)
	if err != nil {
		return err
	}
	if !result {
		logging.VLog().WithFields(logrus.Fields{
			"blockHash": block.Hash(),
			"sign":      byteutils.Hex(block.Header().Sign().Data),
			"pubKey":    byteutils.Hex(block.Header().Sign().Signer),
			"err":       err,
		}).Error("Failed to check block's signature")
		return ErrInvalidBlockSign
	}
	return nil
}

func (block *Block) GetAccount(address byteutils.Hash) (state.Account, error) {
	worldState, err := block.WorldState().Copy()
	if err != nil {
		return nil, err
	}
	return worldState.GetOrCreateAccount(address)
}

func (block *Block) GetChainConfig() *ChainConfig {
	sysConfig := NewNormalSysConfig()
	key := byteutils.Hex(block.Hash())
	if val, ok := block.blkPool.bc.chainConfigCache.Get(key); ok {
		return val.(*ChainConfig)
	} else {
		council, err := block.worldState.GetCouncil(block.TermId())
		if err == nil {
			config := council.GetMeta().Config
			if config != nil {
				chainConfig := SystemConfigToChainConfig(config)
				block.blkPool.bc.chainConfigCache.Add(key, chainConfig)
				return chainConfig
			}
		}
	}

	return SystemConfigToChainConfig(sysConfig)
}

func (block *Block) IsValidSuperNode(address string) bool {
	superNodes := block.GetChainConfig().SuperNodes
	for _, node := range superNodes {
		if node.Address == address {
			return true
		}
	}
	return false
}

// SetRandomSeed set block.header.random
func (block *Block) SetRandomSeed(vrfseed, vrfproof []byte) {
	block.header.random = &corepb.Random{
		VrfSeed:  vrfseed,
		VrfProof: vrfproof,
	}
}

// return string object of a block
func (block *Block) String() string {
	//memo := ""
	//if block.header.memo != nil {
	//	if block.header.memo.pledge != nil {
	//		for _, pledge := range block.header.memo.pledge {
	//			memo += pledge.String()
	//		}
	//	}
	//
	//	if block.header.memo.rewards != nil {
	//		for _, reward := range block.header.memo.rewards {
	//			memo += reward.String()
	//		}
	//	}
	//}
	//txs := make([]string, 0)
	//for _, tx := range block.transactions {
	//	txs = append(txs, tx.hash.Base58())
	//}
	//	txsOut, _ := json.Marshal(txs)
	//	return fmt.Sprintf(`{"height": %d, "chainId": %d, "termId": %d, "hash": "%s", "parent_hash": "%s",
	//"acc_root": "%s", "txs_root:": "%s", "consensus_root": "%s", "timestamp": %d, "output": "%s", "txs": %s, "miner": "%s","memo":"%s"}`,
	//		block.Height(),
	//		block.header.ChainId(),
	//		block.header.termId,
	//		block.header.hash,
	//		block.header.parentHash,
	//		block.header.stateRoot,
	//		block.header.txsRoot,
	//		block.header.consensusRoot,
	//		block.header.timestamp,
	//		block.header.output.String(),
	//		txsOut,
	//		block.header.Coinbase().String(),
	//		memo,
	//	)

	return fmt.Sprintf(`{"height": %d, "chainId": %d, "termId": %d, "hash": "%s", "parent_hash": "%s",
	"acc_root": "%s", "timestamp": %d, "output": "%s", "txs": %d, "miner": "%s"}`,
		block.Height(),
		block.header.ChainId(),
		block.header.termId,
		block.header.hash,
		block.header.parentHash,
		block.header.stateRoot,
		block.header.timestamp,
		block.header.output.String(),
		len(block.transactions),
		block.header.Coinbase().String(),
	)
}
