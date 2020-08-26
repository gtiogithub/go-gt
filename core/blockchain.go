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
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-gt library.  If not, see <http://www.gnu.org/licenses/>.
//
package core

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/conf"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
)

var (
	TxHashLengthNotMatchError  = errors.New("tx hash is not 64")
	TransactionNotFoundInBlock = errors.New("transaction not found in block")
)

const (
	// ChunkSize is the size of blocks in a chunk
	ChunkSize = 32
	// Tail Key in storage
	Tail = "blockchain_tail"
	// Fixed in storage
	Fixed = "blockchain_fixed"
	// transaction's block height
	TxBlockHeight = "height"
)

type ChainConfig struct {
	BlockInterval           int32
	SuperNodeCount          int32
	WitnessCount            int32
	SuperNodes              []*corepb.Node
	ContractTxFee           *big.Int
	DeployContractMinVolume int32
	FloatingCycle           int32
	MinPledge               *big.Int
	CycleDuration           int32
}

// BlockChain
type BlockChain struct {
	chainId   uint32
	consensus Consensus
	sync      Synchronize

	config       *config.Config
	db           cdb.Storage
	genesis      *Genesis
	cvm          CVM
	tailBlock    *Block
	fixedBlock   *Block
	genesisBlock *Block

	txPool *TxPool
	bkPool *BlockPool

	cachedBlocks       *lru.Cache
	detachedTailBlocks *lru.Cache
	chainConfigCache   *lru.Cache

	superNode   bool
	standbyNode bool

	quitCh chan int

	eventEmitter *EventEmitter
}

// get next term id
func (bc *BlockChain) NextTermId() uint64 {
	return bc.tailBlock.TermId() + 1
}

// set super node state
func (bc *BlockChain) SetSuperNodeState(flg bool) {
	bc.superNode = flg
}

// set standby node state
func (bc *BlockChain) SetStandbyNodeState(flg bool) {
	bc.standbyNode = flg
}

// return the cvm object
func (bc *BlockChain) VM() CVM {
	return bc.cvm
}

// EventEmitter return the eventEmitter.
func (bc *BlockChain) EventEmitter() *EventEmitter {
	return bc.eventEmitter
}

// load system config
func (bc *BlockChain) LoadSystemConfig() (*corepb.SystemConfig, error) {
	var contractAddr *Address
	genesisBlock := bc.GenesisBlock()
	tailBlock := bc.TailBlock()
	txs := genesisBlock.Transactions()

	for _, tx := range txs {
		if tx.GetData().Type == ContractDeployTx {
			if addr, err := tx.GenerateContractAddress(); err == nil {
				contractAddr = addr
			}
		}
	}

	if contractAddr == nil {
		return nil, errors.New("cannot get system contract address")
	}

	sysconfig := NewNormalSysConfig()
	// get super nodes
	superNodes, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getSuperNodes", "")
	if err != nil {
		return nil, err
	}
	supers := strings.Split(strings.ReplaceAll(superNodes.Msg, "\"", ""), ",") // string:
	superNodesMap := make(map[string][]byte)
	superKeys := make([]string, 0)
	for _, node := range supers {
		if node != "" {
			items := strings.Split(node, ":")
			val, _ := new(big.Int).SetString(items[1], 10)
			superNodesMap[items[0]] = val.Bytes()
			superKeys = append(superKeys, items[0])
		}
	}
	sort.Strings(superKeys)
	for _, key := range superKeys {
		sysconfig.SuperNodes = append(sysconfig.SuperNodes, &corepb.Node{
			Address: key,
			Fund:    superNodesMap[key],
		})
	}

	// get block interval
	resSimulateInterval, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getBlockInterval", "")
	if err != nil {
		return nil, err
	}
	resInterval := resSimulateInterval.Msg
	interval, err := strconv.Atoi(resInterval)
	if err != nil {
		return nil, err
	}
	sysconfig.BlockInterval = int32(interval / 1000)

	// get witness num
	resSimulateWitNum, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getWitnessCount", "")
	if err != nil {
		return nil, err
	}
	resWitNum := resSimulateWitNum.Msg
	witNum, err := strconv.Atoi(resWitNum)
	if err != nil {
		return nil, err
	}
	sysconfig.WitnessCount = int32(witNum)
	//psec.witnessNum = witNum

	// get deploy contract min volume
	resSimulateVolume, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getDeployContractMinVolume", "")
	if err != nil {
		return nil, err
	}
	resVolume := resSimulateVolume.Msg
	volume, err := strconv.Atoi(resVolume)
	if err != nil {
		return nil, err
	}
	sysconfig.DeployContractMinVolume = int32(volume)

	// get per contract tx fee
	resSimulateTxFee, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getPerContractTxFee", "")
	if err != nil {
		return nil, err
	}
	resTxFee := strings.ReplaceAll(resSimulateTxFee.Msg, "\"", "")
	txFee, err := strconv.Atoi(resTxFee)
	if err != nil {
		return nil, err
	}
	sysconfig.ContractTxFee = big.NewInt(int64(txFee)).Bytes()

	// get floating cycle
	resSimulateFloatingCycle, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getFloatingCycle", "")
	if err != nil {
		return nil, err
	}
	resFloatingCycle := resSimulateFloatingCycle.Msg
	floatingCycle, err := strconv.Atoi(resFloatingCycle)
	if err != nil {
		return nil, err
	}
	sysconfig.FloatingCycle = int32(floatingCycle)

	// get min pledge
	resSimulateMinPledge, err := bc.simulateGenesisTransactionExecution(contractAddr, tailBlock, "getVariables", "[\"min_pledge\"]")
	if err != nil {
		return nil, err
	}
	resMinPledge := strings.ReplaceAll(resSimulateMinPledge.Msg, "\"", "")
	if len(resMinPledge) > 0 {
		minPledge, err := strconv.Atoi(resMinPledge)
		if err != nil {
			return nil, err
		}
		sysconfig.MinPledge = big.NewInt(int64(minPledge)).Bytes()
	}

	return sysconfig, nil
}

func NewNormalSysConfig() *corepb.SystemConfig {
	sysConfig := &corepb.SystemConfig{
		BlockInterval:           10000,
		SuperNodeCount:          21,
		WitnessCount:            21,
		SuperNodes:              make([]*corepb.Node, 0),
		ContractTxFee:           big.NewInt(100000).Bytes(),
		DeployContractMinVolume: 1000,
		FloatingCycle:           1,
		MinPledge:               big.NewInt(50000000000000).Bytes(),
	}
	return sysConfig
}

func SystemConfigToChainConfig(sysConfig *corepb.SystemConfig) *ChainConfig {
	chainConf := &ChainConfig{
		BlockInterval:           sysConfig.BlockInterval,
		SuperNodeCount:          sysConfig.SuperNodeCount,
		WitnessCount:            sysConfig.WitnessCount,
		SuperNodes:              make([]*corepb.Node, 0),
		ContractTxFee:           new(big.Int).SetBytes(sysConfig.ContractTxFee),
		DeployContractMinVolume: sysConfig.DeployContractMinVolume,
		FloatingCycle:           sysConfig.FloatingCycle,
		MinPledge:               new(big.Int).SetBytes(sysConfig.MinPledge),
	}
	if sysConfig.SuperNodes != nil && len(sysConfig.SuperNodes) > 0 {
		for _, node := range sysConfig.SuperNodes {
			chainConf.SuperNodes = append(chainConf.SuperNodes, &corepb.Node{
				Address: node.Address,
				Fund:    node.Fund[:],
			})
		}
	}

	chainConf.CycleDuration = chainConf.WitnessCount * chainConf.WitnessCount * chainConf.FloatingCycle
	return chainConf
}

// NewBlockChain
func NewBlockChain(config *config.Config, net network.Service, eventEmitter *EventEmitter, db cdb.Storage) (*BlockChain, error) {
	chainConfig := conf.GetChainConfig(config)

	blockPool, err := NewBlockPool(int(chainConfig.BlockPoolSize))
	if err != nil {
		return nil, err
	}

	txPool := NewTxPool()
	txPool.setEventEmitter(eventEmitter)

	chain := &BlockChain{
		chainId:      chainConfig.ChainId,
		config:       config,
		db:           db,
		bkPool:       blockPool,
		txPool:       txPool,
		genesis:      &Genesis{},
		superNode:    false,
		standbyNode:  false,
		eventEmitter: eventEmitter,
		quitCh:       make(chan int),
	}

	blockPool.RegisterInNetwork(net)
	txPool.RegisterInNetwork(net)

	chain.cachedBlocks, err = lru.New(128)
	if err != nil {
		return nil, err
	}

	chain.detachedTailBlocks, err = lru.New(128)
	if err != nil {
		return nil, err
	}
	chain.chainConfigCache, err = lru.New(21)
	if err != nil {
		return nil, err
	}

	chain.bkPool.setBlockChain(chain)
	chain.txPool.setBlockChain(chain)

	return chain, nil
}

// setup blockchain
func (bc *BlockChain) Setup(gt Gt) error {
	bc.consensus = gt.Consensus()
	bc.cvm = gt.Cvm()
	var err error

	bc.genesis, err = LoadGenesisConf(DefaultGenesisPath)
	if err != nil {
		return err
	}

	bc.genesisBlock, err = bc.LoadGenesisFromStorage()
	if err != nil {
		return err
	}

	bc.tailBlock, err = bc.LoadTailFromStorage()
	if err != nil {
		return err
	}
	logging.CLog().WithFields(logrus.Fields{
		"tail": bc.tailBlock,
	}).Info("Tail Block.")

	bc.fixedBlock, err = bc.LoadFixedFromStorage()
	if err != nil {
		return err
	}
	logging.CLog().WithFields(logrus.Fields{
		"block": bc.fixedBlock,
	}).Info("Latest Permanent Block.")
	return nil
}

// LoadGenesisFromStorage load genesis
func (bc *BlockChain) LoadGenesisFromStorage() (*Block, error) { // ToRefine, remove or ?
	blockHash, _ := bc.db.Get(byteutils.FromUint64(1))
	if blockHash == nil {
		genesis, err := NewGenesis(bc.genesis, bc)
		if err != nil {
			return nil, err
		}
		if err := bc.StoreBlockToStorage(genesis); err != nil {
			return nil, err
		}
		heightKey := byteutils.FromUint64(genesis.Height())
		if err := bc.db.Put(heightKey, genesis.Hash()); err != nil {
			return nil, err
		}
		return genesis, nil
	} else {
		genesis, err := LoadBlockFromStorage(blockHash, bc)
		if err != nil {
			return nil, err
		}
		return genesis, nil
	}
}

// LoadTailFromStorage load tail block
func (bc *BlockChain) LoadTailFromStorage() (*Block, error) {
	hash, err := bc.db.Get([]byte(Tail))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err == cdb.ErrKeyNotFound {
		genesis, err := bc.LoadGenesisFromStorage()
		if err != nil {
			return nil, err
		}

		if err := bc.StoreTailHashToStorage(genesis); err != nil {
			return nil, err
		}

		return genesis, nil
	}

	return LoadBlockFromStorage(hash, bc)
}

// store tail block hash to storage
func (bc *BlockChain) StoreTailHashToStorage(block *Block) error {
	return bc.db.Put([]byte(Tail), block.Hash())
}

// LoadFixedFromStorage load FIXED
func (bc *BlockChain) LoadFixedFromStorage() (*Block, error) {
	hash, err := bc.db.Get([]byte(Fixed))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}

	if err == cdb.ErrKeyNotFound {
		if err := bc.StoreFixedHashToStorage(bc.genesisBlock); err != nil {
			return nil, err
		}
		return bc.genesisBlock, nil
	}

	return LoadBlockFromStorage(hash, bc)
}

// StoreFIXEDHashToStorage store FIXED block hash
func (bc *BlockChain) StoreFixedHashToStorage(block *Block) error {
	return bc.db.Put([]byte(Fixed), block.Hash())
}

// return blockchain's chain id
func (bc *BlockChain) ChainId() uint32 {
	return bc.chainId
}

// return blockchain's storage
func (bc *BlockChain) Storage() cdb.Storage {
	return bc.db
}

// set tail block
func (bc *BlockChain) SetTailBlock(newTail *Block) error {
	if newTail == nil {
		return ErrNilArgument
	}
	oldTail := bc.tailBlock
	ancestor, err := bc.queryCommonAncestorWithTail(newTail)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"target": newTail,
			"tail":   oldTail,
		}).Error("Failed to find common ancestor with tail")
		return err
	}

	err = bc.revertBlocks(ancestor, oldTail)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"from":  ancestor,
			"to":    oldTail,
			"range": "(from, to]",
		}).Error("Failed to get revert blocks's txs")
	}

	if err = bc.buildIndexByBlockHeight(ancestor, newTail); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"from":  ancestor,
			"to":    newTail,
			"range": "(from, to]",
		}).Error("Failed to build index by block height.")
	}

	if err := bc.StoreTailHashToStorage(newTail); err != nil {
		return err
	}

	bc.tailBlock = newTail

	return nil
}

// return tx by tx hash
func (bc *BlockChain) GetTransactionByHash(txHash string) (*Transaction, error) {
	txHashBytes, err := byteutils.FromHex(txHash)
	if err != nil {
		return nil, err
	}
	worldState, err := bc.TailBlock().WorldState().Copy()
	if err != nil {
		return nil, err
	}
	tx, err := GetTransaction(txHashBytes, worldState)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// GetBlockOnCanonicalChainByHash check if a block is on canonical chain
func (bc *BlockChain) GetBlockOnCanonicalChainByHash(blockHash byteutils.Hash) *Block {
	blockByHash := bc.GetBlock(blockHash)
	if blockByHash == nil {
		logging.VLog().WithFields(logrus.Fields{
			"hash": blockHash.Hex(),
			"tail": bc.tailBlock,
			"err":  "cannot find block with the given hash in local storage",
		}).Debug("Failed to check a block on canonical chain.")
		return nil
	}
	blockByHeight := bc.GetBlockOnCanonicalChainByHeight(blockByHash.Height())
	if blockByHeight == nil {
		logging.VLog().WithFields(logrus.Fields{
			"height": blockByHash.Height(),
			"tail":   bc.tailBlock,
			"err":    "cannot find block with the given height in local storage",
		}).Debug("Failed to check a block on canonical chain.")
		return nil
	}
	if !blockByHeight.Hash().Equals(blockByHash.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"blockByHash":   blockByHash,
			"blockByHeight": blockByHeight,
			"tail":          bc.tailBlock,
			"err":           "block with the given hash isn't on canonical chain",
		}).Debug("Failed to check a block on canonical chain.")
		return nil
	}
	return blockByHeight
}

// GetBlock return block of given hash from local storage and detachedBlocks.
func (bc *BlockChain) GetBlock(hash byteutils.Hash) *Block {
	v, _ := bc.cachedBlocks.Get(hash.Hex())
	if v == nil {
		block, err := LoadBlockFromStorage(hash, bc)
		if err != nil {
			return nil
		}
		return block
	}

	block := v.(*Block)
	return block
}

// GetTransactionHeight return transaction's block height
func (bc *BlockChain) GetTransactionHeight(hash byteutils.Hash) (uint64, error) {
	bytes, err := bc.db.Get(append(hash, []byte(TxBlockHeight)...))
	if err != nil {
		return 0, err
	}

	if len(bytes) == 0 {
		// for empty value (history txs), height = 0
		return 0, nil
	}

	return byteutils.Uint64(bytes), nil
}

// GetBlockOnCanonicalChainByHeight return block in given height
func (bc *BlockChain) GetBlockOnCanonicalChainByHeight(height uint64) *Block {
	if height > bc.tailBlock.Height() {
		return nil
	}

	blockHash, err := bc.db.Get(byteutils.FromUint64(height))
	if err != nil {
		return nil
	}
	return bc.GetBlock(blockHash)
}

// return block by height
func (bc *BlockChain) GetBlocksByHeight(height uint64) []*Block {
	res := make([]*Block, 0)
	b := bc.GetBlockOnCanonicalChainByHeight(height)
	if b == nil {
		return nil
	}
	res = append(res, b)
	return res
}

// remove block's txs from tx pool
func (bc *BlockChain) removeTxsInBlockFromTxPool(block *Block) {
	for _, tx := range block.transactions {
		bc.txPool.removeNormalTransaction(tx)
	}
}

// detach tail blcok
func (bc *BlockChain) DetachedTailBlocks() []*Block {
	ret := make([]*Block, 0)
	for _, k := range bc.detachedTailBlocks.Keys() {
		v, _ := bc.detachedTailBlocks.Get(k)
		if v != nil {
			block := v.(*Block)
			ret = append(ret, block)
		}
	}
	return ret
}

// PutVerifiedNewBlocks put verified new blocks and tails.
func (bc *BlockChain) putVerifiedNewBlocks(parent *Block, allBlocks, tailBlocks []*Block) error {
	for _, v := range allBlocks {
		bc.cachedBlocks.Add(v.Hash().Hex(), v)
		if err := bc.StoreBlockToStorage(v); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"block": v,
				"err":   err,
			}).Error("Failed to store the verified block.")
			return err
		}

		logging.VLog().WithFields(logrus.Fields{
			"block": v,
		}).Info("Accepted the new block on chain")

	}
	for _, v := range tailBlocks {
		bc.detachedTailBlocks.Add(v.Hash().Hex(), v)
		logging.VLog().WithFields(logrus.Fields{
			"block.hash":   v.Hash().Hex(),
			"block.height": v.Height(),
			"parent.hash":  v.ParentHash().Hex(),
		}).Debug("ADD detachedTailBlocks.")
	}

	bc.detachedTailBlocks.Remove(parent.Hash().Hex())
	logging.VLog().WithFields(logrus.Fields{
		"parent.hash":   parent.Hash().Hex(),
		"parent.height": parent.Height(),
	}).Debug("DELETE detachedTailBlocks.")

	return nil
}

func (bc *BlockChain) GetAccountTxs(account byteutils.Hash, index uint64, count uint64) ([]byteutils.Hash, error) {
	acc, err := bc.TailBlock().worldState.GetOrCreateAccount(account)
	if err != nil {
		return nil, err
	}
	txsCount := acc.TxsCount()
	if txsCount <= index {
		return nil, nil
	}
	txs := make([]byteutils.Hash, 0)
	curCount := txsCount - index
	startIndex := curCount - 1
	var endIndex uint64
	if curCount >= count {
		endIndex = curCount - count
	} else {
		endIndex = 0
	}
	for ; startIndex >= endIndex; startIndex-- {
		txHash, err := acc.GetTx(byteutils.FromUint64(startIndex))
		if err != nil {
			return nil, err
		}
		txs = append(txs, txHash)
		if startIndex == 0 {
			break
		}
	}
	return txs, nil
}

// return  contract account by address
func (bc *BlockChain) GetContract(addr *Address) (state.Account, error) {
	ws, err := bc.TailBlock().WorldState().Copy()
	if err != nil {
		return nil, err
	}

	contract, err := GetContract(addr, ws)
	if err != nil {
		return nil, err
	}

	return contract, nil
}

// return tx by tx hash
func (bc *BlockChain) GetTransaction(txHash byteutils.Hash) (*Transaction, error) {
	ws, err := bc.TailBlock().WorldState().Copy()
	if err != nil {
		return nil, err
	}

	tx, err := GetTransaction(txHash, ws)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

// StoreBlockToStorage store block
func (bc *BlockChain) StoreBlockToStorage(block *Block) error {
	pbBlock, err := block.ToProto()
	if err != nil {
		return err
	}
	value, err := proto.Marshal(pbBlock)
	if err != nil {
		return err
	}
	err = bc.db.Put(block.Hash(), value)
	if err != nil {
		return err
	}

	// store block's txs to storage
	for _, tx := range block.transactions {
		pbTx, err := tx.ToProto()
		if err != nil {
			continue
		}

		txBytes, err := proto.Marshal(pbTx)
		if err != nil {
			continue
		}

		// TxHash --> Tx
		_ = bc.db.Put(tx.Hash(), txBytes)

		// TxHash+"height" --> BlockHeight
		_ = bc.db.Put(append(tx.Hash(), []byte(TxBlockHeight)...), byteutils.FromUint64(block.Height()))
	}

	return nil
}

// return the blockpool object
func (bc *BlockChain) BlockPool() *BlockPool {
	return bc.bkPool
}

// return the txpool object
func (bc *BlockChain) TxPool() *TxPool {
	return bc.txPool
}

// return consensus
func (bc *BlockChain) Consensus() Consensus {
	return bc.consensus
}

// return tail block
func (bc *BlockChain) TailBlock() *Block {
	return bc.tailBlock
}

// return genesis block
func (bc *BlockChain) GenesisBlock() *Block {
	return bc.genesisBlock
}

// return fixed block
func (bc *BlockChain) FixedBlock() *Block {
	return bc.fixedBlock
}

// set fixed block
func (bc *BlockChain) SetFixedBlock(block *Block) {
	bc.fixedBlock = block
}

// StartActiveSync start active sync task
func (bc *BlockChain) StartActiveSync() bool {
	if bc.sync.StartActiveSync() {
		bc.consensus.SuspendMining()
		go func() {
			bc.sync.WaitingForFinish()
			bc.consensus.ResumeMining()
		}()
		return true
	}
	return false
}

// IsActiveSyncing returns true if being syncing
func (bc *BlockChain) IsActiveSyncing() bool {
	return bc.sync.IsActiveSyncing()
}

// SetSyncEngine set sync engine
func (bc *BlockChain) SetSyncEngine(syncEngine Synchronize) {
	bc.sync = syncEngine
}

// Start start loop.
func (bc *BlockChain) Start() {
	logging.CLog().Info("Starting BlockChain...")
	go bc.loop()
}

// loop:
// update the fixed block
func (bc *BlockChain) loop() {
	logging.CLog().Info("Started BlockChain.")
	timerChan := time.NewTicker(15 * time.Second).C
	for {
		select {
		case <-bc.quitCh:
			logging.CLog().Info("Stopped BlockChain.")
			return
		case <-timerChan:
			bc.Consensus().UpdateFixedBlock()
		}
	}
}

func (bc *BlockChain) triggerNewTailInfo(blocks []*Block) {
	for i := len(blocks) - 1; i >= 0; i-- {
		block := blocks[i]
		bc.eventEmitter.Trigger(&state.Event{
			Topic: TopicNewTailBlock,
			Data:  block.String(),
		})

		for _, v := range block.transactions {
			bc.db.Put(append(v.hash, []byte(TxBlockHeight)...), byteutils.FromUint64(block.Height()))
			events, err := block.FetchEvents(v.hash)
			if err == nil {
				for _, e := range events {
					bc.eventEmitter.Trigger(e)
				}
			}
		}
	}
}

// Stop stop loop.
func (bc *BlockChain) Stop() {
	logging.CLog().Info("Stopping BlockChain...")
	bc.quitCh <- 0
}

// GetInputForVRFSigner
func (bc *BlockChain) GetInputForVRFSigner(parentHash byteutils.Hash, height uint64) (ancestorHash, parentSeed []byte, err error) {
	if parentHash == nil {
		return nil, nil, ErrInvalidArgument
	}

	parent := bc.GetBlockOnCanonicalChainByHash(parentHash)
	if parent == nil || parent.Height()+1 != height {
		return nil, nil, ErrInvalidBlockHash
	}

	if height == 2 {
		parentSeed = parent.header.hash
	} else {
		parentSeed = parent.header.random.VrfSeed
	}

	council, err := parent.WorldState().GetCouncil(parent.TermId())
	if err != nil {
		return nil, nil, err
	}
	baseHeight := uint64(council.Meta.Config.WitnessCount * council.Meta.Config.WitnessCount * council.Meta.Config.FloatingCycle * 2)
	if height > baseHeight {
		b := bc.GetBlockOnCanonicalChainByHeight(height - baseHeight)
		if b == nil {
			return nil, nil, ErrNotBlockInCanonicalChain
		}
		ancestorHash = b.Hash()
	} else {
		ancestorHash = bc.GenesisBlock().Hash()
	}
	return ancestorHash, parentSeed, nil
}

// build index by block height
func (bc *BlockChain) buildIndexByBlockHeight(oldTail *Block, newTail *Block) error {
	blocks := []*Block{}
	for !oldTail.Hash().Equals(newTail.Hash()) {
		err := bc.db.Put(byteutils.FromUint64(newTail.Height()), newTail.Hash())
		if err != nil {
			return err
		}
		blocks = append(blocks, newTail)
		//remove transactions in block from tx pool
		go bc.removeTxsInBlockFromTxPool(newTail)

		newTail = bc.GetBlock(newTail.ParentHash())
		if newTail == nil {
			return ErrMissingParentBlock
		}
	}
	go bc.triggerNewTailInfo(blocks)
	return nil
}

// queryCommonAncestorWithTail return the block's common ancestor with current tail
func (bc *BlockChain) queryCommonAncestorWithTail(block *Block) (*Block, error) {
	if block == nil {
		return nil, ErrNilArgument
	}
	target := bc.GetBlock(block.Hash())
	if target == nil {
		target = bc.GetBlock(block.ParentHash())
	}
	if target == nil {
		return nil, ErrMissingParentBlock
	}

	tail := bc.TailBlock()
	if tail.Height() > target.Height() {
		tail = bc.GetBlockOnCanonicalChainByHeight(target.Height())
		if tail == nil {
			return nil, ErrMissingParentBlock
		}
	}

	for tail.Height() < target.Height() {
		target = bc.GetBlock(target.header.parentHash)
		if target == nil {
			return nil, ErrMissingParentBlock
		}
	}

	for !tail.Hash().Equals(target.Hash()) {
		tail = bc.GetBlock(tail.header.parentHash)
		target = bc.GetBlock(target.header.parentHash)
		if tail == nil || target == nil {
			return nil, ErrMissingParentBlock
		}
	}

	return target, nil
}

func (bc *BlockChain) triggerRevertBlockEvent(blocks []string) {
	for i := len(blocks) - 1; i >= 0; i-- {
		bc.eventEmitter.Trigger(&state.Event{
			Topic: TopicRevertBlock,
			Data:  blocks[i],
		})
	}
}

// revert blocks
func (bc *BlockChain) revertBlocks(from *Block, to *Block) error {
	reverted := to
	blocks := []string{}
	for !reverted.Hash().Equals(from.Hash()) {
		if reverted.Hash().Equals(bc.fixedBlock.Hash()) {
			return ErrCannotRevertFixed
		}
		reverted.PutBackTxs()

		logging.VLog().WithFields(logrus.Fields{
			"block": reverted,
		}).Warn("A block is reverted.")
		blocks = append(blocks, reverted.String())
		reverted = bc.GetBlock(reverted.header.parentHash)
		if reverted == nil {
			return ErrMissingParentBlock
		}
	}
	go bc.triggerRevertBlockEvent(blocks)
	return nil
}

// NewBlock create new #Block instance.
//func (bc *BlockChain) NewBlock(coinbase *Address) (*Block, error) {
//	if coinbase == nil {
//		return nil, ErrInvalidArgument
//	}
//	return bc.NewBlockFromParent(coinbase, bc.tailBlock)
//}

// NewBlockFromParent create new block from parent block and return it.
func (bc *BlockChain) NewBlockFromParent(coinbase *Address, parentBlock *Block) (*Block, error) {
	if parentBlock == nil || coinbase == nil {
		return nil, ErrNilArgument
	}
	return NewBlock(bc.chainId, coinbase, parentBlock, time.Now().Unix())
}

// SimulateResult the result of simulating transaction execution
type SimulateResult struct {
	GasUsed *big.Int
	Msg     string
	Err     error
}

// SimulateTransactionExecution execute transaction in sandbox and rollback all changes, used to EstimateGas and Call api.
func (bc *BlockChain) SimulateTransactionExecution(tx *Transaction) (*SimulateResult, error) {
	if tx == nil {
		return nil, ErrInvalidArgument
	}

	tail := bc.tailBlock
	// create block.
	block, err := bc.NewBlockFromParent(GenesisCoinbase, tail)
	if err != nil {
		return nil, err
	}

	sVrfSeed, sVrfProof := make([]byte, 32), make([]byte, 129)
	_, _ = io.ReadFull(rand.Reader, sVrfSeed)
	_, _ = io.ReadFull(rand.Reader, sVrfProof)
	block.header.random.VrfSeed = sVrfSeed
	block.header.random.VrfProof = sVrfProof

	defer block.RollBack()

	// simulate execution.
	return tx.simulateExecution(block, tail.GetChainConfig())
}

func (bc *BlockChain) simulateGenesisTransactionExecution(contractAddress *Address, tail *Block, function string, args string) (*SimulateResult, error) {
	parentBlock := tail
	if parentBlock == nil {
		parentBlock = bc.tailBlock
	}

	callHandler, err := NewCallHandler(function, args)
	if err != nil {
		return nil, err
	}

	handler, err := callHandler.ToBytes()
	if err != nil {
		return nil, err
	}
	addr, err := AddressParse(bc.genesis.FirstAccount)
	if err != nil {
		return nil, err
	}

	tx, err := NewTransaction(bc.chainId, addr, contractAddress, big.NewInt(0), 0, 0,
		ContractInvokeTx, handler, "", MinGasCountPerTransaction, nil)
	if err != nil {
		return nil, err
	}
	result, err := tx.simulateExecution(parentBlock, nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}
