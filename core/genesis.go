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
	"io/ioutil"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/dag"
	"gt.pro/gtio/go-gt/util/logging"
)

const (
	DefaultGenesisPath        = "conf/genesis.yaml"
	DefaultSystemContractPath = "conf/system_contract.js"
)

// Genesis Block Hash
var (
	GenesisTimestamp   = int64(1597802400)
	GenesisCoinbase, _ = NewAddressFromPublicKey(make([]byte, PublicKeyDataLength))
)

//
type Genesis struct {
	ChainId        uint32                 `yaml:"chain_id"`
	FirstAccount   string                 `yaml:"first_account"`
	SuperNodes     []*TokenDistribution   `yaml:"super_nodes"`
	GenesisCouncil []*CouncilMember       `yaml:"genesis_council"`
	Funds          []*TokenDistribution   `yaml:"genesis_funds"`
	EngineFactors  map[string]interface{} `yaml:"engine_factors"`
}

type SystemContractArgs struct {
	BlockInterval           uint32               `json:"blockInterval"`
	SuperNodeCount          uint32               `json:"superNodeCount"`
	WitnessCount            uint32               `json:"witnessCount"`
	FloatingCycle           uint32               `json:"floatingCycle"`
	Variables               []*Property          `json:"variables"`
	PerContractTxFee        uint64               `json:"perContractTxFee"`
	DeployContractMinVolume uint32               `json:"deployContractMinVolume"`
	SuperNodes              []*TokenDistribution `json:"superNodes"`
}

type TokenDistribution struct {
	Address string `json:"address,omitempty"`
	Value   string `json:"value,omitempty"`
}

type CouncilMember struct {
	Address    string `yaml:"address"`
	PeerId     string `yaml:"peer_id"`
	PledgeFund string `yaml:"pledge_fund""`
}

type Property struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

//
func GetSysContractSrc() (string, error) {
	bytes, err := ioutil.ReadFile(DefaultSystemContractPath)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

//
func LoadGenesisConf(filePath string) (*Genesis, error) {
	in, err := ioutil.ReadFile(filePath)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to read the genesis config file.")
		return nil, err
	}
	genesis := new(Genesis)
	err = yaml.Unmarshal(in, genesis)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to parse genesis file.")
		return nil, err
	}
	if len(genesis.FirstAccount) <= 0 {
		logging.CLog().WithFields(logrus.Fields{
			"genesis.FirstAccount": genesis.FirstAccount,
		}).Error("invalid genesis config.")
		return nil, ErrInvalidGenesis
	}
	_, err = AddressParse(genesis.FirstAccount)
	if err != nil {
		return nil, err
	}
	return genesis, nil
}

// NewGenesis
func NewGenesis(cfg *Genesis, chain *BlockChain) (*Block, error) {
	if cfg == nil || chain == nil {
		return nil, ErrNilArgument
	}

	worldState, err := state.NewWorldState(chain.consensus, chain.db)
	if err != nil {
		return nil, err
	}

	genesisBlock := &Block{
		header: &BlockHeader{
			chainId:    cfg.ChainId,
			termId:     1,
			parentHash: nil,
			timestamp:  GenesisTimestamp,
			coinbase:   GenesisCoinbase,
			height:     1,
			sign:       &corepb.Signature{},
			output:     big.NewInt(0),
			memo: &BlockMemo{
				rewards: make([]*corepb.BlockFundEntity, 0),
				pledge:  make([]*corepb.BlockFundEntity, 0),
			},
			random: &corepb.Random{},
		},
		transactions: make([]*Transaction, 0),
		dependency:   dag.NewDag(),
		txPool:       chain.txPool,
		blkPool:      chain.bkPool,
		cvm:          chain.cvm,
		db:           chain.db,
		eventEmitter: chain.eventEmitter,
		worldState:   worldState,
		sealed:       false,
	}
	if err := genesisBlock.Begin(); err != nil {
		return nil, err
	}

	if cfg.Funds != nil && len(cfg.Funds) > 0 {
		for _, token := range cfg.Funds {
			if err := processingDistributionFund(token, genesisBlock, false); err != nil {
				genesisBlock.RollBack()
				return nil, err
			}
		}
	}

	sysConfig := NewNormalSysConfig()
	chainConfig := SystemConfigToChainConfig(sysConfig)

	addr, err := AddressParse(cfg.FirstAccount)
	if err != nil {
		return nil, err
	}

	sysSrc, err := GetSysContractSrc()
	if err != nil {
		return nil, err
	}

	args := &SystemContractArgs{
		BlockInterval:           10000,
		PerContractTxFee:        100000,
		SuperNodeCount:          21,
		WitnessCount:            21,
		DeployContractMinVolume: 1000,
		FloatingCycle:           1,
	}

	args.SuperNodes = make([]*TokenDistribution, 0)
	if cfg.SuperNodes != nil && len(cfg.SuperNodes) > 0 {
		args.SuperNodes = cfg.SuperNodes
	}

	args.Variables = make([]*Property, 0)
	tempArr := make([]string, 0)
	for key, value := range cfg.EngineFactors {
		switch key {
		case "block_interval":
			args.BlockInterval = uint32(value.(int))
			sysConfig.BlockInterval = int32(value.(int))
		case "super_node_count":
			args.SuperNodeCount = uint32(value.(int))
			sysConfig.SuperNodeCount = int32(value.(int))
		case "witness_count":
			args.WitnessCount = uint32(value.(int))
			sysConfig.WitnessCount = int32(value.(int))
		case "floating_cycle":
			args.FloatingCycle = uint32(value.(int))
			sysConfig.FloatingCycle = int32(value.(int))
		case "per_contract_tx_fee":
			args.PerContractTxFee = uint64(value.(int))
			sysConfig.ContractTxFee = big.NewInt(int64(value.(int))).Bytes()
		case "deploy_contract_min_volume":
			args.DeployContractMinVolume = uint32(value.(int))
			sysConfig.DeployContractMinVolume = int32(value.(int))
		default:
			tempArr = append(tempArr, key)
		}
	}
	if len(tempArr) > 0 {
		sort.Strings(tempArr)
		for _, key := range tempArr {
			args.Variables = append(args.Variables, &Property{Name: key, Value: cfg.EngineFactors[key]})
		}
	}

	data, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}

	deployHandler, err := NewDeployHandler(sysSrc, SourceTypeJavaScript, "[\"system_contract\",\""+cfg.FirstAccount+"\","+string(data)+"]", DefaultAuthFlag)
	if err != nil {
		return nil, err
	}

	bytesHandler, err := deployHandler.ToBytes()
	if err != nil {
		return nil, err
	}

	// deploy tx
	deployTx, err := NewTransaction(chain.ChainId(), addr, addr, big.NewInt(1000000000), 1, PriorityNormal, ContractDeployTx, bytesHandler, "", big.NewInt(50000), chainConfig)
	if err != nil {
		return nil, err
	}
	deployTx.timestamp = GenesisTimestamp
	deployHash, err := deployTx.CalcHash()
	if err != nil {
		return nil, err
	}
	deployTx.hash = deployHash

	//// store export data
	contractAddr, err := deployTx.GenerateContractAddress()
	if err != nil {
		return nil, err
	}

	genesisAcc, _ := genesisBlock.worldState.GetOrCreateAccount(GenesisCoinbase.Bytes())
	genesisAcc.AddBalance(big.NewInt(10000000000))
	sysContractAcc, _ := genesisBlock.worldState.GetOrCreateAccount(addr.Bytes())
	sysContractAcc.AddBalance(big.NewInt(10000000000))

	// transfer tx
	declaration := fmt.Sprintf("%s\n%s\n", "hello", "This is the genesis of \"Grand Treasunse\".")
	handler, err := NewNormalHandler([]byte(declaration)).ToBytes()
	if err != nil {
		return nil, err
	}
	genesisTx, err := NewTransaction(chain.ChainId(), GenesisCoinbase, GenesisCoinbase, big.NewInt(1), 1, PriorityNormal, NormalTx, handler, declaration, big.NewInt(22000), chainConfig)
	if err != nil {
		return nil, err
	}
	genesisTx.timestamp = GenesisTimestamp
	hash, err := genesisTx.CalcHash()
	if err != nil {
		return nil, err
	}
	genesisTx.hash = hash

	genesisBlock.transactions = append(genesisBlock.transactions, genesisTx)

	genesisBlock.transactions = append(genesisBlock.transactions, deployTx)

	logging.VLog().WithFields(logrus.Fields{
		"tx": "exc",
	}).Info("exe tx")
	for _, tx := range genesisBlock.transactions {
		txws, err := genesisBlock.WorldState().Prepare(tx.Hash().String())
		if err != nil {
			return nil, err
		}

		if _, err := genesisBlock.ExecuteTransaction(tx, txws, chainConfig); err != nil {
			return nil, err
		}

		if _, err := txws.CheckAndUpdate(); err != nil {
			return nil, err
		}
	}

	// get super nodes
	superNodes, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getSuperNodes", "")
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
			token := &TokenDistribution{
				Address: items[0],
				Value:   items[1],
			}
			if err := processingDistributionFund(token, genesisBlock, true); err != nil {
				genesisBlock.RollBack()
				return nil, err
			}
		}
	}
	sort.Strings(superKeys)
	for _, key := range superKeys {
		sysConfig.SuperNodes = append(sysConfig.SuperNodes, &corepb.Node{
			Address: key,
			Fund:    superNodesMap[key],
		})
	}

	// get block interval
	resSimulateInterval, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getBlockInterval", "")
	if err != nil {
		return nil, err
	}
	resInterval := resSimulateInterval.Msg
	interval, err := strconv.Atoi(resInterval)
	if err != nil {
		return nil, err
	}
	sysConfig.BlockInterval = int32(interval / 1000)

	// get witness num
	resSimulateWitNum, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getWitnessCount", "")
	if err != nil {
		return nil, err
	}
	resWitNum := resSimulateWitNum.Msg
	witNum, err := strconv.Atoi(resWitNum)
	if err != nil {
		return nil, err
	}
	sysConfig.WitnessCount = int32(witNum)
	//psec.witnessNum = witNum

	// get deploy contract min volume
	resSimulateVolume, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getDeployContractMinVolume", "")
	if err != nil {
		return nil, err
	}
	resVolume := resSimulateVolume.Msg
	volume, err := strconv.Atoi(resVolume)
	if err != nil {
		return nil, err
	}
	sysConfig.DeployContractMinVolume = int32(volume)

	// get per contract tx fee
	resSimulateTxFee, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getPerContractTxFee", "")
	if err != nil {
		return nil, err
	}
	resTxFee := strings.ReplaceAll(resSimulateTxFee.Msg, "\"", "")
	txFee, err := strconv.Atoi(resTxFee)
	if err != nil {
		return nil, err
	}
	sysConfig.ContractTxFee = big.NewInt(int64(txFee)).Bytes()

	// get floating cycle
	resSimulateFloatingCycle, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getFloatingCycle", "")
	if err != nil {
		return nil, err
	}
	resFloatingCycle := resSimulateFloatingCycle.Msg
	floatingCycle, err := strconv.Atoi(resFloatingCycle)
	if err != nil {
		return nil, err
	}
	sysConfig.FloatingCycle = int32(floatingCycle)

	// get min pledge
	resSimulateMinPledge, err := chain.simulateGenesisTransactionExecution(contractAddr, genesisBlock, "getVariables", "[\"min_pledge\"]")
	if err != nil {
		return nil, err
	}
	resMinPledge := strings.ReplaceAll(resSimulateMinPledge.Msg, "\"", "")
	if len(resMinPledge) > 0 {
		minPledge, err := strconv.Atoi(resMinPledge)
		if err != nil {
			return nil, err
		}
		sysConfig.MinPledge = big.NewInt(int64(minPledge)).Bytes()
	}

	members := make([]*corepb.Member, 0)
	if cfg.GenesisCouncil != nil && len(cfg.GenesisCouncil) > 0 {
		for _, councilMember := range cfg.GenesisCouncil {
			member := &corepb.Member{
				Address: councilMember.Address,
				PeerId:  councilMember.PeerId,
			}
			pledgeFund := big.NewInt(0)
			if len(councilMember.PledgeFund) > 0 {
				pledgeFund, err = CUintStringToNcUintBigInt(councilMember.PledgeFund)
				if err != nil {
					return nil, err
				}
			}
			member.PledgeFund = pledgeFund.Bytes()
			members = append(members, member)
		}
	}
	genesisCouncil := &corepb.GenesisCouncil{
		Members: members,
	}

	consensusState, err := chain.consensus.GenesisConsensusState(chain, sysConfig, genesisCouncil)
	if err != nil {
		return nil, err
	}
	genesisBlock.worldState.SetConsensusState(consensusState)

	genesisBlock.Commit()

	genesisBlock.header.stateRoot = genesisBlock.WorldState().AccountsRoot()
	genesisBlock.header.txsRoot = genesisBlock.WorldState().TxsRoot()
	genesisBlock.header.eventsRoot = genesisBlock.WorldState().EventsRoot()
	pbCRoot, err := proto.Marshal(genesisBlock.WorldState().ConsensusRoot())
	if err != nil {
		return nil, err
	}
	genesisBlock.header.consensusRoot = pbCRoot

	hash, err = genesisBlock.calcHash()
	if err != nil {
		return nil, err
	}
	genesisBlock.header.hash = hash

	genesisBlock.sealed = true

	return genesisBlock, nil
}

func processingDistributionFund(token *TokenDistribution, gBlock *Block, frozen bool) error {
	addr, err := AddressParse(token.Address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"address": token.Address,
			"err":     err,
		}).Error("Found invalid address in genesis")
		return err
	}
	acc, err := gBlock.worldState.GetOrCreateAccount(addr.address)
	if err != nil {
		return err
	}
	balance, status := new(big.Int).SetString(token.Value, 10)
	if !status {
		return ErrInvalidAmount
	}

	if frozen {
		err = acc.AddFrozenFund(balance)
	} else {
		err = acc.AddBalance(balance)
	}

	if err != nil {
		return err
	}

	return nil
}
