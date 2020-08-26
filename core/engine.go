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
	consensuspb "gt.pro/gtio/go-gt/consensus/pb"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/config"
	"math/big"
	"time"
)

// ConsensusEngine
type Consensus interface {
	Setup(gt Gt) error
	Start()
	Stop()
	EnableMining(passphrase string) error
	DisableMining() error
	IsEnable() bool

	ResumeMining()
	SuspendMining()
	IsSuspend() bool
	NewBlock(tail *Block, deadline int64, mineTime int64) (*Block, error)
	VerifyBlock(parent *Block, block *Block) error
	CheckDoubleMint(block *Block) bool
	HandleFork() error
	UpdateFixedBlock()
	Coinbase() *Address

	NewState(*consensuspb.ConsensusRoot, cdb.Storage, bool) (state.ConsensusState, error)
	GenesisConsensusState(chain *BlockChain, sysConfig *corepb.SystemConfig, genesisCouncil *corepb.GenesisCouncil) (state.ConsensusState, error)
}

// Synchronize interface of sync service
type Synchronize interface {
	Start()
	Stop()
	StartActiveSync() bool
	StopActiveSync()
	WaitingForFinish()
	IsActiveSyncing() bool
}

type AccountManager interface {
	NewAccount(passphrase []byte) (*Address, string, error)
	UpdateAccount(address *Address, oldPassphrase, newPassphrase []byte) error
	GetAllAddress() []*Address
	AddressIsValid(address string) (*Address, error)
	UnLock(address *Address, passphrase []byte, duration time.Duration) error
	Lock(address *Address) error
	ImportAccount(priKey, passphrase []byte) (*Address, error)
	GetPrivateKey(address *Address, passphrase []byte) ([]byte, error)
	Sign(address *Address, hash []byte) ([]byte, error)
	SignBlock(address *Address, block *Block) error
	SignTx(addr *Address, tx *Transaction) error
	SignTxWithPassphrase(*Address, *Transaction, []byte) error
	Verify(addr *Address, message, sig []byte) (bool, error)
	Stop()
	GenerateRandomSeed(*Address, []byte, []byte) ([]byte, []byte, error)
}

type Gt interface {
	BlockChain() *BlockChain
	NetService() network.Service
	AccountManager() AccountManager
	Consensus() Consensus
	Config() *config.Config
	Storage() cdb.Storage
	EventEmitter() *EventEmitter
	Cvm() CVM
	Stop()
}

type TxHandler interface {
	ToBytes() ([]byte, error)
	BaseGasCount() *big.Int
	Before(tx *Transaction, block *Block, ws WorldState, chainConfig *ChainConfig) error
	Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error)
	After(tx *Transaction, block *Block, ws WorldState, chainConfig *ChainConfig, result string) error
}

//
type CVM interface {
	CreateEngine(block *Block, tx *Transaction, contract state.Account, ws WorldState) (ContractEngine, error)
}

//
type ContractEngine interface {
	SetExecutionLimits(uint64, uint64) error
	DeployAndInit(source, args string) (string, error)
	Call(source, function, args string) (string, error)
	ExecutionInstructions() uint64
	Dispose()
}

// WorldState needed by core
type WorldState interface {
	GetOrCreateAccount(addr byteutils.Hash) (state.Account, error)
	GetContractAccount(addr byteutils.Hash) (state.Account, error)
	CreateContractAccount(owner byteutils.Hash, birthTxHash byteutils.Hash, version string) (state.Account, error)

	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	RecordGas(from string, gas *big.Int)

	Reset(addr byteutils.Hash, isResetChangeLog bool) error

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)

	GetCouncil(termId uint64) (*corepb.Council, error)

	JoinElection(joinInfo byteutils.Hash) error
	CancelElection(byteutils.Hash) error
	RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error

	RecordEvent(txHash byteutils.Hash, event *state.Event)
	FetchEvents(byteutils.Hash) ([]*state.Event, error)
}
