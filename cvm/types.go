// Copyright (C) 2018 go-gt authors
//
// This file is part of the go-gt library.
//
// the go-gt library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of t1he License, or
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
package cvm

import (
	"errors"
	"math/big"

	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/byteutils"
)

const (
	DeploySucceed      = "DeploySucceed"
	DeployFailed       = "DeployFailed"
	CallContractFailed = "CallContractFailed"
)

//the max recent block number can query
const (
	maxQueryBlockInfoValidTime = 30
	maxBlockOffset             = maxQueryBlockInfoValidTime * 24 * 3600 * 1000 / 5000
)

//inner cvm
const (
	MaxInnerContractLevel = 3
)

//transfer err code enum
const (
	SuccessTransferFunc = iota
	SuccessTransfer
	ErrTransferGetEngine
	ErrTransferAddressParse
	ErrTransferGetAccount
	ErrTransferStringToBigInt
	ErrTransferInsufficientAmount
	ErrTransferSubBalance
	ErrTransferAddBalance
	ErrTransferRecordEvent
	ErrTransferAddress
)

// define gas consume
const (
	// crypto
	CryptoSha256GasBase         = 20000
	CryptoSha3256GasBase        = 20000
	CryptoRipemd160GasBase      = 20000
	CryptoRecoverAddressGasBase = 100000
	CryptoMd5GasBase            = 6000
	CryptoBase64GasBase         = 3000

	//In blockChain
	GetTxByHashGasBase     = 1000
	GetAccountStateGasBase = 2000
	TransferGasBase        = 2000
	VerifyAddressGasBase   = 100
	GetPreBlockHashGasBase = 2000
	GetPreBlockSeedGasBase = 2000

	//inner nvm
	GetContractSourceGasBase = 5000
	InnerContractGasBase     = 32000

	//random
	GetTxRandomGasBase = 1000

	//nr
	GetLatestGtRankGasBase        = 20000
	GetLatestGtRankSummaryGasBase = 20000
)

//define
const (
	EventNameSpaceContract    = "chain.contract" //ToRefine: move to core
	InnerTransactionErrPrefix = "inner transation err ["
	InnerTransactionResult    = "] result ["
	InnerTransactionErrEnding = "] engine index:%v"
)

//common err
var (
	ErrKeyNotFound = cdb.ErrKeyNotFound
)

var (
	ErrContextConstructArrEmpty = errors.New("context construct err by args empty")
	ErrNewCVMConfigWithCode     = errors.New("new cvm config error")
	ErrNewCVMWithConfig         = errors.New("new cvm with config error")
	ErrCompileContract          = errors.New("compile contract error")
	ErrSourceCodeIsEmpty        = errors.New("source code is empty")
	ErrInvalidArgument          = errors.New("invalid argument")

	ErrArgumentsFormat                = errors.New("arguments format error")
	ErrInjectTracingInstructionFailed = errors.New("inject tracing instructions failed")
	ErrLimitHasEmpty                  = errors.New("limit args has empty")
	ErrSetMemorySmall                 = errors.New("set memory small than v8 limit")

	ErrExecutionTimeout = errors.New("execution timeout")

	ErrInsufficientGas    = errors.New("insufficient gas")
	ErrExceedMemoryLimits = errors.New("exceed memory limits")

	ErrDisallowCallNotStandardFunction = errors.New("disallow call not standard function")
	ErrDisallowCallPrivateFunction     = errors.New("disallow call private function")

	ErrEngineNotFound = errors.New("Failed to get engine")

	ErrMaxInnerContractLevelLimit = errors.New("out of limit cvm count")
	ErrInnerTransferFailed        = errors.New("inner transfer failed")
	ErrInnerInsufficientGas       = errors.New("preparation inner cvm insufficient gas")
	ErrInnerInsufficientMem       = errors.New("preparation inner cvm insufficient mem")
)

//
type Block interface {
	Hash() byteutils.Hash
	Height() uint64
	Timestamp() int64
	ChainId() uint32
	//StoreContractData(key, val []byte)
	//GetContractData(key []byte) ([]byte, error)
}

//
type Transaction interface {
	Hash() byteutils.Hash
	From() *core.Address
	To() *core.Address
	Value() *big.Int
	Nonce() uint64
	Timestamp() int64
	GetData() *corepb.Data
	ChainId() uint32
	Priority() uint32
	GasLimit() *big.Int
	NewInnerTransaction(from, to *core.Address, value *big.Int, handlerType string, handler []byte) (*core.Transaction, error)
}

//
type Account interface {
	Address() byteutils.Hash
	Balance() *big.Int
	FrozenFund() *big.Int
	PledgeFund() *big.Int
	Nonce() uint64

	VarsHash() byteutils.Hash

	AddBalance(value *big.Int) error
	SubBalance(value *big.Int) error
	AddFrozenFund(value *big.Int) error
	SubFrozenFund(value *big.Int) error

	AddPledgeFund(value *big.Int) error
	SubPledgeFund(value *big.Int) error

	SetCreditIndex(value *big.Int) error
	SubCreditIndex(value *big.Int) error

	BirthTransaction() byteutils.Hash
	ContractVersion() string
	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error

	Closed() bool
	SetState(int32) error
	GetStorage() cdb.Storage
}

//
type WorldState interface {
	GetOrCreateAccount(addr byteutils.Hash) (state.Account, error)
	GetContractAccount(addr byteutils.Hash) (state.Account, error)
	CreateContractAccount(owner byteutils.Hash, birthTxHash byteutils.Hash, version string) (state.Account, error)

	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)

	GetCouncil(termId uint64) (*corepb.Council, error)

	JoinElection(joinInfo byteutils.Hash) error
	CancelElection(byteutils.Hash) error
	RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error

	RecordEvent(txHash byteutils.Hash, event *state.Event)
	FetchEvents(byteutils.Hash) ([]*state.Event, error)
	Reset(addr byteutils.Hash, isResetChangeLog bool) error

	RecordGas(from string, gas *big.Int)
}

// Handler struct in getPayloadByAddress
type Handler struct {
	deploy   *core.DeployHandler
	contract Account
}
