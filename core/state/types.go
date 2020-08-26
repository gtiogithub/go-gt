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
package state

import (
	"errors"
	"math/big"

	consensuspb "gt.pro/gtio/go-gt/consensus/pb"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/byteutils"
)

// Errors
var (
	ErrBalanceInsufficient     = errors.New("cannot subtract a value which is bigger than current balance")
	ErrFrozenFundInsufficient  = errors.New("cannot subtract a value which is bigger than frozen fund")
	ErrPledgeFundInsufficient  = errors.New("cannot subtract a value which is bigger than pledge fund")
	ErrAccountNotFound         = errors.New("cannot found account in storage")
	ErrContractAccountNotFound = errors.New("cannot found contract account in storage")
	ErrContractCheckFailed     = errors.New("contract check failed")
	ErrInvalidAccountState     = errors.New("invalid account state")
	ErrChangeAccountState      = errors.New("invalid change account state")
	ErrInvalidCommand          = errors.New("invalid command")
	ErrInvalidAuthorizeType    = errors.New("invalid authorize type")
)

type Event struct {
	Topic string
	Data  string
}

//ElectionEvent the event of vote election event
type ElectionEvent struct {
	Address    string   `json:"address"`
	Hashes     []string `json:"hashes"`
	Selected   int8     `json:"selected"`
	Role       string   `json:"role"`
	PledgeFund string   `json:"pledge_fund"`
	Score      int64    `json:"score"`
}

type VoteEvent struct {
	Address    string `json:"address"`
	PledgeFund string `json:"pledge_fund"`
	Status     string `json:"status"`
	Cause      string `json:"cause"`
}

type DoEvilEvent struct {
	Malefactor    string `json:"malefactor"`
	EvilType      string `json:"evil_type"`
	PenaltyAmount string `json:"penalty_amount"`
	Timestamp     int64  `json:"timestamp"`
}

type ReportRewardEvent struct {
	Prosecutor string `json:"prosecutor"`
	Timestamp  int64  `json:"timestamp"`
	Malefactor string `json:"malefactor"`
	Amount     string `json:"amount"`
}

type InheritMetaInfo struct {
	// 是否可被继承
	Inheritable bool `json:"inheritable"`
	// 继承字段（变量名称）
	InheritField string `json:"inheritField"`
	// 本身字段名称
	Field string `json:"field"`
	// 被继承字段
	InheritedField []string `json:"inheritedField"`
}

type JoinElectionInfo struct {
	PeerId        string
	Address       string
	JoinHeight    uint64
	ExpiryHeight  uint64
	RelieveHeight uint64
	PledgeFund    string
	TxHash        string
}

type CancelElectionInfo struct {
	Address string
	TxHash  string
}

type ChangeStateInfo struct {
	Height        uint64
	Timestamp     int64
	Miner         string
	NormalTxCnt   uint64
	ContractTxCnt uint64
	Participators map[string]string
}

// Iterator Variables in Account Storage
type Iterator interface {
	Next() (bool, error)
	Value() []byte
	Key() []byte
}

// Account Interface
type Account interface {
	Address() byteutils.Hash
	Balance() *big.Int
	FrozenFund() *big.Int
	PledgeFund() *big.Int
	Nonce() uint64
	CreditIndex() *big.Int
	Permissions() []*corepb.Permission
	Copy() (Account, error)

	ToBytes() ([]byte, error)
	FromBytes(bytes []byte, storage cdb.Storage) error
	IncreaseNonce()
	TxsCount() uint64
	Evil() uint64
	SetEvil(uint64)
	PutTx(txTash []byte) error
	GetTx(key []byte) ([]byte, error)
	AddBalance(value *big.Int) error
	SubBalance(value *big.Int) error
	AddFrozenFund(value *big.Int) error
	SubFrozenFund(value *big.Int) error
	AddPledgeFund(value *big.Int) error
	SubPledgeFund(value *big.Int) error
	SetCreditIndex(value *big.Int) error
	SubCreditIndex(value *big.Int) error
	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	Iterator(prefix []byte) (Iterator, error)

	ModifyPermission(command, address, function, rule string) error
	CheckPermission(command, address, function string) (bool, error)
	GetPermission(authType, key string) ([]byte, error)
	GetContractFuncList() ([]string, error)
	// contract
	Closed() bool
	State() int32
	SetState(int32) error
	BirthTransaction() byteutils.Hash
	VarsHash() byteutils.Hash
	ContractVersion() string

	IncreaseIntegral(termId uint64, integralType string) error
	CreditIntegral(termId uint64) *corepb.CreditIntegral

	IncreaseContractIntegral(address string, height uint64) error
	ContractIntegral() []*corepb.ContractIntegral
	GetStorage() cdb.Storage
}

// AccountState Interface
type AccountState interface {
	RootHash() byteutils.Hash
	Flush() error
	Abort() error
	DirtyAccounts() ([]Account, error)
	Accounts() ([]Account, error)
	Copy() (AccountState, error)
	Replay(AccountState) error

	GetOrCreateAccount(byteutils.Hash) (Account, error)
	GetContractAccount(byteutils.Hash) (Account, error)
	CreateContractAccount(byteutils.Hash, byteutils.Hash, string) (Account, error)
}

// Consensus interface
type Consensus interface {
	NewState(*consensuspb.ConsensusRoot, cdb.Storage, bool) (ConsensusState, error)
}

// ConsensusState interface of consensus state
type ConsensusState interface {
	RootHash() *consensuspb.ConsensusRoot
	String() string
	Clone() (ConsensusState, error)
	Replay(ConsensusState) error

	NextConsensusState(info []byte, ws WorldState) (ConsensusState, []*ElectionEvent, error)
	FetchElectionEvent(txHash byteutils.Hash) (*ElectionEvent, error)
	//Period() (*corepb.Period, error)
	GetCouncil(termId uint64) (*corepb.Council, error)
	//PeriodRoot() byteutils.Hash

	JoinElection(joinInfo byteutils.Hash) error
	CancelElection(byteutils.Hash) error
	RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error
}

// WorldState interface of world state
type WorldState interface {
	Begin() error
	Commit() error
	RollBack() error

	Prepare(interface{}) (TxWorldState, error)
	Reset(addr byteutils.Hash, isResetChangeLog bool) error
	Flush() error
	Abort() error

	LoadAccountsRoot(byteutils.Hash) error
	LoadTxsRoot(byteutils.Hash) error
	LoadConsensusRoot(*consensuspb.ConsensusRoot) error
	LoadEventsRoot(root byteutils.Hash) error

	NextConsensusState(info []byte) (ConsensusState, []*ElectionEvent, error)
	SetConsensusState(ConsensusState)

	Copy() (WorldState, error)
	AccountsRoot() byteutils.Hash
	TxsRoot() byteutils.Hash
	Accounts() ([]Account, error)
	GetOrCreateAccount(addr byteutils.Hash) (Account, error)
	GetContractAccount(byteutils.Hash) (Account, error)
	CreateContractAccount(byteutils.Hash, byteutils.Hash, string) (Account, error)

	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	ConsensusRoot() *consensuspb.ConsensusRoot

	FetchElectionEvent(txHash byteutils.Hash) (*ElectionEvent, error)
	GetCouncil(termId uint64) (*corepb.Council, error)

	//WitnessRoot() byteutils.Hash
	//GetWitnesses(uint64) ([]*corepb.Group, error)
	//PutWitnesses(*corepb.WitnessState) error

	JoinElection(joinInfo byteutils.Hash) error
	CancelElection(byteutils.Hash) error
	RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)

	EventsRoot() byteutils.Hash
	RecordEvent(txHash byteutils.Hash, event *Event)
	FetchEvents(byteutils.Hash) ([]*Event, error)

	RecordGas(from string, gas *big.Int)
	GetGas() map[string]*big.Int
}

// TxWorldState is the world state of a single transaction
type TxWorldState interface {
	AccountsRoot() byteutils.Hash
	TxsRoot() byteutils.Hash

	CheckAndUpdate() ([]interface{}, error)
	Reset(addr byteutils.Hash, isResetChangeLog bool) error
	Close() error

	Accounts() ([]Account, error)
	GetOrCreateAccount(addr byteutils.Hash) (Account, error)
	GetContractAccount(byteutils.Hash) (Account, error)
	CreateContractAccount(byteutils.Hash, byteutils.Hash, string) (Account, error)

	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	//Witnesses() ([]byteutils.Hash, error)
	//WitnessRoot() byteutils.Hash
	JoinElection(joinInfo byteutils.Hash) error
	CancelElection(byteutils.Hash) error
	RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error
	GetCouncil(termId uint64) (*corepb.Council, error)

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)

	RecordGas(from string, gas *big.Int)
	RecordEvent(txHash byteutils.Hash, event *Event)
	FetchEvents(byteutils.Hash) ([]*Event, error)
}
