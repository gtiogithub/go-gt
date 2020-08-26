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
// but WITHOUT ANY WARRANTY; without even the implied warranty ofF
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-gt library.  If not, see <http://www.gnu.org/licenses/>.
//
package state

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"strconv"
	"strings"

	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"github.com/gogo/protobuf/proto"
)

const (
	Normal             = "normal"
	Contract           = "contract"
	Template           = "template"
	DoEvil             = "doEvil"
	CollectBlock       = "collectBlock"
	AuthFunCategory    = "1"
	AuthRoleCategory   = "2"
	AuthCustomCategory = "3"

	ContractVariableMeta_Prefix = "@CTVM:"
	ContractVariable_Prefix     = "@CTVD:"
	ContractMeta_Prefix         = "@CTM:"
	ContractFCA                 = "FCA"
	ContractFunList             = "FunList"
)

const (
	AddCommand    = "add"
	ModifyCommand = "modify"
	DelCommand    = "del"

	FuncAuthType = "0"
	RoleAuthType = "1"

	DefaultAuthType = FuncAuthType

	FuncForbidRule = "0"
	FuncAllowRule  = "1"

	FuzzyAuthorize = "*"

	RoleAddRule             = "1"
	RoleModifyRule          = "2"
	RoleDelRule             = "4"
	RoleAddAndModifyRule    = "3"
	RoleAddAndDelRule       = "5"
	RoleModifyAndDelRule    = "6"
	RoleAddModifyAndDelRule = "7"
)

const (
	AccountStateRunning int32 = 0
	AccountStateFix     int32 = 1
	AccountStateClosed  int32 = 2
)

type CreditIntegral struct {
	normal       uint64
	contract     uint64
	template     uint64
	doEvil       uint64
	collectBlock uint64
}

type ContractIntegral struct {
	createdHeight   uint64
	contractTxCount *big.Int
}

// account info in state Trie
type account struct {
	address byteutils.Hash
	nonce   uint64
	//doEvils          uint32
	//products         uint32
	balance          *big.Int
	frozenFund       *big.Int
	pledgeFund       *big.Int
	creditIndex      *big.Int
	birthTxHash      byteutils.Hash
	state            int32
	child            byteutils.Hash //
	contractVersion  string
	variables        *trie.Trie
	permissions      []*corepb.Permission
	integral         map[uint64]*CreditIntegral
	contractIntegral map[string]*ContractIntegral

	//contract authority
	contractFunAuths   *trie.Trie
	contractRoles      *trie.Trie
	contractCustomData *trie.Trie

	txsCount uint64
	txTrie   *trie.Trie

	evil uint64
	// structure trie.Trie need cdb.Storage
	storage cdb.Storage
}

// ToBytes converts domain Account to bytes
func (acc *account) ToBytes() ([]byte, error) {
	pbAccount := &corepb.Account{
		Address:            acc.address,
		Balance:            acc.balance.Bytes(),
		FrozenFund:         acc.frozenFund.Bytes(),
		PledgeFund:         acc.pledgeFund.Bytes(),
		Nonce:              acc.nonce,
		State:              acc.state,
		VarsHash:           acc.variables.RootHash(),
		CreditIndex:        acc.creditIndex.Bytes(),
		CreatedTransaction: acc.birthTxHash,
		ContractVersion:    acc.contractVersion,
		Permissions:        make([]*corepb.Permission, 0),
		Integral:           make([]*corepb.CreditIntegral, 0),
		HoldContract:       make([]*corepb.ContractIntegral, 0),
		TxsHash:            acc.txTrie.RootHash(),
		TxCount:            acc.txsCount,
		Evil:               acc.evil,
	}
	if acc.integral != nil {
		var keys []int
		for key := range acc.integral {
			keys = append(keys, int(key))
		}
		sort.Ints(keys)
		for _, key := range keys {
			u64Key := uint64(key)
			pbAccount.Integral = append(pbAccount.Integral, &corepb.CreditIntegral{
				TermId:       u64Key,
				Normal:       acc.integral[u64Key].normal,
				Contract:     acc.integral[u64Key].contract,
				Template:     acc.integral[u64Key].template,
				DoEvil:       acc.integral[u64Key].doEvil,
				CollectBlock: acc.integral[u64Key].collectBlock,
			})
		}
	}

	if acc.contractIntegral != nil {
		var keys []string
		for key := range acc.contractIntegral {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			pbAccount.HoldContract = append(pbAccount.HoldContract, &corepb.ContractIntegral{
				Address:         key,
				CreatedHeight:   acc.contractIntegral[key].createdHeight,
				ContractTxCount: acc.contractIntegral[key].contractTxCount.Bytes(),
			})
		}
	}

	funPermission := &corepb.Permission{
		AuthCategory: AuthFunCategory,
		AuthMessage:  make([][]byte, 0),
	}
	funPermission.AuthMessage = append(funPermission.AuthMessage, acc.contractFunAuths.RootHash())
	pbAccount.Permissions = append(pbAccount.Permissions, funPermission)

	rolePermission := &corepb.Permission{
		AuthCategory: AuthRoleCategory,
		AuthMessage:  make([][]byte, 0),
	}
	rolePermission.AuthMessage = append(rolePermission.AuthMessage, acc.contractRoles.RootHash())
	pbAccount.Permissions = append(pbAccount.Permissions, rolePermission)

	customPermission := &corepb.Permission{
		AuthCategory: AuthCustomCategory,
		AuthMessage:  make([][]byte, 0),
	}
	customPermission.AuthMessage = append(customPermission.AuthMessage, acc.contractCustomData.RootHash())
	pbAccount.Permissions = append(pbAccount.Permissions, customPermission)

	bytes, err := proto.Marshal(pbAccount)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// FromBytes converts bytes to Account
func (acc *account) FromBytes(bytes []byte, storage cdb.Storage) error {
	pbAccount := &corepb.Account{}
	var err error
	if err = proto.Unmarshal(bytes, pbAccount); err != nil {
		return err
	}
	acc.address = pbAccount.Address
	acc.balance = new(big.Int).SetBytes(pbAccount.Balance)
	acc.frozenFund = new(big.Int).SetBytes(pbAccount.FrozenFund)
	acc.pledgeFund = new(big.Int).SetBytes(pbAccount.PledgeFund)
	acc.state = pbAccount.State
	acc.nonce = pbAccount.Nonce
	acc.birthTxHash = pbAccount.CreatedTransaction
	acc.contractVersion = pbAccount.ContractVersion
	//acc.permissions = pbAccount.Permissions
	acc.integral = make(map[uint64]*CreditIntegral)
	if pbAccount.Integral != nil && len(pbAccount.Integral) > 0 {
		for _, entity := range pbAccount.Integral {
			acc.integral[entity.TermId] = &CreditIntegral{
				normal:       entity.Normal,
				contract:     entity.Contract,
				template:     entity.Template,
				doEvil:       entity.DoEvil,
				collectBlock: entity.CollectBlock,
			}
		}
	}
	acc.contractIntegral = make(map[string]*ContractIntegral)
	if pbAccount.HoldContract != nil && len(pbAccount.HoldContract) > 0 {
		for _, entity := range pbAccount.HoldContract {
			acc.contractIntegral[entity.Address] = &ContractIntegral{
				createdHeight:   entity.CreatedHeight,
				contractTxCount: new(big.Int).SetBytes(entity.ContractTxCount),
			}
		}
	}

	if acc.contractFunAuths, err = trie.NewTrie(pbAccount.Permissions[0].AuthMessage[0], storage, false); err != nil {
		return err
	}

	if acc.contractRoles, err = trie.NewTrie(pbAccount.Permissions[1].AuthMessage[0], storage, false); err != nil {
		return err
	}

	if acc.contractCustomData, err = trie.NewTrie(pbAccount.Permissions[2].AuthMessage[0], storage, false); err != nil {
		return err
	}

	if acc.variables, err = trie.NewTrie(pbAccount.VarsHash, storage, false); err != nil {
		return err
	}
	acc.creditIndex = new(big.Int).SetBytes(pbAccount.CreditIndex)

	if acc.txTrie, err = trie.NewTrie(pbAccount.TxsHash, storage, false); err != nil {
		return err
	}

	acc.txsCount = pbAccount.TxCount
	acc.evil = pbAccount.Evil
	acc.storage = storage
	return nil
}

// return whether the (contract) account is closed
func (acc *account) Closed() bool {
	return acc.state == AccountStateClosed
}

// State return account's state
func (acc *account) State() int32 {
	return acc.state
}

func (acc *account) Child() byteutils.Hash {
	return acc.child
}

// Address return account's address.
func (acc *account) Address() byteutils.Hash {
	return acc.address
}

// Balance return account's balance.
func (acc *account) Balance() *big.Int {
	return acc.balance
}

// FrozenFund return account's frozen fund.
func (acc *account) FrozenFund() *big.Int {
	return acc.frozenFund
}

// PledgeFund return account's pledge fund.
func (acc *account) PledgeFund() *big.Int {
	return acc.pledgeFund
}

// Nonce return account's nonce.
func (acc *account) Nonce() uint64 {
	return acc.nonce
}

// Iterator map var from account's storage.
func (acc *account) Iterator(prefix []byte) (Iterator, error) {
	return acc.variables.Iterator(prefix)
}

//
func (acc *account) ContractVersion() string {
	return acc.contractVersion
}

// return contract's deploy transaction
func (acc *account) BirthTransaction() byteutils.Hash {
	return acc.birthTxHash
}

// CreditIndex return account's credit index.
func (acc *account) CreditIndex() *big.Int {
	return acc.creditIndex
}

// VarsHash return account's variables hash.
func (acc *account) VarsHash() byteutils.Hash {
	return acc.variables.RootHash()
}

// Permissions return account's permissions.
func (acc *account) Permissions() []*corepb.Permission {
	return acc.permissions
}

// IncreaseNonce increases nonce by 1.
func (acc *account) IncreaseNonce() {
	acc.nonce++
}

func (acc *account) TxsCount() uint64 {
	return acc.txsCount
}

func (acc *account) Evil() uint64 {
	return acc.evil
}

func (acc *account) SetEvil(termId uint64) {
	if acc.evil < termId {
		acc.evil = termId
	}
}

// Copy copies account.
func (acc *account) Copy() (Account, error) {
	variables, err := acc.variables.Clone()
	if err != nil {
		return nil, err
	}

	contractFunAuths, err := acc.contractFunAuths.Clone()
	if err != nil {
		return nil, err
	}

	contractRoles, err := acc.contractRoles.Clone()
	if err != nil {
		return nil, err
	}

	contractCustomData, err := acc.contractCustomData.Clone()
	if err != nil {
		return nil, err
	}

	txTrie, err := acc.txTrie.Clone()
	if err != nil {
		return nil, err
	}
	return &account{
		address:     acc.address,
		balance:     acc.balance,
		frozenFund:  acc.frozenFund,
		pledgeFund:  acc.pledgeFund,
		creditIndex: acc.creditIndex,
		nonce:       acc.nonce,
		variables:   variables,
		//permissions:      acc.permissions,
		state:              acc.state,
		integral:           acc.integral,
		contractIntegral:   acc.contractIntegral,
		contractFunAuths:   contractFunAuths,
		contractRoles:      contractRoles,
		contractCustomData: contractCustomData,
		txTrie:             txTrie,
		txsCount:           acc.txsCount,
		evil:               acc.evil,
	}, nil

}

// set account's closed
func (acc *account) SetState(flag int32) (err error) {
	if flag == int32(AccountStateRunning) ||
		flag == int32(AccountStateFix) ||
		flag == int32(AccountStateClosed) {
		acc.state = flag
		return
	}
	err = ErrInvalidAccountState
	return
}

// AddBalance adds balance to an account.
func (acc *account) AddBalance(value *big.Int) error {
	balance := new(big.Int).Add(acc.balance, value)
	acc.balance = balance
	return nil
}

// SubBalance subtracts balance to an account.
func (acc *account) SubBalance(value *big.Int) error {
	if acc.balance.Cmp(value) < 0 {
		return ErrBalanceInsufficient
	}
	balance := new(big.Int).Sub(acc.balance, value)
	acc.balance = balance
	return nil
}

// AddFrozenFund freezes funds to an account.
func (acc *account) AddFrozenFund(value *big.Int) error {
	frozenFund := new(big.Int).Add(acc.frozenFund, value)
	acc.frozenFund = frozenFund
	return nil
}

// SubFrozenFund subtracts frozen funds to an account.
func (acc *account) SubFrozenFund(value *big.Int) error {
	if acc.frozenFund.Cmp(value) < 0 {
		return ErrFrozenFundInsufficient
	}
	frozenFund := new(big.Int).Sub(acc.frozenFund, value)
	acc.frozenFund = frozenFund
	return nil
}

// AddPledgeFund adds pledge funds to an account.
func (acc *account) AddPledgeFund(value *big.Int) error {
	pledgeFund := new(big.Int).Add(acc.pledgeFund, value)
	acc.pledgeFund = pledgeFund
	return nil
}

// SubPledgeFund subtracts pledge funds to an account.
func (acc *account) SubPledgeFund(value *big.Int) error {
	if acc.pledgeFund.Cmp(value) < 0 {
		return ErrPledgeFundInsufficient
	}
	pledgeFund := new(big.Int).Sub(acc.pledgeFund, value)
	acc.pledgeFund = pledgeFund
	return nil
}

// AddCreditIndex adds credit index to an account.
func (acc *account) SetCreditIndex(value *big.Int) error {
	acc.creditIndex = new(big.Int).Add(value, new(big.Int))
	return nil
}

// SubCreditIndex subtracts index to an account.
func (acc *account) SubCreditIndex(value *big.Int) error {
	acc.creditIndex = new(big.Int).Sub(acc.creditIndex, value)
	return nil
}

// Put into account's storage.
func (acc *account) PutTx(txHash []byte) error {
	_, err := acc.txTrie.Put(byteutils.FromUint64(acc.txsCount), txHash)
	acc.txsCount++
	return err
}

// Get from account's storage.
func (acc *account) GetTx(key []byte) ([]byte, error) {
	return acc.txTrie.Get(key)
}

// Put into account's storage.
func (acc *account) Put(key []byte, value []byte) error {
	_, err := acc.variables.Put(key, value)
	return err
}

// Get from account's storage.
func (acc *account) Get(key []byte) ([]byte, error) {
	return acc.variables.Get(key)
}

// Del from account's storage.
func (acc *account) Delete(key []byte) error {
	if _, err := acc.variables.Del(key); err != nil {
		return err
	}
	return nil
}

func (acc *account) IncreaseIntegral(termId uint64, integralType string) error {
	creditIntegral := &CreditIntegral{
		normal:       0,
		contract:     0,
		template:     0,
		doEvil:       0,
		collectBlock: 0,
	}
	if oldIntegral, ok := acc.integral[termId]; ok {
		creditIntegral = oldIntegral
	}
	switch integralType {
	case Normal:
		creditIntegral.normal++
	case Contract:
		creditIntegral.contract++
	case Template:
		creditIntegral.template++
	case DoEvil:
		creditIntegral.doEvil++
	case CollectBlock:
		creditIntegral.collectBlock++
	}
	acc.integral[termId] = creditIntegral
	return nil
}

func (acc *account) CreditIntegral(termId uint64) *corepb.CreditIntegral {

	if integral, ok := acc.integral[termId]; ok {
		return &corepb.CreditIntegral{
			TermId:       termId,
			Normal:       integral.normal,
			Contract:     integral.contract,
			Template:     integral.template,
			DoEvil:       integral.doEvil,
			CollectBlock: integral.collectBlock,
		}
	}
	return &corepb.CreditIntegral{
		TermId:       termId,
		Normal:       0,
		Contract:     0,
		Template:     0,
		DoEvil:       0,
		CollectBlock: 0,
	}
}

func (acc *account) IncreaseContractIntegral(address string, height uint64) error {
	contractIntegral := &ContractIntegral{
		createdHeight:   0,
		contractTxCount: big.NewInt(0),
	}

	if oldIntegral, ok := acc.contractIntegral[address]; ok {
		contractIntegral.createdHeight = oldIntegral.createdHeight
		contractIntegral.contractTxCount = oldIntegral.contractTxCount
	} else {
		contractIntegral.createdHeight = height
	}
	contractIntegral.contractTxCount = new(big.Int).Add(contractIntegral.contractTxCount, big.NewInt(1))
	acc.contractIntegral[address] = contractIntegral
	return nil
}

func (acc *account) ContractIntegral() []*corepb.ContractIntegral {
	if acc.contractIntegral != nil {
		pbIntegral := make([]*corepb.ContractIntegral, 0)
		for key, val := range acc.contractIntegral {
			pbIntegral = append(pbIntegral, &corepb.ContractIntegral{
				Address:         key,
				CreatedHeight:   val.createdHeight,
				ContractTxCount: val.contractTxCount.Bytes(),
			})
		}
		return pbIntegral
	}
	return nil
}

func (acc *account) ModifyPermission(command, address, function, rule string) error {
	commands := strings.Split(command, "_")
	if len(commands) != 2 {
		return ErrInvalidCommand
	}
	switch commands[0] {
	case FuncAuthType:
		switch commands[1] {
		case AddCommand,
			ModifyCommand:
			acc.contractFunAuths.Put([]byte(address+"_"+function), []byte(rule))
		case DelCommand:
			acc.contractFunAuths.Del([]byte(address + "_" + function))
		default:
			return ErrInvalidCommand
		}
	case RoleAuthType:
		switch commands[1] {
		case AddCommand,
			ModifyCommand:
			acc.contractRoles.Put([]byte(address+"_"+function), []byte(rule))
		case DelCommand:
			acc.contractRoles.Del([]byte(address + "_" + function))
		default:
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (acc *account) CheckPermission(command, address, function string) (bool, error) {
	commands := strings.Split(command, "_")
	if len(commands) != 2 {
		return false, ErrInvalidCommand
	}
	if commands[0] == FuncAuthType {
		byteRule, err := acc.contractFunAuths.Get([]byte(FuzzyAuthorize + "_" + FuzzyAuthorize))
		if err != nil && err != cdb.ErrKeyNotFound {
			return false, err
		}

		if byteRule != nil && string(byteRule[:]) == FuncAllowRule {
			return true, nil
		}

		byteRule, err = acc.contractFunAuths.Get([]byte(FuzzyAuthorize + "_" + function))
		if err != nil && err != cdb.ErrKeyNotFound {
			return false, err
		}

		if byteRule != nil && string(byteRule[:]) == FuncAllowRule {
			return true, nil
		}

		byteRule, err = acc.contractFunAuths.Get([]byte(address + "_" + FuzzyAuthorize))
		if err != nil && err != cdb.ErrKeyNotFound {
			return false, err
		}

		if byteRule != nil && string(byteRule[:]) == FuncAllowRule {
			return true, nil
		}

		byteRule, err = acc.contractFunAuths.Get([]byte(address + "_" + function))
		if err != nil && err != cdb.ErrKeyNotFound {
			return false, err
		}

		if byteRule != nil && string(byteRule[:]) == FuncAllowRule {
			return true, nil
		}
	} else if commands[0] == RoleAuthType {
		byteRule, err := acc.contractRoles.Get([]byte(address + "_" + FuzzyAuthorize))
		if err != nil && err != cdb.ErrKeyNotFound {
			return false, err
		}

		if byteRule != nil {
			rule, err := strconv.Atoi(string(byteRule[:]))
			if err != nil {
				return false, err
			}
			switch commands[1] {
			case AddCommand:
				if 1&rule == 1 {
					return true, nil
				}
			case ModifyCommand:
				if 2&rule == 2 {
					return true, nil
				}
			case DelCommand:
				if 4&rule == 4 {
					return true, nil
				}
			default:
				return false, ErrInvalidCommand
			}
		}

		byteRule, err = acc.contractRoles.Get([]byte(address + "_" + function))
		if err != nil && err != cdb.ErrKeyNotFound {
			return false, err
		}

		if byteRule != nil {
			rule, err := strconv.Atoi(string(byteRule[:]))
			if err != nil {
				return false, err
			}
			switch commands[1] {
			case AddCommand:
				if 1&rule == 1 {
					return true, nil
				}
			case ModifyCommand:
				if 2&rule == 2 {
					return true, nil
				}
			case DelCommand:
				if 4&rule == 4 {
					return true, nil
				}
			default:
				return false, ErrInvalidCommand
			}
		}
	} else {
		return false, ErrInvalidCommand
	}
	return false, nil
}

func (acc *account) GetPermission(authType, key string) ([]byte, error) {
	if authType == FuncAuthType {
		return acc.contractFunAuths.Get([]byte(key))
	} else if authType == RoleAuthType {
		return acc.contractRoles.Get([]byte(key))
	} else {
		return nil, ErrInvalidAuthorizeType
	}
	return nil, nil
}

func (acc *account) GetContractFuncList() ([]string, error) {
	byteFunList, err := acc.Get(trie.HashDomains(ContractMeta_Prefix, ContractFunList))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	funList := make([]string, 0)
	if byteFunList != nil {

		if err = json.Unmarshal(byteFunList, &funList); err != nil {
			return nil, err
		}
	}
	return funList, nil
}

// return string object of account
func (acc *account) String() string {
	return fmt.Sprintf("Account %p {Address: %v, Balance:%v, FrozenFund:%v, PledgeFund:%v, CreditIndex:%v; Nonce:%v, IsClosed:%v}",
		acc,
		byteutils.Hex(acc.address),
		acc.balance.String(),
		acc.frozenFund.String(),
		acc.pledgeFund.String(),
		acc.creditIndex,
		acc.nonce,
		acc.state,
	)
}

// Get from account's storage.
func (acc *account) GetStorage() cdb.Storage {
	return acc.storage
}
