package cvm

import (
	"math/big"
	"math/rand"
	"unsafe"

	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"github.com/gogo/protobuf/proto"
)

// SerializableAccount serializable account state
type SerializableAccount struct {
	Nonce      uint64 `json:"nonce"`
	Balance    string `json:"balance"`
	FrozenFund string `json:"frozenFund"`
	PledgeFund string `json:"pledgeFund"`
}

// SerializableBlock serializable block
type SerializableBlock struct {
	Timestamp int64  `json:"timestamp"`
	Hash      string `json:"hash"`
	Height    uint64 `json:"height"`
}

// SerializableTransaction serializable transaction
type SerializableTransaction struct {
	Hash      string `json:"hash"`
	From      string `json:"from"`
	To        string `json:"to"`
	Value     string `json:"value"`
	Nonce     uint64 `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Priority  uint32 `json:"priority"`
	GasLimit  string `json:"gasLimit"`
}

// ContextRand ..
type ContextRand struct {
	rand *rand.Rand
}

type Context struct {
	block        Block
	tx           Transaction
	contract     Account
	expendAmount *big.Int
	state        WorldState
	head         unsafe.Pointer
	index        uint32
	contextRand  *ContextRand
}

// NewContext create a engine context
func NewContext(block Block, tx Transaction, contract Account, state WorldState) (*Context, error) {
	if block == nil || tx == nil || contract == nil || state == nil {
		return nil, ErrContextConstructArrEmpty
	}
	ctx := &Context{
		block:        block,
		tx:           tx,
		expendAmount: big.NewInt(0),
		contract:     contract,
		state:        state,
		contextRand:  &ContextRand{},
	}
	return ctx, nil
}

// NewInnerContext create a child engine context
func NewInnerContext(block Block, tx Transaction, contract Account, state WorldState, head unsafe.Pointer, index uint32, ctxRand *ContextRand) (*Context, error) {
	if block == nil || tx == nil || contract == nil || state == nil || head == nil {
		return nil, ErrContextConstructArrEmpty
	}
	ctx := &Context{
		block:        block,
		tx:           tx,
		expendAmount: big.NewInt(0),
		contract:     contract,
		state:        state,
		head:         head,
		index:        index,
		contextRand:  ctxRand,
	}
	return ctx, nil
}

func toSerializableBlock(block Block) *SerializableBlock {
	sBlock := &SerializableBlock{
		Timestamp: block.Timestamp(),
		Hash:      "",
		Height:    block.Height(),
	}
	return sBlock
}

func toSerializableTransaction(tx Transaction) *SerializableTransaction {
	return &SerializableTransaction{
		From:      tx.From().String(),
		To:        tx.To().String(),
		Value:     tx.Value().String(),
		Timestamp: tx.Timestamp(),
		Nonce:     tx.Nonce(),
		Hash:      tx.Hash().String(),
		Priority:  tx.Priority(),
		GasLimit:  tx.GasLimit().String(),
	}
}

func toSerializableTransactionFromBytes(txBytes []byte) (*SerializableTransaction, error) {
	pbTx := new(corepb.Transaction)
	if err := proto.Unmarshal(txBytes, pbTx); err != nil {
		return nil, err
	}
	tx := new(core.Transaction)
	if err := tx.FromProto(pbTx); err != nil {
		return nil, err
	}

	return &SerializableTransaction{
		From:      tx.From().String(),
		To:        tx.To().String(),
		Value:     tx.Value().String(),
		Timestamp: tx.Timestamp(),
		Nonce:     tx.Nonce(),
		Hash:      tx.Hash().String(),

		Priority: tx.Priority(),
		GasLimit: tx.GasLimit().String(),
	}, nil
}

func toSerializableAccount(acc Account) *SerializableAccount {
	sAcc := &SerializableAccount{
		Nonce:      acc.Nonce(),
		Balance:    acc.Balance().String(),
		FrozenFund: acc.FrozenFund().String(),
		PledgeFund: acc.PledgeFund().String(),
	}
	return sAcc
}
