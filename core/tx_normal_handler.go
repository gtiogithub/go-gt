package core

import (
	"encoding/json"
	"math/big"

	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

type NormalHandler struct {
	Data []byte
}

// LoadNormalHandler from bytes
func LoadNormalHandler(bytes []byte) (*NormalHandler, error) {
	handler := &NormalHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewNormalHandler(handler.Data), nil
}

// NewNormalHandler with data
func NewNormalHandler(data []byte) *NormalHandler {
	return &NormalHandler{
		Data: data,
	}
}

// ToBytes serialize handler
func (handler *NormalHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *NormalHandler) BaseGasCount() *big.Int {
	return big.NewInt(0)
}

func (handler *NormalHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	return nil
}

// Execute the normal handler in tx, call a function
func (handler *NormalHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	fromAcc, err := ws.GetOrCreateAccount(tx.from.address) // sender account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get from account")
		return zero, "", err
	}

	toAcc, err := ws.GetOrCreateAccount(tx.to.address) // receiver account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get to account")
		return zero, "", err
	}
	var subErr, addErr error

	subErr = fromAcc.SubBalance(tx.value) // sub (tx.value) from sender
	if subErr == nil {
		addErr = toAcc.AddBalance(tx.value) // add tx.value to receiver
	}

	if subErr != nil || addErr != nil {
		logging.VLog().WithFields(logrus.Fields{
			"subErr":      subErr,
			"addErr":      addErr,
			"tx":          tx,
			"fromBalance": fromAcc.Balance(),
			"toBalance":   toAcc.Balance(),
			"block":       block,
		}).Error("Failed to transfer value, unexpected error")
		return zero, "", err
	}

	return zero, "", nil
}

func (handler *NormalHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	return nil
}
