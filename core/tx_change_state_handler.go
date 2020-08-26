package core

import (
	"encoding/json"
	"errors"
	"math/big"

	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

type ChangeStateHandler struct {
	Name  string
	State int32
}

// LoadCloseHandler from bytes
func LoadChangeStateHandler(bytes []byte) (*ChangeStateHandler, error) {
	handler := &ChangeStateHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewChangeStateHandler(handler.State), nil
}

// NewCloseHandler with data
func NewChangeStateHandler(state int32) *ChangeStateHandler {
	return &ChangeStateHandler{
		State: state,
	}
}

// ToBytes serialize handler
func (handler *ChangeStateHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *ChangeStateHandler) BaseGasCount() *big.Int {
	return big.NewInt(0)
}

func (handler *ChangeStateHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	return nil
}

// Execute the close handler in tx, call a function
func (handler *ChangeStateHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	contractAcc, err := ws.GetContractAccount(tx.to.address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get contract account")
		return zero, "", err
	}

	birthTx, err := GetTransaction(contractAcc.BirthTransaction(), ws)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get contract's birth transaction")
		return zero, "", err
	}

	if !birthTx.from.Equals(tx.from) {
		return zero, "", errors.New("you didn't change state this contract")
	}

	// contract had been close
	if contractAcc.Closed() {
		return zero, "", errors.New("the contract had been closed")
	}
	if contractAcc.State() == state.AccountStateFix &&
		handler.State == state.AccountStateClosed {
		return zero, "", errors.New("the contract is fix state. don't transfer to closed state.")
	}

	deployerAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get contract's deployer account")
		return zero, "", err
	}

	if handler.State == state.AccountStateClosed {
		balance := contractAcc.Balance()
		if err := contractAcc.SubBalance(balance); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err": err,
			}).Error("Sub contract balance error")
			return zero, "", err
		}
		if err := deployerAcc.AddBalance(balance); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err": err,
			}).Error("Add contract balance back to deployer error")
			return zero, "", err
		}
	}

	if err := contractAcc.SetState(handler.State); err != nil {
		return zero, "", err
	}
	return zero, "", nil
}

func (handler *ChangeStateHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	return nil
}
