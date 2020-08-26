package core

import (
	"gt.pro/gtio/go-gt/util/byteutils"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

type CallHandler struct {
	Function string
	Args     string
}

// CheckContractArgs check contract args
func CheckContractArgs(args string) error {
	if len(args) > 0 {
		var argsObj []interface{}
		if err := json.Unmarshal([]byte(args), &argsObj); err != nil {
			return err
		}
	}
	return nil
}

// LoadCallHandler from bytes
func LoadCallHandler(bytes []byte) (*CallHandler, error) {
	handler := &CallHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewCallHandler(handler.Function, handler.Args)
}

// NewCallHandler with function & args
func NewCallHandler(function, args string) (*CallHandler, error) {

	if PublicFuncNameChecker.MatchString(function) == false {
		return nil, ErrInvalidCallFunction
	}

	if err := CheckContractArgs(args); err != nil {
		return nil, ErrInvalidArgument
	}

	return &CallHandler{
		Function: function,
		Args:     args,
	}, nil
}

// ToBytes serialize handler
func (handler *CallHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *CallHandler) BaseGasCount() *big.Int {
	return big.NewInt(60)
}

func (handler *CallHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	contractAcc, err := ws.GetContractAccount(tx.to.address)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get contract account")
		return err
	}

	if contractAcc.State() != state.AccountStateRunning {
		return errors.New("the contract is not running state.")
	}

	//check execute authorize
	birthTx, err := GetTransaction(contractAcc.BirthTransaction(), ws)
	if err != nil {
		return err
	}
	if !byteutils.Equal(tx.from.Bytes(), birthTx.from.Bytes()) { //check owner
		if ok, _ := contractAcc.CheckPermission(state.FuncAuthType+"_"+"", tx.from.String(), handler.Function); !ok { //check normal account
			return errors.New("permission denied")
		}
	}

	return nil
}

// Execute the call handler in tx, call a function
func (handler *CallHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	// payloadGasLimit <= 0, v8 engine not limit the execution instructions
	if limitedGas.Cmp(zero) <= 0 {
		return zero, "", ErrOutOfGasLimit
	}

	fromAcc, err := ws.GetOrCreateAccount(tx.from.address) // sender account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get from account")
		return zero, "", err
	}

	contract, err := GetContract(tx.to, ws)
	if err != nil {
		return zero, "", err
	}

	var subErr, addErr error

	subErr = fromAcc.SubBalance(tx.value) // sub (tx.value) from sender
	if subErr == nil {
		addErr = contract.AddBalance(tx.value) // add tx.value to receiver
	}

	if subErr != nil || addErr != nil {
		logging.VLog().WithFields(logrus.Fields{
			"subErr":      subErr,
			"addErr":      addErr,
			"tx":          tx,
			"fromBalance": fromAcc.Balance(),
			"toBalance":   contract.Balance(),
			"block":       block,
		}).Error("Failed to transfer value, unexpected error")
		return zero, "", err
	}

	birthTx, err := GetTransaction(contract.BirthTransaction(), ws)
	if err != nil {
		return zero, "", err
	}

	if !byteutils.Equal(tx.from.Bytes(), birthTx.from.Bytes()) { //check owner
		if ok, _ := contract.CheckPermission(state.FuncAuthType+"_"+"", tx.from.String(), handler.Function); !ok { //check normal account
			return zero, "", errors.New("permission denied")
		}
	}

	deploy, err := LoadDeployHandler(birthTx.data.Msg)
	if err != nil {
		return zero, "", err
	}

	engine, err := block.cvm.CreateEngine(block, tx, contract, ws)
	if err != nil {
		return zero, "", err
	}
	defer engine.Dispose()

	if err := engine.SetExecutionLimits(limitedGas.Uint64(), DefaultLimitsOfTotalMemorySize); err != nil {
		return zero, "", err
	}

	result, exeErr := engine.Call(deploy.Source, handler.Function, handler.Args)
	gasCount := engine.ExecutionInstructions()
	instructions := big.NewInt(int64(gasCount))

	if exeErr == ErrExecutionFailed && len(result) > 0 {
		exeErr = fmt.Errorf("Call: %s", result)
	}

	logging.VLog().WithFields(logrus.Fields{
		"tx.hash":      tx.Hash(),
		"instructions": instructions,
		"limitedGas":   limitedGas,
	}).Debug("record gas of v8")

	return instructions, result, exeErr
}

func (handler *CallHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	contract, err := GetContract(tx.to, ws)
	if err != nil {
		return err
	}
	//sub contract execute fee
	txFee := config.ContractTxFee
	if subErr := contract.SubBalance(txFee); subErr != nil {
		return subErr
	}
	ws.RecordGas(tx.to.String(), txFee)
	return nil
}
