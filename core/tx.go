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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gt.pro/gtio/go-gt/crypto"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/crypto/keystore"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/dfs"
	"gt.pro/gtio/go-gt/util/logging"
)

var (
	zero = big.NewInt(0)
)

const (
	TestFile = "D:/gopath/src/gt.pro/gtio/go-gt/cvm/lmlx_go_test/test_file/test_add_eq.js"

	TxHashByteLength = 32
	PriorityNormal   = 0
	PriorityHigh     = 255

	// TxFailed failed status for transaction execute result.
	TxFailed = 0
	// TxSuccess success status for transaction execute result.
	TxSuccess = 1
	// TxPendding pendding status when transaction in transaction pool.
	TxPendding = 2

	nC = int64(1)
	uC = int64(100 * nC)
	mC = int64(100 * uC)
	cC = int64(100 * mC)
	C  = int64(100 * cC)

	UintPricePerGas   = 1 * uC
	ContractInvokeFee = 10 * mC

	Thousand = int64(1000)

	Decimals        = 8
	ZeroString      = "0"
	ZeroCUintString = "0.00000000"
	Minus           = "-"
	Dot             = "."
	Numerical       = "-[0-9]+(.[0-9]+)?|[0-9]+(.[0-9]+)?"
)

const (
	//InnerTransactionNonce inner tx nonce
	InnerTransactionNonce = uint64(0)
)

var (
	// TransactionMaxGas max gas:50 * 10 ** 9
	TransactionMaxGas = big.NewInt(50000000000)
	// MaxDataPayLoadLength Max data length in transaction
	MaxDataPayLoadLength = 256 * 1024

	// MinGasCountPerTransaction default gas for normal transaction
	MinGasCountPerTransaction = big.NewInt(21000)

	// MaxEventErrLength Max error length in event
	MaxEventErrLength = 256
	// MaxResultLength max execution result length
	MaxResultLength = 256

	GasCountPerByte = big.NewInt(1)
)

var (
	TxDataIsNilError             = errors.New("transaction data is nil")
	ComplexTxInnerDataIsNilError = errors.New("complex transaction inner data is nil")
	TxDataMsgIsNilError          = errors.New("transaction data msg is nil or length is 0")
	TransactionTypeNotSupport    = errors.New("the transaction type is nonsupport")
	TransactionTypeMismatch      = errors.New("transaction type mismatch")
	IllegalAmountError           = errors.New("the amount must be greater than 0")
	IllegalAddressError          = errors.New("address is nil or length is not 37")
	ToAddressIsNilError          = errors.New("to address is nil")
	UnmarshalDataError           = errors.New("unmarshal data error")
	MarshalDataError             = errors.New("marshal data error")
	ComplexTxTypeError           = errors.New("complex transaction can not contain complex transaction")
	IllegalPriorityRangeError    = errors.New("transaction priority out of rang")
	AmountNotEnoughError         = errors.New("amount not enough to create contract")
	TxFeeInvalidError            = errors.New("the transaction fee is not equal to the calculated transaction fee")

	ValueCanNotToBigIntError = errors.New("value string can not transfer to big int")
	ValueIsNotValid          = errors.New("the value must be greater than 0")
	IsNotNumericalValueError = errors.New("the value is not numerical value")
	ContractCodeIsEmptyError = errors.New("contract code is empty")

	ErrPledgeFundNotEnough    = errors.New("pledge fund not enough to pledge transaction")
	ErrAccountNotJoinElection = errors.New("account is not join election")

	ErrInvalidVoteType = errors.New("invalid vote type")
)

// Transaction
type Transaction struct {
	hash      byteutils.Hash
	from      *Address
	to        *Address
	value     *big.Int
	nonce     uint64
	chainId   uint32
	timestamp int64
	data      *corepb.Data
	priority  uint32
	gasLimit  *big.Int
	sign      *corepb.Signature
	memo      []byte
}

// Transactions is an alias of Transaction array.
type Transactions []*Transaction

// NewTransaction
func NewTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int, config *ChainConfig) (*Transaction, error) {
	if priority > PriorityHigh {
		return nil, IllegalPriorityRangeError
	}
	switch txType {
	case PledgeTx:
		return NewPledgeTransaction(chainId, from, amount, nonce, priority, txType, msg, memo, gasLimit, config)
	case NormalTx:
		return NewNormalTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	case ContractDeployTx:
		return NewDeployTransaction(chainId, from, amount, nonce, priority, txType, msg, memo, gasLimit)
	case ContractInvokeTx:
		return NewInvokeTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	case ContractChangeStateTx:
		return NewChangeStateTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	case ComplexTx:
		return NewComplexTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	case AuthorizeTx:
		return NewAuthorizeTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	case ReportTx:
		return NewReportTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	default:
		logging.VLog().WithField(
			"tx.data.type", txType,
		).Error("Unsupported transaction types")
		return nil, TransactionTypeNotSupport
	}
}

// NewPledgeTransaction
func NewPledgeTransaction(chainId uint32, from *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int, config *ChainConfig) (*Transaction, error) {

	if PledgeTx != txType {
		return nil, TransactionTypeMismatch
	}

	pledgeHandler, err := LoadPledgeHandler(msg)
	if err != nil {
		return nil, err
	}
	switch pledgeHandler.VoteType {
	case LoginWitness:
		if amount == nil || amount.Cmp(zero) <= 0 {
			return nil, IllegalAmountError
		}
	case LogoutWitness:
		amount = big.NewInt(0)
	default:
		return nil, ErrInvalidVoteType
	}

	return newTransaction(chainId, from, from, amount, nonce, priority, txType, msg, memo, gasLimit)
}

// NewNormalTransaction
func NewNormalTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {

	if txType != NormalTx {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if amount == nil || amount.Cmp(zero) <= 0 {
		return nil, IllegalAmountError
	}

	return newTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
}

// NewDeployTransaction
func NewDeployTransaction(chainId uint32, from *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {
	if ContractDeployTx != txType {
		return nil, TransactionTypeMismatch
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}

	if amount == nil || amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, IllegalAmountError
	}

	tx, err := newTransaction(chainId, from, from, amount, nonce, priority, txType, msg, memo, gasLimit)
	if err != nil {
		return nil, err
	}

	referenceAmount := big.NewInt(Thousand)
	referenceAmount.Mul(referenceAmount, big.NewInt(ContractInvokeFee))
	if amount.Cmp(referenceAmount) < 0 {
		logging.CLog().WithFields(logrus.Fields{
			"value":      amount.String(),
			"calc value": referenceAmount.String(),
		}).Debug(AmountNotEnoughError.Error())
		return nil, AmountNotEnoughError
	}
	return tx, nil
}

// NewInvokeTransaction
func NewInvokeTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {
	if ContractInvokeTx != txType {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	return newTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
}

// NewContractClose
func NewChangeStateTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {

	if ContractChangeStateTx != txType {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}

	return newTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
}

// NewFileTransaction
func NewComplexTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {
	if ComplexTx != txType {
		return nil, TransactionTypeMismatch
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	complexData := new(corepb.ComplexData)
	if err := proto.Unmarshal(msg, complexData); err != nil {
		logging.VLog().Error("Failed to unmarshal data.")
		return nil, UnmarshalDataError
	}

	if complexData.Data == nil {
		return nil, TxDataIsNilError
	}

	if complexData.Data == nil {
		return nil, ComplexTxInnerDataIsNilError
	}

	if ComplexTx == complexData.Data.Type {
		return nil, ComplexTxTypeError
	}
	//resultFiles := processDocumentTx(from.String(), complexData.Flies, dfsPrefix)
	//complexData.Flies = resultFiles

	//complexData.Flies = resultFiles
	//resultBytes, err := proto.Marshal(complexData)
	//if err != nil {
	//	logging.VLog().Error("Failed to marshal complexData")
	//	return nil, MarshalDataError
	//}
	tx, err := newTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
	//NewTransaction(from, to, amount, nonce, chainId, priority, complexData.Data.Type, resultBytes, nil, memo)
	if err != nil {
		return nil, err
	}
	tx.data.Type = ComplexTx
	return tx, nil
}

// NewAuthorizeTransaction
func NewAuthorizeTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {
	if AuthorizeTx != txType {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	return newTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
}

func NewReportTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, msg []byte, memo string, gasLimit *big.Int) (*Transaction, error) {
	if ReportTx != txType {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	return newTransaction(chainId, from, to, amount, nonce, priority, txType, msg, memo, gasLimit)
}

// SetNonce update th nonce
func (tx *Transaction) SetNonce(newNonce uint64) {
	tx.nonce = newNonce
}

// newTransaction
func newTransaction(chainId uint32, from, to *Address, amount *big.Int, nonce uint64, priority uint32,
	txType string, data []byte, memo string, gasLimit *big.Int) (*Transaction, error) {

	if gasLimit == nil || gasLimit.Cmp(zero) <= 0 || gasLimit.Cmp(TransactionMaxGas) > 0 {
		return nil, ErrInvalidGasLimit
	}
	if nil == from || nil == amount {
		return nil, ErrInvalidArgument
	}

	if len(data) > MaxDataPayLoadLength {
		return nil, ErrTxDataHandlerOutOfMaxLength
	}

	var v struct {
		state int32
	}
	_ = json.Unmarshal(data, &v)

	tx := Transaction{
		from:      from,
		to:        to,
		value:     amount,
		nonce:     nonce,
		chainId:   chainId,
		data:      &corepb.Data{Type: txType, Msg: data},
		priority:  priority,
		timestamp: time.Now().Unix(),
		gasLimit:  gasLimit,
	}

	if len(memo) > 0 {
		tx.memo = []byte(memo)
	}

	return &tx, nil
}

func (tx *Transaction) Nonce() uint64        { return tx.nonce }
func (tx *Transaction) Hash() byteutils.Hash { return tx.hash }
func (tx *Transaction) Timestamp() int64     { return tx.timestamp }
func (tx *Transaction) Type() string         { return tx.data.Type }
func (tx *Transaction) Priority() uint32     { return tx.priority }
func (tx *Transaction) ChainId() uint32      { return tx.chainId }
func (tx *Transaction) GasLimit() *big.Int {
	if tx == nil || tx.gasLimit == nil {
		return nil
	}
	value := *tx.gasLimit
	return &value
}

//
func (tx *Transaction) IsContractTransaction() bool {
	typ := tx.data.Type
	if ContractDeployTx == typ || ContractInvokeTx == typ || ContractChangeStateTx == typ {
		return true
	}
	return false
}

//
//func (tx *Transaction) IsPledgeTransaction() bool {
//	if tx.data.Type == PledgeTx {
//		return true
//	}
//	return false
//}

//
func (tx *Transaction) IsTransferTransaction() bool {
	if tx.data.Type == NormalTx {
		return true
	}
	return false
}

// Sign
func (tx *Transaction) Sign(signature keystore.Signature) error {
	if signature == nil {
		return ErrNilArgument
	}
	hash, err := tx.CalcHash()
	if err != nil {
		return err
	}
	sign, err := signature.Sign(hash)
	if err != nil {
		return err
	}
	tx.hash = hash
	tx.sign = &corepb.Signature{
		Signer: sign.GetSigner(),
		Data:   sign.GetData(),
	}
	return nil
}

// SetSign
func (tx *Transaction) SetSign(signature *corepb.Signature) {
	tx.sign = signature
}

// TxFrom
func (tx *Transaction) From() *Address {
	if tx.from == nil {
		return nil
	}
	from := *tx.from
	return &from
}

// TxTo
func (tx *Transaction) To() *Address {
	if tx.to == nil {
		return nil
	}
	to := *tx.to
	return &to
}

// TxValue
func (tx *Transaction) Value() *big.Int {
	if tx == nil || tx.value == nil {
		return nil
	}
	value := *tx.value
	return &value
}

// TxValue
func (tx *Transaction) GetData() *corepb.Data {
	if tx == nil || tx.data == nil {
		return nil
	}
	data := *tx.data
	return &data
}

// GetHexSignature
func (tx *Transaction) GetHexSignature() string {
	return byteutils.Hex(tx.sign.Data)
}

func (tx *Transaction) GetSign() *corepb.Signature {
	return tx.sign
}

func (tx *Transaction) GetMemo() string {
	if tx.memo == nil {
		return ""
	}
	return string(tx.memo)
}

// GetHexSignature
func (tx *Transaction) GetHexSignAndPubKey() (string, string) {
	return byteutils.Hex(tx.sign.Data), byteutils.Hex(tx.sign.Signer)
}

//
func (tx *Transaction) GenerateContractAddress() (*Address, error) {
	if tx.Type() != ContractDeployTx {
		return nil, ErrTxType
	}

	return NewContractAddressFromData(tx.from.Bytes(), byteutils.FromUint64(tx.nonce))
}

//load transaction data
func (tx *Transaction) LoadTxHandler() (TxHandler, error) {
	var handler TxHandler
	var err error

	switch tx.Type() {
	case NormalTx:
		handler, err = LoadNormalHandler(tx.data.Msg)
	case PledgeTx:
		handler, err = LoadPledgeHandler(tx.data.Msg)
	case ContractDeployTx:
		handler, err = LoadDeployHandler(tx.data.Msg)
	case ContractInvokeTx:
		handler, err = LoadCallHandler(tx.data.Msg)
	case ContractChangeStateTx:
		handler, err = LoadChangeStateHandler(tx.data.Msg)
	case ComplexTx:
		handler, err = LoadComplexHandler(tx.data.Msg)
	case AuthorizeTx:
		handler, err = LoadAuthorizeHandler(tx.data.Msg)
	case ReportTx:
		handler, err = LoadReportHandler(tx.data.Msg)
	default:
		err = ErrInvalidTxHandlerType
	}
	return handler, err
}

// CheckTx checks if the tx in world state.
func CheckTransaction(tx *Transaction, ws WorldState) (bool, error) {
	//if tx.Type() == PledgeTx {
	//	return false, nil
	//}

	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		return true, err
	}

	currentNonce := fromAcc.Nonce()
	if tx.nonce < currentNonce+1 {
		return false, ErrSmallTransactionNonce // nonce is too small
	} else if tx.nonce > currentNonce+1 {
		return true, ErrLargeTransactionNonce // nonce is too large
	}

	return false, nil
}

// GetContract check if contract is valid
func GetContract(addr *Address, ws WorldState) (state.Account, error) {
	if addr == nil || ws == nil {
		return nil, ErrNilArgument
	}

	if addr.Type() != ContractAddress {
		return nil, ErrContractCheckFailed
	}

	contract, err := ws.GetContractAccount(addr.Bytes())
	if err != nil {
		return nil, err
	}

	birthEvents, err := ws.FetchEvents(contract.BirthTransaction())
	if err != nil {
		return nil, err
	}

	result := false
	if birthEvents != nil && len(birthEvents) > 0 {
		event := birthEvents[len(birthEvents)-1]
		if event.Topic == TopicTransactionExecutionResult {
			txEvent := TransactionEvent{}
			if err := json.Unmarshal([]byte(event.Data), &txEvent); err != nil {
				return nil, err
			}
			if txEvent.Status == TxSuccess {
				result = true
			}
		}
	}
	if !result {
		return nil, ErrContractCheckFailed
	}

	return contract, nil
}

// GasCountOfTxBase calculate the actual amount for a tx with data
func (tx *Transaction) GasCountOfTxBase() *big.Int {
	//if tx.IsPledgeTransaction() {
	//	return big.NewInt(0)
	//}
	dataLen := len(tx.data.Msg)
	memoLen := len(tx.memo)
	totalLen := dataLen + memoLen

	txGas := MinGasCountPerTransaction
	if totalLen > 0 {
		txLen := big.NewInt(int64(totalLen))
		dataGas := new(big.Int).Mul(txLen, GasCountPerByte)
		txGas = new(big.Int).Add(txGas, dataGas)
	}

	return txGas
}

// VerifyExecution verifies tx in block and returns result.
func VerifyExecution(tx *Transaction, block *Block, ws WorldState, chainConfig *ChainConfig) (bool, error) {
	// step0. perpare accounts.
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		return true, err
	}

	// step1. check balance >= gasLimit * gasPrice
	limitedFee := new(big.Int).Mul(tx.gasLimit, big.NewInt(UintPricePerGas))
	if tx.Type() != ReportTx {
		if fromAcc.Balance().Cmp(limitedFee) < 0 {
			// Balance is smaller than limitedFee, won't giveback the tx
			return false, ErrInsufficientBalance
		}
	}

	// step2. check gasLimit >= txBaseGas.
	baseGas := tx.GasCountOfTxBase()
	gasUsed := baseGas
	if tx.gasLimit.Cmp(gasUsed) < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"error":       ErrOutOfGasLimit,
			"transaction": tx,
			"limit":       tx.gasLimit,
			"acceptedGas": gasUsed,
		}).Error("Failed to check gasLimit >= txBaseGas.")
		// GasLimit is smaller than based tx gas, won't giveback the tx
		return false, ErrOutOfGasLimit
	}

	// step3. check handler vaild.
	handler, handlerErr := tx.LoadTxHandler()
	if handlerErr != nil {
		return submitTx(tx, block, ws, gasUsed, handlerErr, "Failed to load tx handler.", "")
	}

	// step4. calculate base gas of tx handler
	gasUsed = new(big.Int).Add(gasUsed, handler.BaseGasCount())
	if tx.gasLimit.Cmp(gasUsed) < 0 {
		return submitTx(tx, block, ws, tx.gasLimit, ErrOutOfGasLimit, "Failed to check gasLimit >= txBaseGas + txHandlerBaseGas.", "")
	}

	// step5. check balance >= limitedFee + value. and transfer
	logging.VLog().WithFields(logrus.Fields{
		"limitedFee": limitedFee,
		"tx.value":   tx.value,
	}).Debug("minBalanceRequired check value status")
	minBalanceRequired := new(big.Int).Add(limitedFee, tx.value)
	if tx.Type() != ReportTx {
		if fromAcc.Balance().Cmp(minBalanceRequired) < 0 {
			return submitTx(tx, block, ws, gasUsed, ErrInsufficientBalance, "Failed to check balance >= gasLimit * gasPrice + value", "")
		}
	}
	// step6. calculate contract's limited gas
	contractLimitedGas := new(big.Int).Sub(tx.gasLimit, gasUsed)

	// step7. execute tx prepared process
	preErr := handler.Before(tx, block, ws, chainConfig)
	if preErr != nil {
		return submitTx(tx, block, ws, gasUsed, preErr, "Failed to execute tx prepared process", "")
	}

	// step8. execute tx process
	gasExecution, exeResult, exeErr := handler.Execute(contractLimitedGas, tx, block, ws)
	if exeErr == ErrUnexpected {
		return false, exeErr
	}

	// step9. calculate final gas.
	allGas := new(big.Int).Add(gasUsed, gasExecution)
	if tx.gasLimit.Cmp(allGas) < 0 {
		return submitTx(tx, block, ws, tx.gasLimit, ErrOutOfGasLimit, "Failed to check gasLimit >= allGas", "")
	}

	// step10. execute tx after process
	afterErr := handler.After(tx, block, ws, chainConfig, exeResult)
	if afterErr != nil {
		return submitTx(tx, block, ws, gasUsed, afterErr, "Failed to execute tx after process", "")
	}

	// step11. over
	return submitTx(tx, block, ws, allGas, exeErr, "Failed to execute tx handler", exeResult)
}

func submitTx(tx *Transaction, block *Block, ws WorldState,
	gas *big.Int, exeErr error, exeErrTy string, exeResult string) (bool, error) {
	if exeErr != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":         exeErr,
			"block":       block,
			"transaction": tx,
		}).Error(exeErrTy)
		metricsTxExeFailed.Mark(1)
	} else {
		metricsTxExeSuccess.Mark(1)
	}

	if exeErr != nil {
		if err := ws.Reset(nil, false); err != nil {
			// if reset failed, the tx should be given back
			return true, err
		}
	}

	gasCost := tx.recordGas(gas, ws)

	if err := tx.recordResultEvent(gas, block, ws, exeResult, exeErr); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":   err,
			"tx":    tx,
			"gas":   gas,
			"block": block,
		}).Error("Failed to record result event, unexpected error")
		metricsUnexpectedBehavior.Update(1)
		return true, err
	}
	// sub tx gas
	fromAcc, err := ws.GetOrCreateAccount(tx.from.Bytes())
	if err != nil {
		return true, err
	}
	if err = fromAcc.SubBalance(gasCost); err != nil {
		return true, err
	}

	// No error, won't giveback the tx
	return false, nil
}

func (tx *Transaction) recordGas(gasCnt *big.Int, ws WorldState) *big.Int {
	gasCost := new(big.Int).Mul(big.NewInt(UintPricePerGas), gasCnt)
	if tx.Type() == ReportTx {
		gasCost = big.NewInt(0)
	}
	ws.RecordGas(tx.from.String(), gasCost)
	return gasCost
}

//
func (tx *Transaction) recordResultEvent(gasUsed *big.Int, block *Block, ws WorldState, txRes string, txErr error) error {
	var txData []byte
	var err error
	switch tx.Type() {
	case NormalTx, PledgeTx, AuthorizeTx, ContractChangeStateTx, ReportTx:
		txEvent := &TransactionEvent{
			Hash:    tx.hash.String(),
			GasUsed: gasUsed.String(),
			Status:  TxSuccess,
		}
		if txErr != nil {
			txEvent.Status = TxFailed
			txEvent.Error = txErr.Error()
			if len(txEvent.Error) > MaxEventErrLength {
				txEvent.Error = txEvent.Error[:MaxEventErrLength]
			}
		}
		txData, err = json.Marshal(txEvent)

		block.recordTxExeStatus(tx.hash, txEvent.Status)
	case ContractDeployTx, ContractInvokeTx:
		if len(txRes) > MaxResultLength {
			txRes = txRes[:MaxResultLength]
		}

		txEvent := &ContractTransactionEvent{
			Hash:          tx.hash.String(),
			GasUsed:       gasUsed.String(),
			Status:        TxSuccess,
			ExecuteResult: txRes,
		}
		if txErr != nil {
			txEvent.Status = TxFailed
			txEvent.Error = txErr.Error()
			if len(txEvent.Error) > MaxEventErrLength {
				txEvent.Error = txEvent.Error[:MaxEventErrLength]
			}
		}

		txData, err = json.Marshal(txEvent)
		block.recordTxExeStatus(tx.hash, txEvent.Status)
	}

	if txErr != nil {
		logging.CLog().WithFields(logrus.Fields{
			"tx.hash": tx.hash.String(),
			"err":     txErr.Error(),
		}).Debug("tx execute failed ")
	}
	if err != nil {

		return err
	}

	event := &state.Event{
		Topic: TopicTransactionExecutionResult,
		Data:  string(txData),
	}

	ws.RecordEvent(tx.Hash(), event)

	return nil
}

// SetHash set hash to in args
func (tx *Transaction) SetHash(in byteutils.Hash) {
	tx.hash = in
}

//get transaction by txHash and worldstate
func GetTransaction(txHash byteutils.Hash, ws WorldState) (*Transaction, error) {
	if len(txHash) != TxHashByteLength {
		return nil, ErrInvalidArgument
	}

	bytes, err := ws.GetTx(txHash)
	if err != nil {
		return nil, err
	}
	pbTx := new(corepb.Transaction)
	if err := proto.Unmarshal(bytes, pbTx); err != nil {
		return nil, err
	}

	tx := new(Transaction)
	if err := tx.FromProto(pbTx); err != nil {
		return nil, err
	}

	return tx, nil
}

// AcceptTx accepts a tx in world state.
func AcceptTransaction(tx *Transaction, block *Block, ws WorldState) (bool, error) {
	// record tx
	pbTx, err := tx.ToProto()
	if err != nil {
		return true, err
	}
	txBytes, err := proto.Marshal(pbTx)
	if err != nil {
		return true, err
	}
	if err := ws.PutTx(tx.hash, txBytes); err != nil {
		return true, err
	}
	// incre nonce
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		return true, err
	}

	fromAcc.IncreaseNonce()

	err = fromAcc.PutTx(tx.hash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"account": fromAcc.Address().String(),
			"error":   err,
		}).Debug("account put hash failed")
		return true, err
	}
	if !byteutils.Equal(tx.from.address, tx.to.address) {
		toAcc, _ := ws.GetOrCreateAccount(tx.to.address)
		err = toAcc.PutTx(tx.hash)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"account": toAcc.Address().String(),
				"error":   err,
			}).Debug("account put hash failed")
		}
		return true, err
	}

	if tx.IsContractTransaction() {
		fromAcc.IncreaseIntegral(block.TermId(), state.Contract)
		if tx.Type() == ContractDeployTx {
			contractAddr, _ := tx.GenerateContractAddress()
			contractAcc, _ := ws.GetOrCreateAccount(contractAddr.address)
			contractAcc.IncreaseContractIntegral(contractAddr.String(), block.Height())
			fromAcc.IncreaseContractIntegral(contractAddr.String(), block.Height())
		} else if tx.Type() == ContractInvokeTx || tx.Type() == ContractChangeStateTx {
			contractAcc, _ := ws.GetOrCreateAccount(tx.to.address)
			contractAcc.IncreaseContractIntegral(tx.to.String(), 0)
		}
	} else if tx.IsTransferTransaction() {
		fromAcc.IncreaseIntegral(block.TermId(), state.Normal)
	}

	return false, nil
}

// ToProto converts domain Tx to proto Tx
func (tx *Transaction) ToProto() (proto.Message, error) {
	protoTx := corepb.Transaction{
		Hash:      tx.hash,
		From:      tx.from.address,
		Nonce:     tx.nonce,
		ChainId:   tx.chainId,
		Timestamp: tx.timestamp,
		Priority:  tx.priority,
		Sign:      tx.sign,
		Memo:      tx.memo,
		GasLimit:  tx.gasLimit.Bytes(),
	}
	if tx.value != nil {
		protoTx.Value = tx.value.Bytes()
	}
	if tx.to != nil {
		protoTx.To = tx.to.address
	}
	if tx.data != nil {
		protoTx.Data = tx.data
	}

	return &protoTx, nil
}

// FromProto converts proto Tx to domain Tx
func (tx *Transaction) FromProto(msg proto.Message) error {
	if msg, ok := msg.(*corepb.Transaction); ok {
		if msg != nil {
			tx.hash = msg.Hash
			from, err := AddressParseFromBytes(msg.From)
			if err != nil {
				return ErrInvalidProtoToTransaction
			}
			tx.from = from
			if len(msg.To) > 0 {
				to, err := AddressParseFromBytes(msg.To)
				if err != nil {
					return ErrInvalidProtoToTransaction
				}
				tx.to = to
			}
			if len(msg.Value) > 0 {
				tx.value = new(big.Int).SetBytes(msg.Value)
			} else {
				tx.value = big.NewInt(0)
			}
			tx.nonce = msg.Nonce
			tx.chainId = msg.ChainId
			tx.timestamp = msg.Timestamp
			tx.data = msg.Data
			tx.priority = msg.Priority
			tx.sign = msg.Sign
			tx.memo = msg.Memo
			tx.gasLimit = new(big.Int).SetBytes(msg.GasLimit)
			return nil
		}
		return ErrInvalidProtoToTransaction
	}
	return ErrInvalidProtoToTransaction
}

// VerifyIntegrity return transaction verify result, including Hash and Signature.
func (tx *Transaction) VerifyIntegrity(chainId uint32) error {
	// check ChainID.
	if tx.chainId != chainId {
		return ErrInvalidChainID
	}

	// check Hash.
	wantedHash, err := tx.CalcHash()
	if err != nil {
		return err
	}
	if wantedHash.Equals(tx.hash) == false {
		return ErrInvalidTransactionHash
	}

	// check Signature.
	return tx.verifySign()

}

// NcUnitToCUnitString
func NcUnitToCUnitString(value *big.Int) string {
	if value == nil || value.String() == ZeroString {
		return ZeroCUintString
	}
	valueStr := value.String()
	neg := false
	if value.Cmp(big.NewInt(0)) < 0 {
		neg = true
		valueStr = valueStr[1:]
	}

	//value length more than 8
	if len(valueStr) > Decimals {
		dotPos := len(valueStr) - Decimals
		integerStr := valueStr[:dotPos]
		decimals := valueStr[dotPos:]
		valueStr = integerStr + Dot + decimals
	} else { //value length less than 8, add prefix zero string
		count := Decimals - len(valueStr)
		valueStr = addPrefixZero(valueStr, uint8(count))
		//value length equals 8 or less than 8, add zero and dot string
		//for example 0.12345678  or   0.00123456
		valueStr = ZeroString + Dot + valueStr
	}

	if neg {
		valueStr = Minus + valueStr
	}

	return valueStr
}

// CUintStringToNcUintBigInt
func CUintStringToNcUintBigInt(valueStr string) (*big.Int, error) {
	value := valueStr
	value = strings.TrimSpace(value)
	neg := false
	if strings.HasPrefix(value, Minus) {
		neg = true
		value = value[1:]
	}
	if strings.HasPrefix(value, Dot) {
		logging.CLog().WithFields(logrus.Fields{
			"value": valueStr,
		}).Debug("value string start whit dot")
		return nil, ValueCanNotToBigIntError
	}

	reg := regexp.MustCompile(Numerical)
	isNumber := reg.MatchString(value)
	if !isNumber {
		return nil, IsNotNumericalValueError
	}

	split := strings.Split(value, Dot)
	var amount *big.Int
	result := true
	if len(split) == 1 {
		amount, result = new(big.Int).SetString(value, 0)
		if !result {
			logging.CLog().WithFields(logrus.Fields{
				"value:": valueStr,
				"error":  ValueCanNotToBigIntError,
			}).Debug("value can not to big int")
			return nil, ValueCanNotToBigIntError
		}
		amount.Mul(amount, big.NewInt(C))
	} else {

		integer := split[0]
		decimal := split[1]
		if len(decimal) < Decimals {
			j := Decimals - len(decimal)
			for i := 0; i < j; i++ {
				decimal += ZeroString
			}
		}

		if len(decimal) > Decimals {
			decimal = decimal[:Decimals]
		}

		value = integer + decimal
		value = trimPrefixZero(value)

		amount, result = new(big.Int).SetString(value, 0)

		if !result {
			logging.CLog().WithFields(logrus.Fields{
				"value:": valueStr,
				"error":  ValueCanNotToBigIntError,
			}).Debug("value can not to big int")
			return nil, ValueCanNotToBigIntError
		}
	}

	if neg {
		return new(big.Int).Neg(amount), nil
	}
	return amount, nil
}

// verifySign
func (tx *Transaction) verifySign() error {
	if tx.sign == nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx.hash": tx.hash.String(),
		}).Debug("Failed to verify tx's sign.")
		return ErrInvalidTransactionSignatureEmpty
	}
	signer, err := NewAddressFromPublicKey(tx.sign.Signer)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx.sign.Signer": hex.EncodeToString(tx.sign.Signer),
		}).Debug("Failed to verify tx's sign.")
		return ErrInvalidPublicKey
	}
	if !tx.from.Equals(signer) {
		logging.VLog().WithFields(logrus.Fields{
			"signer":  signer.String(),
			"tx.from": tx.from,
		}).Debug("Failed to verify tx's sign.")
		return ErrInvalidTransactionSigner
	}

	signature, err := crypto.NewSignature()
	if err != nil {
		return err
	}
	verify, err := signature.Verify(tx.hash, tx.sign)
	if err != nil {
		return err
	}
	if !verify {
		logging.VLog().WithFields(logrus.Fields{
			"txHash": tx.hash,
			"sign":   byteutils.Hex(tx.sign.Data),
			"pubKey": byteutils.Hex(tx.sign.Signer),
			"err":    err,
		}).Info("Failed to check transaction's signature.")
		return ErrInvalidTransactionSign
	}

	return nil
}

// HashTransaction hash the transaction.
func (tx *Transaction) CalcHash() (byteutils.Hash, error) {
	hasher := sha3.New256()

	data, err := proto.Marshal(tx.data)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Error("proto.Marshal(tx.data) error")
		return nil, err
	}

	hasher.Write(tx.from.address)

	if tx.to != nil {
		hasher.Write(tx.to.address)
	}

	if tx.value != nil {
		hasher.Write(tx.value.Bytes())
	}

	//if tx.memo != nil && !tx.IsPledgeTransaction() {
	//	hasher.Write(tx.memo)
	//}
	if tx.memo != nil {
		hasher.Write(tx.memo)
	}

	hasher.Write(byteutils.FromUint64(tx.nonce))
	hasher.Write(byteutils.FromUint32(tx.chainId))
	hasher.Write(byteutils.FromInt64(tx.timestamp))
	hasher.Write(data)
	hasher.Write(byteutils.FromUint32(tx.priority))
	hasher.Write(tx.gasLimit.Bytes())

	return hasher.Sum(nil), nil
}

//calculate cache key to prevent duplication nonce and priority on same address
func (tx *Transaction) CalcCacheKey() string {
	hasher := sha3.New256()
	hasher.Write(tx.From().Bytes())
	hasher.Write(byteutils.FromUint64(tx.nonce))
	hasher.Write(byteutils.FromUint32(tx.priority))
	var key byteutils.Hash
	key = hasher.Sum(nil)
	return key.String()
}

// JSONString of transaction
func (tx *Transaction) JSONString() string {
	txJSONObj := make(map[string]interface{})
	txJSONObj["chainId"] = tx.chainId
	txJSONObj["hash"] = tx.hash.String()
	txJSONObj["from"] = tx.from.String()
	txJSONObj["to"] = tx.to.String()
	txJSONObj["nonce"] = tx.nonce
	if tx.value != nil {
		txJSONObj["value"] = tx.value.String()
	}
	txJSONObj["timestamp"] = tx.timestamp
	txJSONObj["priority"] = tx.priority
	txJSONObj["gasLimit"] = tx.gasLimit.String()
	if tx.data != nil {
		txJSONObj["data"] = byteutils.Hex(tx.data.Msg)
	}
	txJSONObj["type"] = tx.Type()
	if tx.memo != nil {
		txJSONObj["memo"] = string(tx.memo)
	}
	txJSON, err := json.Marshal(txJSONObj)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"tx":  tx,
		}).Error("Failed to get transaction json string")
	}
	return string(txJSON)
}

func (tx *Transaction) String() string {
	txString := fmt.Sprintf(`{"chainID":%d,"hash":"%s","from":"%s","nonce":%d,"timestamp":%d,`,
		tx.chainId,
		tx.hash.String(),
		tx.from.String(),
		tx.nonce,
		tx.timestamp,
	)

	if tx.To() != nil {
		txString += fmt.Sprintf(`"to":"%s",`, tx.to.String())
	}
	if tx.value != nil {
		txString += fmt.Sprintf(`"value":"%s",`, tx.value.String())
	}
	if tx.data != nil {
		txString += fmt.Sprintf(`"data": "%s",`, byteutils.Hex(tx.data.Msg))
	}
	txString += fmt.Sprintf(`"type":"%s"}`, tx.Type())
	if tx.memo != nil {
		txString += fmt.Sprintf(`"memo":"%s"}`, string(tx.memo))
	}
	return txString
}

// processDocumentTx
func processDocumentTx(from string, files []*corepb.File, dfsPrefix []string) []*corepb.File {
	if files == nil || len(files) < 1 {
		logging.VLog().Debug("the complex tx not contain file tx")
		return nil
	}

	for _, file := range files {
		if file == nil {
			continue
		}
		storageState := file.State
		if storageState == nil {
			storageState = new(corepb.StorageState)
		}
		//send file to dfs and return result
		newFile := &corepb.File{
			Name:    file.Name,
			Content: file.Content,
			BindKey: file.BindKey,
			State:   file.State,
		}

		storageState.Result = dfs.GetResult(from, newFile, dfsPrefix)
		file.State = storageState
		file.Size_ = uint64(len(file.Content))
		file.Content = nil
	}
	return files
}

// handle string start with 0
func trimPrefixZero(str string) string {
	startZero := strings.HasPrefix(str, ZeroString)
	if startZero {
		bytes := []byte(str)
		zeroCount := 0
		for i := 0; i < len(str); i++ {
			if string(bytes[i]) != ZeroString {
				break
			}
			zeroCount++
		}
		if zeroCount != len(str) {
			str = str[zeroCount:]
		}
	}
	return str
}

// addPrefixZero
func addPrefixZero(valueStr string, count uint8) string {
	for i := uint8(0); i < count; i++ {
		valueStr = ZeroString + valueStr
	}
	return valueStr
}

func CheckTxType(txType string) error {
	switch txType {
	case PledgeTx, NormalTx, ComplexTx, ContractInvokeTx, ContractDeployTx, ContractChangeStateTx, AuthorizeTx, ReportTx:
		return nil
	default:
		return TransactionTypeNotSupport
	}
}

// NewChildTransaction return child tx to inner nvm
func (tx *Transaction) NewInnerTransaction(from, to *Address, value *big.Int, handlerType string, handler []byte) (*Transaction, error) {
	innerTx, err := NewTransaction(tx.chainId, from, to, value, InnerTransactionNonce, tx.priority, handlerType, handler, "", tx.gasLimit, nil)
	if err != nil {
		return nil, ErrCreateInnerTx
	}
	innerTx.SetHash(tx.hash)
	return innerTx, nil
}

// simulateExecution simulate execution and return gasUsed, executionResult and executionErr, sysErr if occurred.
func (tx *Transaction) simulateExecution(block *Block, chainConfig *ChainConfig) (*SimulateResult, error) {
	// hash is necessary in cvm
	hash, err := tx.CalcHash()
	if err != nil {
		return nil, err
	}
	tx.hash = hash

	// Generate world state
	ws := block.WorldState()

	// Get from account
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		return nil, err
	}

	// calculate min gas.
	gasUsed := tx.GasCountOfTxBase()

	handler, err := tx.LoadTxHandler()
	if err != nil {
		return &SimulateResult{gasUsed, "Invalid Handler", err}, nil
	}

	gasUsed = new(big.Int).Add(gasUsed, handler.BaseGasCount())

	var (
		result string
		exeErr error
	)

	if tx.data.Type == ContractDeployTx {
		exeErr = handler.Before(tx, block, ws, chainConfig)
		if exeErr != nil {
			return &SimulateResult{gasUsed, result, exeErr}, nil
		}
	}

	// try run smart contract if handler is.
	if tx.data.Type == ContractInvokeTx || tx.data.Type == NormalTx || tx.data.Type == ContractDeployTx {
		// execute.
		gasExecution := big.NewInt(0)
		gasExecution, result, exeErr = handler.Execute(TransactionMaxGas, tx, block, ws)

		// add gas.
		gasUsed := new(big.Int).Add(gasUsed, gasExecution)

		if exeErr != nil {
			return &SimulateResult{gasUsed, result, exeErr}, nil
		}
	}

	// check balance.
	if tx.Type() != ReportTx {
		err = checkBalanceForGasUsedAndValue(ws, fromAcc, tx.value, gasUsed)
	}
	return &SimulateResult{gasUsed, result, err}, nil
}

// checkBalanceForGasUsedAndValue check balance >= gasUsed * gasPrice + value.
func checkBalanceForGasUsedAndValue(ws WorldState, fromAcc state.Account, value, gasUsed *big.Int) error {
	gasFee := new(big.Int).Mul(big.NewInt(UintPricePerGas), gasUsed)
	balanceRequired := new(big.Int).Add(gasFee, value)
	if fromAcc.Balance().Cmp(balanceRequired) < 0 {
		return ErrInsufficientBalance
	}
	return nil
}
