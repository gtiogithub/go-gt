// +build cgo

package cvm

/*
#include "../v8/clib/error.h"
*/
import "C"
import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"unsafe"

	"github.com/pkg/errors"

	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

// GetTxByHashFunc returns tx info by hash
//export GetTxByHashFunc
func GetTxByHashFunc(handler unsafe.Pointer, hash *C.char, gasCnt *C.size_t) *C.char {
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx.block == nil {
		return nil
	}

	// calculate Gas.
	*gasCnt = C.size_t(GetTxByHashGasBase)

	txHash, err := byteutils.FromHex(C.GoString(hash))
	if err != nil {
		return nil
	}
	txBytes, err := engine.ctx.state.GetTx(txHash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     C.GoString(hash),
			"err":     err,
		}).Debug("GetTxByHashFunc get tx failed.")
		return nil
	}
	sTx, err := toSerializableTransactionFromBytes(txBytes)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     C.GoString(hash),
			"err":     err,
		}).Debug("GetTxByHashFunc get tx failed.")
		return nil
	}
	txJSON, err := json.Marshal(sTx)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"key":     C.GoString(hash),
			"err":     err,
		}).Debug("GetTxByHashFunc get tx failed.")
		return nil
	}

	return C.CString(string(txJSON))
}

// GetAccountStateFunc returns account info by address
//export GetAccountStateFunc
func GetAccountStateFunc(handler unsafe.Pointer, address *C.char, gasCnt *C.size_t,
	result **C.char, exceptionInfo **C.char) int {
	*result = nil
	*exceptionInfo = nil
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx.block == nil {
		logging.VLog().Error("Unexpected error: failed to get engine")
		return C.CVM_UNEXPECTED_ERR
	}

	// calculate Gas.
	*gasCnt = C.size_t(GetAccountStateGasBase)

	addr, err := core.AddressParse(C.GoString(address))
	if err != nil {
		*exceptionInfo = C.CString("Blockchain.getAccountState(), parse address failed")
		return C.CVM_EXCEPTION_ERR
	}

	acc, err := engine.ctx.state.GetOrCreateAccount(addr.Bytes())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"address": addr,
			"err":     err,
		}).Error("Unexpected error: GetAccountStateFunc get account state failed")
		return C.CVM_UNEXPECTED_ERR
	}
	state := toSerializableAccount(acc)
	json, err := json.Marshal(state)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"state": state,
			"json":  json,
			"err":   err,
		}).Error("Unexpected error: GetAccountStateFunc failed to mashal account state")
		return C.CVM_UNEXPECTED_ERR
	}

	*result = C.CString(string(json))
	return C.CVM_SUCCESS
}

func recordTransferEvent(errNo int, from string, to string, value string,
	height uint64, wsState WorldState, txHash byteutils.Hash) {

	if errNo == SuccessTransferFunc {
		event := &TransferFromContractEvent{
			Amount: value,
			From:   from,
			To:     to,
		}
		eData, err := json.Marshal(event)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"from":   from,
				"to":     to,
				"amount": value,
				"err":    err,
			}).Fatal("failed to marshal TransferFromContractEvent")
		}
		wsState.RecordEvent(txHash, &state.Event{Topic: core.TopicTransferFromContract, Data: string(eData)})

	} else {
		var errMsg string
		switch errNo {
		case SuccessTransferFunc:
			errMsg = ""
		case ErrTransferAddressParse:
			errMsg = "failed to parse to address"
		case ErrTransferStringToBigInt:
			errMsg = "failed to parse transfer amount"
		case ErrTransferSubBalance:
			errMsg = "failed to sub balance from contract address"
		default:
			logging.VLog().WithFields(logrus.Fields{
				"from":   from,
				"to":     to,
				"amount": value,
				"errNo":  errNo,
			}).Error("unexpected error to handle")
			return
		}

		status := uint8(1)
		if errNo != SuccessTransferFunc {
			status = 0
		}

		event := &TransferFromContractFailureEvent{
			Amount: value,
			From:   from,
			To:     to,
			Status: status,
			Error:  errMsg,
		}

		eData, err := json.Marshal(event)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"from":   from,
				"to":     to,
				"amount": value,
				"status": event.Status,
				"error":  err,
			}).Fatal("failed to marshal TransferFromContractEvent")
		}

		wsState.RecordEvent(txHash, &state.Event{Topic: core.TopicTransferFromContract, Data: string(eData)})

	}
}

func transfer(e *V8Engine, from *core.Address, to *core.Address, amount *big.Int) int {
	toAcc, err := e.ctx.state.GetOrCreateAccount(to.Bytes())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(e.lcsHandler),
			"address": to,
			"err":     err,
		}).Error("Failed to get to account state")
		return ErrTransferGetAccount
	}

	fromAcc, err := e.ctx.state.GetOrCreateAccount(from.Bytes())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(e.lcsHandler),
			"address": from,
			"err":     err,
		}).Error("Failed to get from account state")
		return ErrTransferGetAccount
	}
	// TestNet sync adjust
	if amount == nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(e.lcsHandler),
			"address": from,
			"err":     err,
		}).Error("Failed to get amount failed.")
		return ErrTransferStringToBigInt
	}

	// update balance
	if amount.Cmp(big.NewInt(0)) > 0 {
		//check able amount
		ableAmount := new(big.Int).Sub(e.ctx.tx.Value(), e.ctx.expendAmount)
		if ableAmount.Cmp(amount) < 0 {
			logging.VLog().WithFields(logrus.Fields{
				"handler":     uint64(e.lcsHandler),
				"from":        from,
				"amount":      amount,
				"able amount": ableAmount,
			}).Error("Insufficient amount available")
			return ErrTransferInsufficientAmount
		}

		e.ctx.expendAmount = new(big.Int).Add(e.ctx.expendAmount, amount)

		err = fromAcc.SubBalance(amount)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"handler": uint64(e.lcsHandler),
				"account": fromAcc,
				"from":    from,
				"amount":  amount,
				"err":     err,
			}).Error("Failed to sub balance")
			return ErrTransferSubBalance
		}

		err = toAcc.AddBalance(amount)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"account": toAcc,
				"amount":  amount,
				"address": to,
				"err":     err,
			}).Error("Failed to add balance")
			return ErrTransferAddBalance
		}
	}
	return SuccessTransfer
}

//TransferByAddress value from to
func TransferByAddress(handler unsafe.Pointer, from *core.Address, to *core.Address, value *big.Int) int {
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx == nil || engine.ctx.block == nil ||
		engine.ctx.state == nil || engine.ctx.tx == nil {
		logging.VLog().Fatal("Unexpected error: failed to get engine.")
	}

	// *gasCnt = uint64(TransferGasBase)
	iRtn := transfer(engine, from, to, value)
	if iRtn != SuccessTransfer {
		return iRtn
	}

	return SuccessTransferFunc
}

// TransferFunc transfer vale to address
//export TransferFunc
func TransferFunc(handler unsafe.Pointer, to *C.char, v *C.char, gasCnt *C.size_t) int {
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx == nil || engine.ctx.block == nil ||
		engine.ctx.state == nil || engine.ctx.tx == nil {
		logging.VLog().Fatal("Unexpected error: failed to get engine.")
	}

	wsState := engine.ctx.state
	height := engine.ctx.block.Height()
	txHash := engine.ctx.tx.Hash()

	fAddr, err := core.AddressParseFromBytes(engine.ctx.contract.Address())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"txhash":  engine.ctx.tx.Hash().String(),
			"address": fAddr,
		}).Fatal("Unexpected error: from address is null")
	}

	// calculate Gas.
	*gasCnt = C.size_t(TransferGasBase)

	addr, err := core.AddressParse(C.GoString(to))
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"handler":   uint64(uintptr(handler)),
			"toAddress": C.GoString(to),
		}).Debug("TransferFunc parse address failed.")
		recordTransferEvent(ErrTransferAddressParse, fAddr.String(), "", "", height, wsState, txHash)
		return ErrTransferAddressParse
	}

	transferValueStr := C.GoString(v)
	recordValue := transferValueStr
	amount, flag := new(big.Int).SetString(transferValueStr, 10)
	if !flag {
		logging.VLog().WithFields(logrus.Fields{
			"handler": uint64(uintptr(handler)),
			"address": addr.String(),
			"err":     err,
			"val":     transferValueStr,
		}).Error("Failed to get amount failed.")
		recordTransferEvent(ErrTransferStringToBigInt, fAddr.String(), addr.String(), transferValueStr, height, wsState, txHash)
		return ErrTransferStringToBigInt
	}

	ret := TransferByAddress(handler, fAddr, addr, amount)

	if ret != ErrTransferStringToBigInt && ret != ErrTransferSubBalance && ret != SuccessTransferFunc { // Unepected to happen, should not to be on chain
		logging.VLog().WithFields(logrus.Fields{
			"height":      engine.ctx.block.Height(),
			"txhash":      engine.ctx.tx.Hash().String(),
			"fromAddress": fAddr.String(),
			"toAddress":   addr.String(),
			"value":       transferValueStr,
			"ret":         ret,
		}).Error("Unexpected error")
	}

	recordTransferEvent(ret, fAddr.String(), addr.String(), recordValue, height, wsState, txHash)
	return ret
}

// VerifyAddressFunc verify address is valid
//export VerifyAddressFunc
func VerifyAddressFunc(handler unsafe.Pointer, address *C.char, gasCnt *C.size_t) int {
	// calculate Gas.
	*gasCnt = C.size_t(VerifyAddressGasBase)

	addr, err := core.AddressParse(C.GoString(address))
	if err != nil {
		return 0
	}
	return int(addr.Type())
}

// GetPreBlockHashFunc returns hash of the block before current tail by n
//export GetPreBlockHashFunc
func GetPreBlockHashFunc(handler unsafe.Pointer, offset C.ulonglong,
	gasCnt *C.size_t, result **C.char, exceptionInfo **C.char) int {
	*result = nil
	*exceptionInfo = nil
	n := uint64(offset)
	if n > uint64(maxBlockOffset) {
		*exceptionInfo = C.CString("Blockchain.GetPreBlockHash(), argument out of range")
		return C.CVM_EXCEPTION_ERR
	}

	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx == nil || engine.ctx.block == nil || engine.ctx.state == nil {
		logging.VLog().Error("Unexpected error: failed to get engine.")
		return C.CVM_UNEXPECTED_ERR
	}
	wsState := engine.ctx.state
	// calculate Gas.
	*gasCnt = C.size_t(GetPreBlockHashGasBase)

	//get height
	height := engine.ctx.block.Height()
	if n >= height { // have checked it in lib js
		logging.VLog().WithFields(logrus.Fields{
			"height": height,
			"offset": n,
		}).Debug("offset is large than height")
		*exceptionInfo = C.CString("Blockchain.GetPreBlockHash(), argument[offset] is large than current height")
		return C.CVM_EXCEPTION_ERR
	}
	height -= n

	blockHash, err := wsState.GetBlockHashByHeight(height)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"height": height,
			"err":    err,
		}).Error("Unexpected error: Failed to get block hash from wsState by height")
		return C.CVM_UNEXPECTED_ERR
	}

	*result = C.CString(byteutils.Hex(blockHash))
	return C.CVM_SUCCESS
}

//getHandlerByAddress
func getHandlerByAddress(ws WorldState, address string) (*Handler, error) {
	addr, err := core.AddressParse(address)
	if err != nil {
		return nil, err
	}
	contract, err := core.GetContract(addr, ws)
	if err != nil {
		return nil, err
	}

	birthTx, err := core.GetTransaction(contract.BirthTransaction(), ws)
	if err != nil {
		return nil, err
	}
	//dataMsg := birthTx.GetData().GetMsg()
	//deployBytes, err := snappy.Decode(nil, dataMsg)
	//if err != nil {
	//	return nil, err
	//}
	deploy, err := core.LoadDeployHandler(birthTx.GetData().GetMsg())
	if err != nil {
		return nil, err
	}
	return &Handler{deploy, contract}, nil
}

// GetContractSourceFunc get contract code by address
//export GetContractSourceFunc
func GetContractSourceFunc(handler unsafe.Pointer, address *C.char, gasCnt *C.size_t) *C.char {
	// calculate Gas.
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx.block == nil {
		logging.VLog().Error("Failed to get engine.")
		return nil
	}
	*gasCnt = C.size_t(GetContractSourceGasBase)
	ws := engine.ctx.state

	contractHandler, err := getHandlerByAddress(ws, C.GoString(address))
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"address": address,
			"err":     err,
		}).Error("getHandlerByAddress err")

		return nil
	}

	return C.CString(contractHandler.deploy.Source)
}

//packErrInfoAndSetHead->packInner
func setHeadErrAndLog(e *V8Engine, index uint32, err error, result string, flag bool) string {
	formatEx := InnerTransactionErrPrefix + err.Error() + InnerTransactionResult + result + InnerTransactionErrEnding
	rStr := fmt.Sprintf(formatEx, index)

	if flag == true {
		logging.VLog().Errorf(rStr)
	}
	if index == 0 {
		e.innerErrMsg = result
		e.innerErr = err
	} else {
		setHeadV8ErrMsg(e.ctx.head, err, result)
	}
	return rStr
}

//setHeadV8ErrMsg set head node err info
func setHeadV8ErrMsg(handler unsafe.Pointer, err error, result string) {
	if handler == nil {
		logging.VLog().Errorf("invalid handler is nil")
		return
	}
	engine := getEngineByEngineHandler(handler)
	if engine == nil {
		logging.VLog().Errorf("not found the v8 engine")
		return
	}
	engine.innerErr = err
	engine.innerErrMsg = result
}

//createInnerContext is private func only in InnerContractFunc
func createInnerContext(engine *V8Engine, fromAddr *core.Address, toAddr *core.Address, value *big.Int, funcName string, args string) (innerCtx *Context, err error) {
	ws := engine.ctx.state
	contract, err := core.GetContract(toAddr, ws)
	if err != nil {
		return nil, err
	}
	ok, err := contract.CheckPermission(state.FuncAuthType+"_"+"", engine.ctx.tx.To().String(), funcName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("call inner contract function permission denied")
	}
	logging.VLog().Infof("inner contract:%v", contract.ContractVersion()) //FIXME: ver limit
	handlerType := core.ContractInvokeTx
	callHandler, err := core.NewCallHandler(funcName, args)
	if err != nil {
		return nil, err
	}
	newPayloadHex, err := callHandler.ToBytes()
	if err != nil {
		return nil, err
	}

	innerToAddr := toAddr
	parentTx := engine.ctx.tx
	newTx, err := parentTx.NewInnerTransaction(fromAddr, innerToAddr, value, handlerType, newPayloadHex)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"from":  fromAddr.String(),
			"to":    toAddr.String(),
			"value": value.String(),
			"err":   err,
		}).Error("failed to create new tx")
		return nil, err
	}
	var head unsafe.Pointer
	if engine.ctx.head == nil {
		head = unsafe.Pointer(engine.v8engine)
	} else {
		head = engine.ctx.head
	}
	newCtx, err := NewInnerContext(engine.ctx.block, newTx, contract, engine.ctx.state, head, engine.ctx.index+1, engine.ctx.contextRand)
	if err != nil {
		return nil, err
	}
	return newCtx, nil
}

//recordInnerContractEvent private func only in InnerContractFunc
func recordInnerContractEvent(e *V8Engine, err error, from string, to string, value string, innerFunc string, innerArgs string, wsState WorldState, txHash byteutils.Hash) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	event := &InnerContractEvent{
		From:     from,
		To:       to,
		Value:    value,
		Err:      errStr,
		Function: innerFunc,
		Args:     innerArgs,
	}

	eData, errMarshal := json.Marshal(event)
	if errMarshal != nil {
		logging.VLog().WithFields(logrus.Fields{
			"from":  from,
			"to":    to,
			"value": value,
			"err":   errStr,
		}).Fatal("failed to marshal TransferFromContractEvent")
	}
	wsState.RecordEvent(txHash, &state.Event{Topic: core.TopicInnerContract, Data: string(eData)})
}

// InnerContractFunc multi run contract. output[c standard]: if err return nil else return "*"
//export InnerContractFunc
func InnerContractFunc(handler unsafe.Pointer, address *C.char, funcName *C.char, v *C.char, args *C.char, gasCnt *C.size_t) *C.char {
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx.block == nil {
		logging.VLog().Errorf(ErrEngineNotFound.Error())
		return nil
	}
	index := engine.ctx.index
	if engine.ctx.index >= uint32(MaxInnerContractLevel) {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, ErrMaxInnerContractLevelLimit.Error(), true)
		return nil
	}
	gasSum := uint64(InnerContractGasBase)
	*gasCnt = C.size_t(gasSum)
	ws := engine.ctx.state

	addr, err := core.AddressParse(C.GoString(address))
	if err != nil {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, err.Error(), true)
		return nil
	}

	var (
		newCtx   *Context
		deploy   *core.DeployHandler
		fromAddr *core.Address
	)

	parentTx := engine.ctx.tx
	innerTxValueStr := C.GoString(v)

	contractHandler, err := getHandlerByAddress(ws, C.GoString(address))
	if err != nil {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, err.Error(), true)
		return nil
	}
	deploy = contractHandler.deploy

	//fromAddr = engine.ctx.tx.From()
	from := engine.ctx.contract.Address()
	fromAddr, err = core.AddressParseFromBytes(from)
	if err != nil {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, err.Error(), true)
		return nil
	}
	//transfer
	toValue, flg := new(big.Int).SetString(innerTxValueStr, 10)
	if !flg {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, err.Error(), true)
		return nil
	}
	iRet := TransferByAddress(handler, fromAddr, addr, toValue)
	if iRet != 0 {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, ErrInnerTransferFailed.Error(), true)
		return nil
	}

	newCtx, err = createInnerContext(engine, fromAddr, addr, big.NewInt(0), C.GoString(funcName), C.GoString(args))
	if err != nil {
		setHeadErrAndLog(engine, index, core.ErrExecutionFailed, err.Error(), true)
		return nil
	}

	remainInstruction, remainMem := engine.GetCVMLeftResources()
	if remainInstruction <= uint64(InnerContractGasBase) {
		logging.VLog().WithFields(logrus.Fields{
			"remainInstruction": remainInstruction,
			"mem":               remainMem,
			"err":               ErrInnerInsufficientGas.Error(),
		}).Error("failed to prepare create cvm")
		setHeadErrAndLog(engine, index, ErrInsufficientGas, "null", false)
		return nil
	} else {
		remainInstruction -= InnerContractGasBase
	}
	if remainMem <= 0 {
		logging.VLog().WithFields(logrus.Fields{
			"remainInstruction": remainInstruction,
			"mem":               remainMem,
			"err":               ErrInnerInsufficientMem.Error(),
		}).Error("failed to prepare create cvm")
		setHeadErrAndLog(engine, index, ErrExceedMemoryLimits, "null", false)
		return nil
	}

	logging.VLog().Debugf("begin create New V8,intance:%v, mem:%v", remainInstruction, remainMem)
	engineNew := NewV8Engine(newCtx)
	defer engineNew.Dispose()
	engineNew.SetExecutionLimits(remainInstruction, remainMem)

	innerFunc := C.GoString(funcName)
	innerArgs := C.GoString(args)
	val, err := engineNew.Call(string(deploy.Source), innerFunc, innerArgs)
	gasCout := engineNew.ExecutionInstructions()
	gasSum += gasCout
	*gasCnt = C.size_t(gasSum)
	recordInnerContractEvent(engine, err, fromAddr.String(), addr.String(), "0", innerFunc, innerArgs, ws, parentTx.Hash())
	if err != nil {
		if err == core.ErrInnerExecutionFailed {
			logging.VLog().Errorf("check inner err, engine index:%v", index)
		} else {
			errLog := setHeadErrAndLog(engine, index, err, val, false)
			logging.VLog().Errorf(errLog)
		}
		return nil
	}

	logging.VLog().Infof("end cal val:%v,gascount:%v,gasSum:%v, engine index:%v", val, gasCout, gasSum, index)
	return C.CString(string(val))
}

// GetTxRandomFunc return random
//export GetTxRandomFunc
func GetTxRandomFunc(handler unsafe.Pointer, gasCnt *C.size_t, result **C.char, exceptionInfo **C.char) int {
	engine, _ := getEngineByStorageHandler(uint64(uintptr(handler)))
	if engine == nil || engine.ctx.block == nil {
		logging.VLog().Error("random.GetTxRandomFunc Unexpected error: failed to get engine")
		return C.CVM_UNEXPECTED_ERR
	}
	// calculate Gas.
	*gasCnt = C.size_t(GetTxRandomGasBase)

	if engine.ctx.contextRand == nil {
		logging.VLog().WithFields(logrus.Fields{
			"height": engine.ctx.block.Height(),
		}).Error("ContextRand is nil")
		*exceptionInfo = C.CString("random.GetTxRandomFunc(), contextRand is nil")
		return C.CVM_EXCEPTION_ERR
	}

	if engine.ctx.contextRand.rand == nil {
		txhash := engine.ctx.tx.Hash().String()
		if len(txhash) == 0 {
			logging.VLog().WithFields(logrus.Fields{
				"height": engine.ctx.block.Height(),
			}).Error("transaction hash is nil")
			*exceptionInfo = C.CString("random.GetTxRandomFunc(), randomSeed len is zero")
			return C.CVM_EXCEPTION_ERR
		}

		m := md5.New()
		io.WriteString(m, txhash)
		seed := int64(binary.BigEndian.Uint64(m.Sum(nil)))
		engine.ctx.contextRand.rand = rand.New(rand.NewSource(seed))
	}

	return C.CVM_SUCCESS
}
