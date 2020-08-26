package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

// Const.
const (
	SourceTypeJavaScript = "js"
	AllPrivateAuth       = "0"
	AllPublicAuth        = "1"
	DefaultAuthFlag      = AllPrivateAuth
)

// deploy Handler
type DeployHandler struct {
	SourceType string
	Source     string
	Args       string
	AuthFlag   string
}

// LoadDeployHandler from bytes
func LoadDeployHandler(bytes []byte) (*DeployHandler, error) {
	handler := &DeployHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewDeployHandler(handler.Source, handler.SourceType, handler.Args, handler.AuthFlag)
}

// NewDeployHandler with source & args
func NewDeployHandler(source, sourceType, args, authFlag string) (*DeployHandler, error) {
	if len(source) == 0 {
		return nil, ErrInvalidDeploySource
	}

	if sourceType != SourceTypeJavaScript {
		return nil, ErrInvalidDeploySourceType
	}

	if err := CheckContractArgs(args); err != nil {
		return nil, ErrInvalidArgument
	}

	flag := ""
	if len(authFlag) == 0 {
		flag = DefaultAuthFlag
	} else {
		switch authFlag {
		case AllPrivateAuth,
			AllPublicAuth:
			flag = authFlag
		default:
			return nil, ErrInvalidContractAuthFlag
		}
	}
	return &DeployHandler{
		Source:     source,
		SourceType: sourceType,
		Args:       args,
		AuthFlag:   flag,
	}, nil
}

// ToBytes serialize handler
func (handler *DeployHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *DeployHandler) BaseGasCount() *big.Int {
	return big.NewInt(60)
}

func (handler *DeployHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	txFee := config.ContractTxFee
	minVolume := new(big.Int).SetInt64(int64(config.DeployContractMinVolume))
	baseContractFee := new(big.Int).Add(txFee, minVolume)
	if tx.value.Cmp(baseContractFee) < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"required value": baseContractFee.String(),
			"real value":     tx.value.String(),
		}).Error("contract fee is too low")
		return ErrContractFeeTooLow
	}
	return nil
}

// Execute deploy handler in tx, deploy a new contract
func (handler *DeployHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	if !tx.From().Equals(tx.To()) {
		return zero, "", ErrContractTransactionAddressNotEqual
	}

	// payloadGasLimit <= 0, v8 engine not limit the execution instructions
	if limitedGas.Cmp(zero) <= 0 {
		return zero, "", ErrOutOfGasLimit
	}
	addr, err := tx.GenerateContractAddress()
	if err != nil {
		return zero, "", err
	}

	contract, err := ws.CreateContractAccount(addr.Bytes(), tx.Hash(), "1.0.0")
	if err != nil {
		return zero, "", err
	}

	fromAcc, err := ws.GetOrCreateAccount(tx.from.address) // sender account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get from account")
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

	engine, err := block.cvm.CreateEngine(block, tx, contract, ws)
	if err != nil {
		return zero, "", err
	}
	defer engine.Dispose()

	if err := engine.SetExecutionLimits(limitedGas.Uint64(), DefaultLimitsOfTotalMemorySize); err != nil {
		return zero, "", err
	}

	// Deploy and Init.
	result, exeErr := engine.DeployAndInit(handler.Source, handler.Args)
	gasCount := engine.ExecutionInstructions()
	instructions := big.NewInt(int64(gasCount))

	if exeErr != nil && exeErr == ErrExecutionFailed && len(result) > 0 {
		exeErr = fmt.Errorf("Deploy: %s", result)
	}

	// 判断有没有继承，有继承才做
	fcaBytes, err := contract.Get(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFCA))
	if err != nil {
		if err == trie.ErrNotFound {
			logging.VLog().WithFields(logrus.Fields{
				"tx.hash":      tx.Hash(),
				"instructions": instructions,
				"limitedGas":   limitedGas,
			}).Debug("not found fca. deploy success.")
			return instructions, result, exeErr
		}
		return zero, "", err
	}
	if len(fcaBytes) <= 0 {
		logging.VLog().WithFields(logrus.Fields{
			"tx.hash":      tx.Hash(),
			"instructions": instructions,
			"limitedGas":   limitedGas,
		}).Debug("record gas of v8")
		return instructions, result, exeErr
	}

	//
	inContractAddr, err := AddressParse(string(fcaBytes[:]))
	if err != nil {
		logging.VLog().Error("address parse err")
		return zero, "", err
	}
	inContract, err := ws.GetOrCreateAccount(inContractAddr.Bytes())
	if err != nil {
		logging.VLog().Error("get account failed.")
		return zero, "", err
	}
	if inContract.State() != state.AccountStateFix {
		return zero, "", ErrContractStateCheckFailed
	}

	// 修改继承信息，到底怎么存还没有
	iter, err := contract.Iterator(trie.HashDomainsPrefix(state.ContractVariableMeta_Prefix))
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Iterator failed.")
		return zero, "", err
	}
	for {
		ret, err := iter.Next()
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Error("Get failed.")
			break
		}
		if !ret {
			break
		}

		var meta state.InheritMetaInfo
		if err = json.Unmarshal(iter.Value(), &meta); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Error("Iterator failed.")
			continue
		}
		if meta.InheritField != "" {
			fi := strings.Split(meta.InheritField, "|")
			if len(fi) < 2 {
				logging.VLog().Error("less 2 string failed.")
				return zero, "", err
			}
			// 继承了
			inContractAddr, err := AddressParse(string(fi[0]))
			if err != nil {
				logging.VLog().Error("address parse err")
				continue
			}
			inContract, err := ws.GetOrCreateAccount(inContractAddr.Bytes())
			if err != nil {
				logging.VLog().Error("get account failed.")
				continue
			}
			metaBytes, err := inContract.Get(trie.HashDomains(state.ContractVariableMeta_Prefix, fi[1]))
			if err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("Get failed.")
				continue
			}
			var imeta state.InheritMetaInfo
			if err = json.Unmarshal(metaBytes, &imeta); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("json unmarshal failed.")
				continue
			}
			str := contract.Address().Base58() + "|" + meta.Field
			if imeta.InheritedField == nil {
				imeta.InheritedField = make([]string, 0)
			}
			imeta.InheritedField = append(imeta.InheritedField, str)
			if metaBytes, err = json.Marshal(imeta); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("json unmarshal failed.")
				continue
			}
			if err = inContract.Put(trie.HashDomains(state.ContractVariableMeta_Prefix, fi[1]), metaBytes); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("Put failed.")
				continue
			}
		}
	}

	// 恢复资产
	inBirthTx, err := GetTransaction(inContract.BirthTransaction(), ws)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("GetTransaction failed.")
		return zero, "", err
	}
	inFromAccount, err := ws.GetOrCreateAccount(inBirthTx.from.Bytes())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("GetOrCreateAccount failed.")
		return zero, "", err
	}
	balance := inContract.Balance()
	if err := inContract.SubBalance(balance); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Sub contract balance error")
		return zero, "", err
	}
	if err := inFromAccount.AddBalance(balance); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Add contract balance back to deployer error")
		return zero, "", err
	}
	if err := inContract.SetState(state.AccountStateClosed); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("contract change state error.")
		return zero, "", err
	}

	logging.VLog().WithFields(logrus.Fields{
		"tx.hash":      tx.Hash(),
		"instructions": instructions,
		"limitedGas":   limitedGas,
	}).Debug("record gas of v8")

	return instructions, result, exeErr
}

func (handler *DeployHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	addr, err := tx.GenerateContractAddress()
	if err != nil {
		return err
	}
	contract, err := ws.GetOrCreateAccount(addr.Bytes())
	if err != nil {
		return err
	}
	rule := ""
	switch handler.AuthFlag {
	case AllPrivateAuth:
		rule = state.FuncForbidRule
	case AllPublicAuth:
		rule = state.FuncAllowRule
	}
	if err := contract.ModifyPermission(state.FuncAuthType+"_"+state.AddCommand, state.FuzzyAuthorize, state.FuzzyAuthorize, rule); err != nil {
		return err
	}

	return nil
}
