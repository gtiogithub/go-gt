package core

import (
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"math/big"
)

type AuthorizeCmd struct {
	Command  string
	FuncName string
	Rule     string
}

// Authorize Handler
type AuthorizeHandler struct {
	Commands []AuthorizeCmd
	Address  string
	AuthType string
}

// LoadDeployHandler from bytes
func LoadAuthorizeHandler(bytes []byte) (*AuthorizeHandler, error) {
	handler := &AuthorizeHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewAuthorizeHandler(handler.Commands, handler.Address, handler.AuthType)
}

// NewDeployHandler with source & args
func NewAuthorizeHandler(commands []AuthorizeCmd, address, authType string) (*AuthorizeHandler, error) {
	handler := &AuthorizeHandler{}

	if len(authType) == 0 {
		authType = state.DefaultAuthType
	}
	cmds := make([]AuthorizeCmd, 0)
	for _, command := range commands {
		cmd := AuthorizeCmd{}
		switch authType {
		case state.FuncAuthType:
			switch command.Rule {
			case state.FuncForbidRule,
				state.FuncAllowRule:
				cmd.Rule = command.Rule
			default:
				return nil, ErrInvalidFuncRule
			}

			if address != state.FuzzyAuthorize {
				_, err := AddressParse(address)
				if err != nil {
					return nil, ErrInvalidAuthorizeAddress
				}
			}
			handler.Address = address

		case state.RoleAuthType:
			switch command.Rule {
			case state.RoleAddRule,
				state.RoleModifyRule,
				state.RoleAddAndModifyRule,
				state.RoleDelRule,
				state.RoleAddAndDelRule,
				state.RoleModifyAndDelRule,
				state.RoleAddModifyAndDelRule:
				cmd.Rule = command.Rule
			default:
				return nil, ErrInvalidRoleRule
			}

			_, err := AddressParse(address)
			if err != nil {
				return nil, ErrInvalidAuthorizeAddress
			}
			handler.Address = address

		default:
			return nil, ErrInvalidAuthorizeType
		}

		if len(command.FuncName) == 0 {
			return nil, ErrInvalidArgument
		}
		if command.FuncName != state.FuzzyAuthorize {
			if PublicFuncNameChecker.MatchString(command.FuncName) == false {
				return nil, ErrInvalidFunctionName
			}
		}
		cmd.FuncName = command.FuncName

		switch command.Command {
		case state.AddCommand,
			state.ModifyCommand,
			state.DelCommand:
			cmd.Command = command.Command
		default:
			return nil, ErrInvalidRoleRule
		}
		cmds = append(cmds, cmd)
	}

	handler.AuthType = authType
	handler.Commands = cmds
	return handler, nil
}

// ToBytes serialize handler
func (handler *AuthorizeHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *AuthorizeHandler) BaseGasCount() *big.Int {
	return big.NewInt(60)
}

func (handler *AuthorizeHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	contractAcc, err := ws.GetContractAccount(tx.to.address)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get contract account")
		return err
	}

	if contractAcc.Closed() {
		return errors.New("the contract had been closed")
	}
	for _, command := range handler.Commands {
		if state.FuzzyAuthorize != command.FuncName {
			//check function name
			byteFunList, err := contractAcc.Get(trie.HashDomains(state.ContractMeta_Prefix, state.ContractFunList))
			if err != nil && err != cdb.ErrKeyNotFound {
				return err
			}
			index := -1
			if byteFunList != nil {
				funList := make([]string, 0)
				if err = json.Unmarshal(byteFunList, &funList); err != nil {
					return err
				}
				for i := 0; i < len(funList); i++ {
					if funList[i] == command.FuncName {
						index = i
						break
					}
				}
			}
			if index == -1 {
				return errors.New("invalid function name")
			}
		}
	}

	return nil
}

// Execute deploy handler in tx, deploy a new contract
func (handler *AuthorizeHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	contract, err := GetContract(tx.to, ws)
	if err != nil {
		return zero, "", err
	}

	birthTx, err := GetTransaction(contract.BirthTransaction(), ws)
	if err != nil {
		return zero, "", err
	}

	for _, command := range handler.Commands {
		if !byteutils.Equal(tx.from.Bytes(), birthTx.from.Bytes()) { //check owner
			// check function authorization
			if handler.AuthType != state.FuncAuthType {
				return zero, "", errors.New("No function authorization")
			}
			ok, err := contract.CheckPermission(state.RoleAuthType+"_"+command.Command, tx.from.String(),
				command.FuncName)
			if err != nil {
				return zero, "", err
			}
			if !ok {
				return zero, "", errors.New("No function authorization")
			}
		}

		if err = contract.ModifyPermission(handler.AuthType+"_"+command.Command, handler.Address,
			command.FuncName, command.Rule); err != nil {
			return zero, "", err
		}
	}

	return zero, "", nil
}

func (handler *AuthorizeHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	return nil
}
