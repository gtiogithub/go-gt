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

package rpc

import (
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gt.pro/gtio/go-gt/account"
	"gt.pro/gtio/go-gt/conf"
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/crypto"
	"gt.pro/gtio/go-gt/network"
	rpcpb "gt.pro/gtio/go-gt/rpc/pb"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
)

var (
	CoinbaseAddressIsNilError          = errors.New("the coinbase address is nil")
	PassphraseLengthIsZeroError        = errors.New("passphrase length is 0")
	MiningProcessingError              = errors.New("mining is in progress, please stop mining before starting")
	HasBeenStoppedError                = errors.New("the mining has been stopped, please restart")
	MessageLengthIsZeroError           = errors.New("message length must greater than 0")
	SignatureLengthIsZeroError         = errors.New("signature length must greater than 0")
	NotHexStringError                  = errors.New("not hex string")
	LogLevelLengthIsZeroError          = errors.New("the log level cannot be empty")
	LogAgeIsZeroError                  = errors.New("log age must be greater than 0")
	RotationTimeIsZeroError            = errors.New("rotation time must be greater than 0")
	LogPathIsEmptyError                = errors.New("the log path cannot be empty")
	BalanceNotEnoughError              = errors.New("balance not enough")
	TxPoolIsNilError                   = errors.New("tx poll is nil")
	DataIsNotHexStringError            = errors.New("data must be a hex string")
	PrivateKeyIsBlankError             = errors.New("private key is blank")
	PrivateKeyIsNotHexStrError         = errors.New("private key must be hex string")
	RotationTimeGreaterThanMaxAgeError = errors.New("rotation time must be less than max age")
	TxNonceLessThanAccountNonceError   = errors.New("transaction nonce must be greater than account nonce")
	FromAddressIsContractAddressError  = errors.New("from address cannot be a contract address")
	AddressIsContractAddressError      = errors.New("address cannot be a contract address")
)

// AdminService implements the RPC admin service interface.
type AdminService struct {
	server  GRPCServer
	gt      core.Gt
	log     *logrus.Logger
	logConf *logging.LogConfig
	zn      sync.Mutex //zero nonce send lock
}

func (s *AdminService) StartMining(ctx context.Context, req *rpcpb.PassphraseRequest) (*rpcpb.BoolResponse, error) {
	if len(req.Passphrase) == 0 {
		return &rpcpb.BoolResponse{Result: false}, PassphraseLengthIsZeroError
	}
	consensus := s.gt.Consensus()
	if consensus.IsEnable() {
		logging.CLog().Debug("mining is in progress ......")
		return &rpcpb.BoolResponse{Result: false}, MiningProcessingError
	}

	address := consensus.Coinbase()
	if address == nil {
		logging.CLog().Debug(CoinbaseAddressIsNilError.Error())
		return &rpcpb.BoolResponse{Result: false}, CoinbaseAddressIsNilError
	}
	err := consensus.EnableMining(req.Passphrase)
	if err != nil {
		return &rpcpb.BoolResponse{Result: false}, err
	}
	return &rpcpb.BoolResponse{Result: true}, nil
}

func (s *AdminService) StopMining(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.BoolResponse, error) {
	if !s.gt.Consensus().IsEnable() {
		logging.CLog().Debug("has been stopped")
		return &rpcpb.BoolResponse{Result: false}, HasBeenStoppedError
	}
	s.gt.Consensus().Stop()
	return &rpcpb.BoolResponse{Result: true}, nil
}

// Accounts is the RPC API handler.
func (s *AdminService) Accounts(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.AccountsResponse, error) {

	accs := s.gt.AccountManager().GetAllAddress()

	resp := new(rpcpb.AccountsResponse)
	addrs := make([]string, len(accs))
	for index, addr := range accs {
		addrs[index] = addr.String()
	}
	resp.Addresses = addrs
	return resp, nil
}

// NewAccount generate a new address with passphrase
func (s *AdminService) NewAccount(ctx context.Context, req *rpcpb.PassphraseRequest) (*rpcpb.NewAccountResponse, error) {
	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	addr, memo, err := s.gt.AccountManager().NewAccount([]byte(req.Passphrase))
	if err != nil {
		return nil, err
	}
	return &rpcpb.NewAccountResponse{Address: addr.String(), Memo: memo}, nil
}

// NewAccount create a new account with passphrase
func (s *AdminService) UpdateAccount(ctx context.Context, req *rpcpb.UpdateAccountRequest) (*rpcpb.BoolResponse, error) {
	oldPassphrase := req.OldPassphrase
	newPassphrase := req.NewPassphrase
	if len(oldPassphrase) == 0 || len(newPassphrase) == 0 {
		return &rpcpb.BoolResponse{Result: false}, PassphraseLengthIsZeroError
	}
	addr, err := s.gt.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return &rpcpb.BoolResponse{Result: false}, err
	}
	err = s.gt.AccountManager().UpdateAccount(addr, []byte(oldPassphrase), []byte(newPassphrase))
	return &rpcpb.BoolResponse{Result: true}, err
}

// NewAccount create a new account with passphrase
func (s *AdminService) ImportAccount(ctx context.Context, req *rpcpb.PrivKeyAndPassphrase) (*rpcpb.Address, error) {
	if len(req.PriKey) == 0 {
		return nil, PrivateKeyIsBlankError
	}

	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	privBytes, err := byteutils.FromHex(req.PriKey)
	if err != nil {
		return nil, PrivateKeyIsNotHexStrError
	}

	address, err := s.gt.AccountManager().ImportAccount(privBytes, []byte(req.Passphrase))
	if err != nil {
		return nil, err
	}
	return &rpcpb.Address{Address: address.String()}, err
}

//GeneratePrivateKey return the key pair
func (s *AdminService) ExportPrivateKey(ctx context.Context, req *rpcpb.ExportPrivateKeyRequest) (*rpcpb.PrivateKey, error) {
	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	addr, err := s.gt.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return nil, err
	}

	bytes, err := s.gt.AccountManager().GetPrivateKey(addr, []byte(req.Passphrase))
	if err != nil {
		return nil, err
	}
	hexPrivKey := byteutils.Hex(bytes)
	return &rpcpb.PrivateKey{PriKey: hexPrivKey}, nil
}

// UnlockAccount unlock address with the passphrase
func (s *AdminService) UnlockAccount(ctx context.Context, req *rpcpb.UnlockAccountRequest) (*rpcpb.BoolResponse, error) {
	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	addr, err := s.gt.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return nil, err
	}

	duration := time.Duration(req.Duration * uint64(time.Second))
	err = s.gt.AccountManager().UnLock(addr, []byte(req.Passphrase), duration)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return nil, err
	}

	metricsUnlockSuccess.Mark(1)
	return &rpcpb.BoolResponse{Result: true}, nil
}

// LockAccount lock address
func (s *AdminService) LockAccount(ctx context.Context, req *rpcpb.LockAccountRequest) (*rpcpb.BoolResponse, error) {

	addr, err := s.gt.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		return nil, err
	}

	err = s.gt.AccountManager().Lock(addr)
	if err != nil {
		return nil, err
	}

	return &rpcpb.BoolResponse{Result: true}, nil
}

// SendTransaction is the RPC API handler.
func (s *AdminService) SendTransaction(ctx context.Context, req *rpcpb.TransactionRequest) (*rpcpb.TransactionHash, error) {
	tx, err := parseTransaction(s.gt, req)
	if err != nil {
		return nil, err
	}

	if tx.Nonce() == 0 {
		s.zn.Lock()
		defer s.zn.Unlock()
		s.autoGenNonceForZeroNonceTransaction(tx)
	}

	if err = s.gt.AccountManager().SignTx(tx.From(), tx); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"txHash": tx.Hash().String(),
			"error":  err.Error(),
		}).Error("sign error")
		return nil, err
	}

	return handleTransactionResponse(s.gt, tx)
}

func handleTransactionResponse(gt core.Gt, tx *core.Transaction) (resp *rpcpb.TransactionHash, err error) {

	tailBlock := gt.BlockChain().TailBlock()
	acc, err := tailBlock.GetAccount(tx.From().Bytes())
	if err != nil {
		return nil, err
	}

	if tx.Nonce() <= acc.Nonce() {
		return nil, errors.New("transaction's nonce is invalid, should bigger than the from's nonce")
	}

	if tx.Type() == core.ContractInvokeTx || tx.Type() == core.ContractChangeStateTx {
		if _, err := tailBlock.CheckContract(tx.To()); err != nil {
			return nil, err
		}
	}

	// push and broadcast tx
	if err := gt.BlockChain().TxPool().AddAndBroadcast(tx); err != nil {
		return nil, err
	}

	return &rpcpb.TransactionHash{Hash: tx.Hash().String()}, nil
}

// Sign is the RPC API handler.
func (s *AdminService) Sign(ctx context.Context, req *rpcpb.SignHashRequest) (*rpcpb.SignHashResponse, error) {

	addr, err := s.gt.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		return nil, err
	}
	hash := req.Message
	if len(hash) == 0 {
		return nil, MessageLengthIsZeroError
	}
	hashBytes, err := byteutils.FromHex(hash)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"message": hash,
			"error":   err,
		}).Debug("the hash must be hex string")
		return nil, NotHexStringError
	}

	data, err := s.gt.AccountManager().Sign(addr, hashBytes)
	if err != nil {
		return nil, err
	}
	sign := byteutils.Hex(data)

	return &rpcpb.SignHashResponse{Data: sign}, nil
}

// VerifyMessage sign msg
func (s *AdminService) VerifyMessage(ctx context.Context, req *rpcpb.VerifyMessageRequest) (*rpcpb.BoolResponse, error) {
	if len(req.Signature) == 0 {
		return &rpcpb.BoolResponse{Result: false}, SignatureLengthIsZeroError
	}

	if len(req.Message) == 0 {
		return &rpcpb.BoolResponse{Result: false}, MessageLengthIsZeroError
	}
	addr, err := s.gt.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		return nil, err
	}

	sign, err := byteutils.FromHex(req.Signature)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"sign":  req.Signature,
			"error": err,
		}).Debug("the sign must be hex string")
		return &rpcpb.BoolResponse{Result: false}, NotHexStringError
	}

	msg, err := byteutils.FromHex(req.Message)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"message": req.Message,
			"error":   err,
		}).Debug("the message must be hex string")
		return &rpcpb.BoolResponse{Result: false}, NotHexStringError
	}

	result, err := s.gt.AccountManager().Verify(addr, msg, sign)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"sign":    req.Signature,
			"message": req.Message,
			"result":  result,
			"error":   err,
		}).Debug("verify signature error")
	}
	return &rpcpb.BoolResponse{Result: result}, err
}

// SignTransactionWithPassphrase is the RPC API handler.
func (s *AdminService) SignTransactionWithPassphrase(ctx context.Context, req *rpcpb.SignTransactionPassphraseRequest) (*rpcpb.SignTransactionPassphraseResponse, error) {
	gt := s.gt
	tx, err := parseTransaction(gt, req.Transaction)
	if err != nil {
		return nil, err
	}
	if tx.Nonce() == 0 {
		s.zn.Lock()
		defer s.zn.Unlock()
		s.autoGenNonceForZeroNonceTransaction(tx)
	}
	if err := gt.AccountManager().SignTxWithPassphrase(tx.From(), tx, []byte(req.Passphrase)); err != nil {
		return nil, err
	}
	pbMsg, err := tx.ToProto()
	if err != nil {
		return nil, err
	}
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		return nil, err
	}

	return &rpcpb.SignTransactionPassphraseResponse{Data: data}, nil
}

// SendTransactionWithPassphrase is the RPC API handler.
func (s *AdminService) SendTransactionWithPassphrase(ctx context.Context, req *rpcpb.SendTransactionPassphraseRequest) (*rpcpb.TransactionHash, error) {
	gt := s.gt
	tx, err := parseTransaction(gt, req.Transaction)
	if err != nil {
		return nil, err
	}

	if tx.Nonce() == 0 {
		s.zn.Lock()
		defer s.zn.Unlock()
		s.autoGenNonceForZeroNonceTransaction(tx)
	}

	if err := gt.AccountManager().SignTxWithPassphrase(tx.From(), tx, []byte(req.Passphrase)); err != nil {
		return nil, err
	}

	return handleTransactionResponse(gt, tx)
}

//Stop the server
func (s *AdminService) Stop(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BoolResponse, error) {
	//Asynchronous close, first response to client request
	go func() {
		s.gt.Stop()
	}()
	return &rpcpb.BoolResponse{Result: true}, nil
}

//Logging Logging Info
func (s *AdminService) Logging(ctx context.Context, req *rpcpb.LoggingInfo) (*rpcpb.LoggingInfo, error) {
	path := s.logConf.LogFile
	if len(req.LogPath) == 0 {
		if !filepath.IsAbs(path) {
			path, _ = filepath.Abs(path)
		}
	}
	if len(req.LogPath) == 0 && len(req.LogLevel) == 0 && req.LogAge == 0 && req.RotationTime == 0 {
		return &rpcpb.LoggingInfo{
			LogLevel:     s.logConf.LogLevel,
			LogPath:      path,
			LogAge:       s.logConf.LogAge,
			RotationTime: uint32(s.logConf.LogRotationTime),
		}, nil
	}

	s.zn.Lock()
	defer s.zn.Unlock()

	if len(req.LogLevel) != 0 && len(req.LogPath) == 0 && req.LogAge == 0 && req.RotationTime == 0 {
		level, err := logrus.ParseLevel(req.LogLevel)
		if err != nil {
			return nil, err
		}
		s.log.SetLevel(level)
		s.logConf.LogLevel = req.LogLevel
		return &rpcpb.LoggingInfo{
			LogLevel:     level.String(),
			LogPath:      path,
			LogAge:       s.logConf.LogAge,
			RotationTime: uint32(s.logConf.LogRotationTime),
		}, nil
	}

	if len(req.LogLevel) == 0 {
		return nil, LogLevelLengthIsZeroError
	}
	if req.LogAge == 0 {
		return nil, LogAgeIsZeroError
	}
	if req.RotationTime == 0 {
		return nil, RotationTimeIsZeroError
	}

	if req.RotationTime > req.LogAge {
		return nil, RotationTimeGreaterThanMaxAgeError
	}

	path = req.LogPath
	if len(path) == 0 {
		return nil, LogPathIsEmptyError
	}

	level, err := logrus.ParseLevel(req.LogLevel)
	if err != nil {
		return nil, err
	}

	if !filepath.IsAbs(path) {
		path, _ = filepath.Abs(path)
	}
	_, err = os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"path":  path,
				"error": err,
			}).Debug("create folder error")
			return nil, err
		}
	}

	hooker := logging.NewFileRotateHooker(path, int64(req.RotationTime), req.LogAge)
	for _, level := range hooker.Levels() {
		if level != logrus.TraceLevel {
			s.log.Hooks[level][1] = hooker
		} else {
			s.log.Hooks[level][0] = hooker
		}
	}
	//update level
	s.log.SetLevel(level)

	s.logConf.LogLevel = req.LogLevel
	s.logConf.LogAge = req.LogAge
	s.logConf.LogFile = req.LogPath
	s.logConf.LogRotationTime = int64(req.RotationTime)

	logInfo := &rpcpb.LoggingInfo{
		LogLevel:     level.String(),
		LogPath:      path,
		LogAge:       req.LogAge,
		RotationTime: uint32(req.RotationTime),
	}

	return logInfo, nil
}

//GeneratePrivateKey return the key pair
func (s *AdminService) GeneratePrivateKey(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.PrivateKey, error) {
	privKey, err := crypto.NewPrivateKey(nil)
	if err != nil {
		return nil, err
	}
	bytes, err := privKey.Encoded()
	if err != nil {
		return nil, err
	}
	hexPrivKey := byteutils.Hex(bytes)
	return &rpcpb.PrivateKey{PriKey: hexPrivKey}, nil
}

// Return the p2p node info.
func (s *AdminService) GetNetVersion(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.NetVersion, error) {
	netConfig := network.GetNetConfig(s.gt.Config())
	return &rpcpb.NetVersion{
		NetworkId:       netConfig.NetworkId,
		ClientVersion:   network.ClientVersion,
		ProtocolVersion: network.GtProtocolID,
		Listen:          netConfig.Listen,
	}, nil
}

// NodeInfo is the RPC API handler.
func (s *AdminService) NodeInfo(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.NodeInfoResponse, error) {
	node := s.gt.NetService().Node()
	streamManager := s.gt.NetService().Node().StreamManager()
	netVersion, _ := s.GetNetVersion(ctx, req)
	activeCount := streamManager.ActivePeersCount()

	nodeInfo := &rpcpb.NodeInfoResponse{
		Id:            node.ID(),
		Coinbase:      conf.GetChainConfig(s.gt.Config()).Coinbase,
		TailHeight:    s.gt.BlockChain().TailBlock().Height(),
		ConfirmHeight: s.gt.BlockChain().FixedBlock().Height(),
		ChainId:       s.gt.BlockChain().ChainId(),
		Synchronized:  node.Synchronized(),
		BucketSize:    int32(node.BucketSize()),
		NetVersion:    netVersion,
		ActiveCount:   activeCount,
	}

	ids := node.AllPeerIds()
	if ids != nil && len(ids) > 0 {
		peerIds := make([]string, len(ids))
		for i, id := range ids {
			peerIds[i] = id
		}
		nodeInfo.PeerIds = peerIds
	}
	return nodeInfo, nil
}

func checkAndConvertValue(gt core.Gt, addr string, targetValue string) (*big.Int, error) {
	value := big.NewInt(0)
	var err error
	//some tx has not value, example fileTx, invokeTx and so on
	if len(targetValue) > 0 {
		value, err = core.CUintStringToNcUintBigInt(targetValue)
		if err != nil {
			return nil, err
		}

		zero := big.NewInt(0)
		worldState := gt.BlockChain().FixedBlock().WorldState()
		//check balance
		if value.Cmp(zero) > 0 {
			acc, err := account.GetAccountByAddress(addr, worldState)
			if err != nil {
				return nil, err
			}
			if acc.Balance().Cmp(value) < 0 {
				logging.CLog().WithFields(logrus.Fields{
					"balance": acc.Balance().String(),
					"value:":  value.String(),
					"error":   BalanceNotEnoughError.Error(),
				}).Debug("check from address error")
				return nil, BalanceNotEnoughError
			}
		}
	}
	return value, nil
}

func parseTransaction(gt core.Gt, reqTx *rpcpb.TransactionRequest) (*core.Transaction, error) {
	chainId := gt.BlockChain().ChainId()

	fromAddr, err := core.AddressParse(reqTx.From)
	if err != nil {
		return nil, err
	}
	if fromAddr.IsContractAddress() {
		return nil, FromAddressIsContractAddressError
	}
	var toAddr *core.Address
	if len(reqTx.To) > 0 {
		toAddr, err = core.AddressParse(reqTx.To)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"toAddress": reqTx.To,
				"error":     err,
			}).Error("check to address error")
			return nil, err
		}
	}

	value, err := checkAndConvertValue(gt, reqTx.From, reqTx.Value)
	if err != nil {
		return nil, err
	}
	priority := reqTx.Priority
	if priority > core.PriorityHigh {
		logging.VLog().WithFields(logrus.Fields{
			"priority": priority,
		}).Error("tx priority out of range")
		return nil, TxPriorityInvalidError
	}

	gasLimit, flag := new(big.Int).SetString(reqTx.GasLimit, 10)
	if !flag {
		return nil, errors.New("invalid gasLimit")
	}

	handlerType, handler, err := parseTransactionHandler(gt, reqTx)
	if err != nil {
		return nil, err
	}

	config := gt.BlockChain().TailBlock().GetChainConfig()
	tx, err := core.NewTransaction(chainId, fromAddr, toAddr, value, reqTx.Nonce, priority,
		handlerType, handler, reqTx.Memo, gasLimit, config)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func parseTransactionHandler(gt core.Gt, reqTx *rpcpb.TransactionRequest) (handlerType string, handler []byte, err error) {
	if len(reqTx.Type) > 0 {
		var data []byte
		if len(reqTx.Data) > 0 {
			data, err = byteutils.FromHex(reqTx.Data)
			if err != nil {
				logging.CLog().WithFields(logrus.Fields{
					"data:": reqTx.Data,
					"error": DataIsNotHexStringError.Error(),
				}).Error("hex data to bytes error")
				return "", nil, DataIsNotHexStringError
			}
		}

		switch reqTx.Type {
		case core.NormalTx:
			{
				handlerType = core.NormalTx
				if handler, err = core.NewNormalHandler(data).ToBytes(); err != nil {
					return "", nil, err
				}
			}
		case core.PledgeTx:
			{
				handlerType = core.PledgeTx
				if reqTx.Vote == nil {
					return "", nil, core.ErrInvalidVote
				}

				if handler, err = core.NewPledgeHandler(gt.NetService().Node().ID(), gt.Consensus().Coinbase().String(),
					reqTx.Vote.VoteType, reqTx.Value).ToBytes(); err != nil {
					return "", nil, err
				}

			}
		case core.ContractDeployTx:
			{
				handlerType = core.ContractDeployTx
				if reqTx.Contract == nil {
					return "", nil, core.ErrInvalidDeploySource
				}
				deployHandler, err := core.NewDeployHandler(reqTx.Contract.Source, reqTx.Contract.SourceType, reqTx.Contract.Args, reqTx.Contract.AuthFlag)
				if err != nil {
					return "", nil, err
				}

				if handler, err = deployHandler.ToBytes(); err != nil {
					return "", nil, err
				}
			}
		case core.ContractInvokeTx:
			{
				handlerType = core.ContractInvokeTx
				if reqTx.Contract == nil {
					return "", nil, core.ErrInvalidCallFunction
				}
				callHandler, err := core.NewCallHandler(reqTx.Contract.Function, reqTx.Contract.Args)
				if err != nil {
					return "", nil, err
				}

				if handler, err = callHandler.ToBytes(); err != nil {
					return "", nil, err
				}
			}
		case core.ContractChangeStateTx:
			{
				handlerType = core.ContractChangeStateTx
				if reqTx.Contract == nil {
					return "", nil, core.ErrInvalidChangeState
				}
				if handler, err = core.NewChangeStateHandler(reqTx.Contract.State).ToBytes(); err != nil {
					return "", nil, err
				}
			}
		case core.ComplexTx:
			{
				handlerType = core.ComplexTx
				if handler, err = core.NewComplexHandler(data).ToBytes(); err != nil {
					return "", nil, err
				}
			}
		case core.AuthorizeTx:
			{
				handlerType = core.AuthorizeTx
				if reqTx.Authorize == nil {
					return "", nil, core.ErrInvalidAuthorizeArguments
				}
				if reqTx.Authorize.Commands == nil {
					return "", nil, core.ErrInvalidAuthorizeArguments
				}
				cmds := make([]core.AuthorizeCmd, 0)
				for _, command := range reqTx.Authorize.Commands {
					cmds = append(cmds, core.AuthorizeCmd{
						Command:  command.Command,
						FuncName: command.Func,
						Rule:     command.Rule,
					})
				}
				authorizeHandler, err := core.NewAuthorizeHandler(cmds, reqTx.Authorize.Address, reqTx.Authorize.Type)
				if err != nil {
					return "", nil, err
				}

				if handler, err = authorizeHandler.ToBytes(); err != nil {
					return "", nil, err
				}
			}
		default:
			return "", nil, core.ErrInvalidTxHandlerType
		}
	}
	return handlerType, handler, nil
}

//func (s *AdminService) createTx(txRequest *rpcpb.TransactionRequest) (*core.Transaction, error) {
//	txPool := s.gt.BlockChain().TxPool()
//	if txPool == nil {
//		return nil, TxPoolIsNilError
//	}
//	am := s.gt.AccountManager()
//	fromAddr, err := am.AddressIsValid(txRequest.From)
//	if err != nil {
//		logging.CLog().WithFields(logrus.Fields{
//			"fromAddress": txRequest.From,
//			"error":       err,
//		}).Error("check from address error")
//		return nil, err
//	}
//
//	if fromAddr.IsContractAddress() {
//		return nil, FromAddressIsContractAddressError
//	}
//
//	var toAddr *core.Address
//	if len(txRequest.To) > 0 {
//		toAddr, err = am.AddressIsValid(txRequest.To)
//		if err != nil {
//			logging.CLog().WithFields(logrus.Fields{
//				"toAddress": txRequest.To,
//				"error":     err,
//			}).Error("check to address error")
//			return nil, err
//		}
//	}
//
//	priority := txRequest.Priority
//	if priority > core.PriorityHigh {
//		logging.VLog().WithFields(logrus.Fields{
//			"priority": priority,
//		}).Error("tx priority out of range")
//		return nil, TxPriorityInvalidError
//	}
//
//	var data []byte
//	if len(txRequest.Data) > 0 {
//		data, err = byteutils.FromHex(txRequest.Data)
//		if err != nil {
//			logging.CLog().WithFields(logrus.Fields{
//				"data:": txRequest.Data,
//				"error": DataIsNotHexStringError.Error(),
//			}).Debug("hex data to bytes error")
//			return nil, DataIsNotHexStringError
//		}
//	}
//
//	value, err := s.checkAndConvertValue(txRequest.From, txRequest.Value)
//	if err != nil {
//		return nil, err
//	}
//
//	nonce := txRequest.Nonce
//	if txRequest.Type != core.PledgeTx {
//		worldState, err := s.gt.BlockChain().TailBlock().WorldState().Copy()
//		if err != nil {
//			return nil, err
//		}
//		//cal account nonce
//		acc, _ := account.GetAccountByAddress(txRequest.From, worldState)
//		if nonce == 0 {
//			s.zn.Lock()
//			defer s.zn.Unlock()
//			txPoolNonce := txPool.GetTxsNumByAddr(txRequest.From)
//			nonce = acc.Nonce() + uint64(txPoolNonce) + 1
//		}
//
//		if nonce <= acc.Nonce() {
//			logging.VLog().WithFields(logrus.Fields{
//				"txNonce:":    nonce,
//				"acc.Nonce()": acc.Nonce(),
//			}).Debug("tx nonce is less than or equal to account nonce")
//			return nil, TxNonceLessThanAccountNonceError
//		}
//	} else {
//		termId := s.gt.BlockChain().TailBlock().TermId() + 1
//		pbTermId := &corepb.TermId{
//			TermId: termId,
//		}
//		pbTermIdBytes, err := proto.Marshal(pbTermId)
//		if err != nil {
//			return nil, err
//		}
//		data = pbTermIdBytes
//	}
//
//	chainId := s.gt.BlockChain().ChainId()
//	var dfsPrefix []string
//	switch txRequest.Type {
//	case core.ComplexTx:
//		dfsConfig := dfs.GetDfsConfig(s.gt.Config())
//		dfsPrefix = dfsConfig.HdfsPrefix
//		if dfsPrefix == nil || len(dfsPrefix) == 0 {
//			return nil, errors.New("dfs url prefix is empty")
//		}
//	case core.ContractDeployTx:
//		deployData, err := core.LoadDeployData(data)
//		if err != nil {
//			return nil, core.UnmarshalDataError
//		}
//
//		//is source code
//		if len(deployData.SourceType) != 0 {
//			contractIrCode, err := s.gt.Cvm().CompileContract(deployData.Source, deployData.Args)
//			if err != nil {
//				return nil, err
//			}
//			if len(contractIrCode) == 0 {
//				return nil, core.ContractCodeIsEmptyError
//			}
//			deployData.Source = contractIrCode
//
//			bytes, err := deployData.ToBytes()
//			if err != nil {
//				return nil, err
//			}
//			//compress
//			res := snappy.Encode(nil, []byte(bytes))
//			data = res
//		}
//
//	}
//
//	tx, err := core.NewTransaction(fromAddr, toAddr, value, nonce, chainId, priority, txRequest.Type, data, dfsPrefix, txRequest.GetMemo())
//	if err != nil {
//		return nil, err
//	}
//
//	//check balance >= tx.fee + tx.value
//	if tx.Value() != nil {
//		worldState, err := s.gt.BlockChain().FixedBlock().WorldState().Copy()
//		if err != nil {
//			return nil, err
//		}
//		acc, err := worldState.GetOrCreateAccount(tx.From().Bytes())
//		if err != nil {
//			return nil, err
//		}
//		value := big.NewInt(0).Add(tx.GetFee(), tx.Value())
//		if acc.Balance().Cmp(value) < 0 {
//			return nil, BalanceNotEnoughError
//		}
//	}
//
//	return tx, nil
//}

func (s *AdminService) autoGenNonceForZeroNonceTransaction(tx *core.Transaction) error {
	pool := s.gt.BlockChain().TxPool()
	tailBlock := s.gt.BlockChain().TailBlock()
	acc, err := tailBlock.GetAccount(tx.From().Bytes())
	if err != nil {
		return err
	}
	tx.SetNonce(acc.Nonce() + uint64(pool.GetTxsNumByAddr(tx.From().String())) + 1)
	logging.VLog().WithFields(logrus.Fields{
		"tx.from":  tx.From().String(),
		"tx.to":    tx.To().String(),
		"value":    tx.Value(),
		"gasLimit": tx.GasLimit(),
		"nonce":    tx.Nonce(),
	}).Debug("Set new nonce for tx")
	return nil
}
