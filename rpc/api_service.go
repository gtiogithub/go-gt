package rpc

import (
	"encoding/json"

	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gt.pro/gtio/go-gt/account"
	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/network"
	rpcpb "gt.pro/gtio/go-gt/rpc/pb"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
)

const (
	hexHashLength   = 64
	hexPubKeyLength = 64
	hexSignLength   = 128
)

var (
	HashLengthIsNot128Error          = errors.New("hex hash length must be 128")
	SignLengthIsNot128Error          = errors.New("hex signature length must be 128")
	BlockHeightError                 = errors.New("block height must be greater than 0")
	BlockHashIsEmptyError            = errors.New("block hash is empty")
	BlockNotExistError               = errors.New("block not exist")
	NoConfirmBlockError              = errors.New("no confirm block now")
	JsonTxHashIsNotHexStringError    = errors.New("tx hash must be hex string")
	JsonTxValueInvalidError          = errors.New("tx value invalid")
	JsonTxFeeInvalidError            = errors.New("tx fee invalid")
	JsonTxChainIdInvalidError        = errors.New("tx chain id invalid")
	JsonTxTypeIsEmptyError           = errors.New("tx type is empty")
	TxPriorityInvalidError           = errors.New("tx priority out of rang")
	PubKeyLengthInvalidError         = errors.New("public key length is not 64")
	DataInvalidError                 = errors.New("tx data must be hex string")
	PubKeyIsNotHexStringError        = errors.New("public key must be hex string")
	TxSignIsNotHexStringError        = errors.New("tx signature must be hex string")
	CalculateTxHashInvalidError      = errors.New("the calculated transaction hash is not equal to the transaction hash")
	CalculateTxFeeInvalidError       = errors.New("the calculated transaction fee is not equal to the transaction fee")
	VerifyTxSignError                = errors.New("verify signature failed")
	ContractNotExistError            = errors.New("contract not exist")
	IsNotContractAddressError        = errors.New("the address is not contract address")
	ContractFunctionNameIsEmptyError = errors.New("the function name is empty")
)

type ApiService struct {
	chain *core.BlockChain
	gt    core.Gt
}

// GetChainState is the RPC API handler.
func (api *ApiService) GetChainState(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.GetChainStateResponse, error) {

	gt := api.gt

	tail := gt.BlockChain().TailBlock()
	fixed := gt.BlockChain().FixedBlock()

	resp := &rpcpb.GetChainStateResponse{}
	resp.ChainId = gt.BlockChain().ChainId()
	resp.Tail = tail.Hash().String()
	resp.Fixed = fixed.Hash().String()
	resp.Height = tail.Height()
	resp.Synchronized = gt.BlockChain().IsActiveSyncing()
	resp.ProtocolVersion = network.GtProtocolID
	resp.Version = network.ClientVersion

	return resp, nil
}

// get account info by address
func (api *ApiService) GetAccount(ctx context.Context, req *rpcpb.Address) (*rpcpb.AccountInfo, error) {
	addr, err := core.AddressParse(req.Address)
	if err != nil {
		return nil, err
	}
	block := api.gt.BlockChain().TailBlock()
	acc, err := block.GetAccount(addr.Bytes())
	if err != nil {
		return nil, err
	}
	return accountToRpcAccountInfo(acc), nil
}

func accountToRpcAccountInfo(account state.Account) *rpcpb.AccountInfo {
	//uint conversion
	balance := core.NcUnitToCUnitString(account.Balance())
	frozenFund := core.NcUnitToCUnitString(account.FrozenFund())
	pledgeFund := core.NcUnitToCUnitString(account.PledgeFund())

	accountInfo := &rpcpb.AccountInfo{
		Address:    account.Address().Base58(),
		Balance:    balance,
		FrozenFund: frozenFund,
		PledgeFund: pledgeFund,
		Nonce:      account.Nonce(),
		State:      account.State(),
	}

	if account.VarsHash() != nil {
		accountInfo.VariablesHash = account.VarsHash().String()
	}

	if account.CreditIndex() != nil {
		accountInfo.CreditIndex = account.CreditIndex().String()
	}

	permissions := account.Permissions()
	if permissions == nil || len(permissions) == 0 {
		return accountInfo
	}

	var rpcPerm *rpcpb.Permission
	rpcPermissions := make([]*rpcpb.Permission, len(permissions))
	i := 0
	for _, per := range permissions {
		if per == nil {
			continue
		}
		if len(per.AuthCategory) == 0 {
			continue
		}
		rpcPerm = new(rpcpb.Permission)
		rpcPerm.AuthCategory = per.AuthCategory

		length := len(per.AuthMessage)
		if length > 0 {
			authMessages := make([]string, length)
			for j, msg := range per.AuthMessage {
				//byte auth message to string
				authMessages[j] = string(msg)
			}
			rpcPerm.AuthMessage = authMessages
		}
		rpcPermissions[i] = rpcPerm
		i++
	}
	if len(rpcPermissions) < len(permissions) {
		endIndex := len(permissions) - len(rpcPermissions)
		rpcPermissions = rpcPermissions[:endIndex]
	}
	accountInfo.Permissions = rpcPermissions

	return accountInfo
}

// Call is the RPC API handler.
func (api *ApiService) CallTransaction(ctx context.Context, req *rpcpb.TransactionRequest) (*rpcpb.CallResponse, error) {
	gt := api.gt
	tx, err := parseTransaction(gt, req)
	if err != nil {
		return nil, err
	}

	result, err := gt.BlockChain().SimulateTransactionExecution(tx)
	if err != nil {
		return nil, err
	}

	errMsg := ""
	if result.Err != nil {
		errMsg = result.Err.Error()
	}

	errInjectTracingInstructionFailed := "inject tracing instructions failed"

	if errMsg == errInjectTracingInstructionFailed {
		errMsg = "contract code syntax error"
	}
	return &rpcpb.CallResponse{
		Result:      result.Msg,
		ExecuteErr:  errMsg,
		EstimateGas: result.GasUsed.String(),
	}, nil
}

// EstimateGas Compute the smart contract gas consumption.
func (api *ApiService) EstimateGas(ctx context.Context, req *rpcpb.TransactionRequest) (*rpcpb.GasResponse, error) {
	tx, err := parseTransaction(api.gt, req)
	if err != nil {
		return nil, err
	}

	result, err := api.chain.SimulateTransactionExecution(tx)
	if err != nil {
		return nil, err
	}

	errMsg := ""
	if result.Err != nil {
		errMsg = result.Err.Error()
	}
	return &rpcpb.GasResponse{Gas: result.GasUsed.String(), Err: errMsg}, nil
}

// SendRawTransaction submit the signed transaction raw data to txpool
func (api *ApiService) SendRawTransaction(ctx context.Context, req *rpcpb.SendRawTransactionRequest) (*rpcpb.TransactionHash, error) {
	// Validate and sign the tx, then submit it to the tx pool.
	gt := api.gt
	pbTx := new(corepb.Transaction)
	if err := proto.Unmarshal(req.GetData(), pbTx); err != nil {
		return nil, err
	}
	tx := new(core.Transaction)
	if err := tx.FromProto(pbTx); err != nil {
		return nil, err
	}

	return handleTransactionResponse(gt, tx)
}

// GetBlockByHash get block info by the block hash
func (api *ApiService) GetBlockByHash(ctx context.Context, req *rpcpb.BlockHashAndFull) (*rpcpb.BlockResponse, error) {

	bhash, err := byteutils.FromHex(req.GetHash())
	if err != nil {
		return nil, err
	}
	block := api.chain.GetBlockOnCanonicalChainByHash(bhash)
	return api.blockToRpcpbBlockResponse(block, req.FullFillTransaction)
}

func (s *ApiService) blockToRpcpbBlockResponse(block *core.Block, fullFillTx bool) (*rpcpb.BlockResponse, error) {
	if block == nil {
		return nil, errors.New("block not found")
	}
	fixed := s.chain.FixedBlock()
	bestBlock := false
	if fixed.Height() > block.Height() {
		bestBlock = true
	}

	blockResponse := &rpcpb.BlockResponse{
		ChainId:   block.Header().ChainId(),
		Hash:      block.Hash().String(),
		BestBlock: bestBlock,
		Coinbase:  block.Coinbase().String(),
		StateRoot: block.StateRoot().String(),
		TxsRoot:   byteutils.Hex(block.Header().TxsRoot()),
		Height:    block.Height(),
		Timestamp: block.Timestamp(),
	}

	//for genesis block
	if block.ParentHash() != nil {
		blockResponse.ParentHash = block.ParentHash().String()
	}

	memo := block.Memo()
	if memo != nil {
		blockResponse.Memo = new(rpcpb.BlockMemo)
		rewards := memo.Rewards()
		if rewards != nil && len(rewards) > 0 && rewards[0] != nil {
			blockResponse.Memo.Rewards = make([]*rpcpb.BlockFundEntity, 0)
			for _, entity := range rewards {
				balance := core.NcUnitToCUnitString(byteutils.BigInt(entity.Balance))
				frozenFund := core.NcUnitToCUnitString(byteutils.BigInt(entity.FrozenFund))
				pledgeFund := core.NcUnitToCUnitString(byteutils.BigInt(entity.PledgeFund))
				blockResponse.Memo.Rewards = append(blockResponse.Memo.Rewards, &rpcpb.BlockFundEntity{
					Address:    string(entity.Address[:]),
					Balance:    balance,
					FrozenFund: frozenFund,
					PledgeFund: pledgeFund,
				})
			}
		}
		pledge := memo.Pledge()
		if pledge != nil && len(pledge) > 0 && pledge[0] != nil {
			blockResponse.Memo.Pledge = make([]*rpcpb.BlockFundEntity, 0)
			for _, entity := range pledge {
				balance := core.NcUnitToCUnitString(byteutils.BigInt(entity.Balance))
				frozenFund := core.NcUnitToCUnitString(byteutils.BigInt(entity.FrozenFund))
				pledgeFund := core.NcUnitToCUnitString(byteutils.BigInt(entity.PledgeFund))
				blockResponse.Memo.Pledge = append(blockResponse.Memo.Pledge, &rpcpb.BlockFundEntity{
					Address:    string(entity.Address[:]),
					Balance:    balance,
					FrozenFund: frozenFund,
					PledgeFund: pledgeFund,
				})
			}
		}
	}

	length := len(block.Transactions())
	if length == 0 {
		logging.CLog().WithFields(logrus.Fields{
			"blockHash": block.Hash().String(),
		}).Debug("the block no transactions")
		return blockResponse, nil
	}

	// add block transactions
	txs := []*rpcpb.TransactionReceipt{}
	for _, v := range block.Transactions() {
		var tx *rpcpb.TransactionReceipt
		if fullFillTx {
			tx, _ = s.txToRpcTxRecepit(v)
		} else {
			tx = &rpcpb.TransactionReceipt{Hash: v.Hash().String()}
		}
		tx.BlockHeight = block.Height()
		txs = append(txs, tx)
	}

	blockResponse.Txs = txs
	return blockResponse, nil
}

// get best block by height
func (api *ApiService) GetBestBlockByHeight(ctx context.Context, req *rpcpb.BlockHeightAndFull) (*rpcpb.BlockResponse, error) {
	if req.Height == 0 {
		return nil, BlockHeightError
	}
	if req.Height > api.chain.FixedBlock().Height() {
		return nil, BlockNotExistError
	}

	block := api.chain.GetBlockOnCanonicalChainByHeight(req.Height)

	return api.blockToRpcpbBlockResponse(block, req.FullFillTransaction)
}

// get best block by height
func (api *ApiService) GetTransactions(ctx context.Context, req *rpcpb.GetTransactionsRequest) (*rpcpb.GetTransactionsResponse, error) {
	fromAddr, err := core.AddressParse(req.Address)
	if err != nil {
		return nil, err
	}
	count := uint64(100)
	if req.Count != 0 {
		count = req.Count
	}
	if count <= req.Index {
		count += 100
	}

	allTxs, err := api.chain.GetAccountTxs(fromAddr.Bytes(), req.Index, count)
	if err != nil {
		return nil, err
	}

	res := &rpcpb.GetTransactionsResponse{
		Address: req.Address,
		Txs:     make([]*rpcpb.TransactionReceipt, 0),
	}

	if allTxs != nil && len(allTxs) > 0 {
		for _, txHash := range allTxs {
			tranRec := &rpcpb.TransactionReceipt{
				Hash: txHash.String(),
			}
			if req.FullFillTransaction {
				tx, err := api.chain.GetTransactionByHash(txHash.String())
				if err != nil {
					logging.CLog().WithFields(logrus.Fields{
						"txHash": txHash,
						"error":  err,
					}).Debug("get tx result is nil")
					return nil, err
				}
				tranRec, err = api.txToRpcTxRecepit(tx)
				if err != nil {
					return nil, err
				}
			}
			res.Txs = append(res.Txs, tranRec)
		}
	}

	return res, nil
}

// GetTransactionByHash get transaction info by the transaction hash
func (api *ApiService) GetTransactionByHash(ctx context.Context, req *rpcpb.TransactionHash) (*rpcpb.TransactionReceipt, error) {
	tx, err := api.chain.GetTransactionByHash(req.Hash)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"txHash": req.Hash,
			"error":  err,
		}).Debug("get tx result is nil")
		return nil, err
	}

	return api.txToRpcTxRecepit(tx)
}
func (s *ApiService) txToRpcTxRecepit(tx *core.Transaction) (*rpcpb.TransactionReceipt, error) {
	var (
		status          int32
		gasUsed         string
		execute_error   string
		execute_result  string
		election_result string
		height          uint64
	)
	isPledge := tx.Type() == core.PledgeTx
	if isPledge {
		data, err := s.chain.TailBlock().FetchElectionResultEvent(tx.Hash())
		if err != nil && err != core.ErrNotFoundElectionResultEvent {
			return nil, err
		}
		election_result = data
	}
	event, err := s.chain.TailBlock().FetchExecutionResultEvent(tx.Hash())
	if err != nil && err != core.ErrNotFoundTransactionResultEvent {
		return nil, err
	}

	if event != nil {
		switch tx.Type() {
		case core.NormalTx, core.PledgeTx, core.AuthorizeTx, core.ContractChangeStateTx, core.ReportTx:
			{
				txEvent := core.TransactionEvent{}
				err := json.Unmarshal([]byte(event.Data), &txEvent)
				if err != nil {
					return nil, err
				}
				status = int32(txEvent.Status)
				gasUsed = txEvent.GasUsed
				execute_error = txEvent.Error
			}
		case core.ContractDeployTx, core.ContractInvokeTx:
			{
				txEvent2 := core.ContractTransactionEvent{}

				err := json.Unmarshal([]byte(event.Data), &txEvent2)
				if err != nil {
					return nil, err
				}
				status = int32(txEvent2.Status)
				gasUsed = txEvent2.GasUsed
				execute_error = txEvent2.Error
				execute_result = txEvent2.ExecuteResult
			}
		}
	} else {
		status = core.TxPendding
	}

	if status != core.TxPendding {
		height, err = s.chain.GetTransactionHeight(tx.Hash())
		if err != nil {
			return nil, err
		}
	}

	txResponse := &rpcpb.TransactionReceipt{
		Hash:           tx.Hash().String(),
		ChainId:        tx.ChainId(),
		From:           tx.From().String(),
		Nonce:          tx.Nonce(),
		Type:           tx.GetData().Type,
		Priority:       tx.Priority(),
		GasLimit:       tx.GasLimit().String(),
		Timestamp:      tx.Timestamp(),
		BlockHeight:    height,
		GasUsed:        gasUsed,
		ExecuteError:   execute_error,
		ExecuteResult:  execute_result,
		ElectionResult: election_result,
		Status:         uint32(status),
	}

	if tx.To() != nil {
		txResponse.To = tx.To().String()
	}

	if tx.Value() != nil {
		txResponse.Value = core.NcUnitToCUnitString(tx.Value())
	}

	//tx memo
	txResponse.Memo = tx.GetMemo()

	if tx.GetData().Msg == nil || len(tx.GetData().Msg) == 0 {
		return txResponse, nil
	}

	txResponse.Data = byteutils.Hex(tx.GetData().Msg)

	if tx.Type() == core.ContractDeployTx {
		contractAddr, err := tx.GenerateContractAddress()
		if err != nil {
			return nil, err
		}
		txResponse.ContractAddress = contractAddr.String()
	}
	return txResponse, nil
}

// GetTransactionByContractAddress get transaction info by the contract address
func (api *ApiService) GetTransactionByContractAddress(ctx context.Context, req *rpcpb.ContractAddressRequest) (*rpcpb.TransactionReceipt, error) {

	addr, err := core.AddressParse(req.ContractAddress)
	if err != nil {
		return nil, err
	}

	contract, err := api.chain.GetContract(addr)
	if err != nil {
		return nil, err
	}

	hash := contract.BirthTransaction()

	tx, err := api.chain.GetTransaction(hash)
	if err != nil {
		return nil, err
	}
	return api.txToRpcTxRecepit(tx)
}

// GetBestBlockHash get latest fixed block hash
func (api *ApiService) GetBestBlockHash(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BlockHash, error) {
	bestBlockHash := api.chain.FixedBlock().Hash().String()
	return &rpcpb.BlockHash{Hash: bestBlockHash}, nil
}

// get max block height
func (api *ApiService) GetMaxHeight(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BlockHeight, error) {
	maxHeight := api.chain.FixedBlock().Height()
	return &rpcpb.BlockHeight{Height: maxHeight}, nil
}

// GetAsset get account asset info by account
func (s *ApiService) GetAsset(ctx context.Context, req *rpcpb.Address) (*rpcpb.AssetResponse, error) {
	worldState := s.chain.TailBlock().WorldState()
	acc, err := account.GetAccountByAddress(req.Address, worldState)
	if err != nil {
		return nil, err
	}
	balance := core.NcUnitToCUnitString(acc.Balance())
	frozenFund := core.NcUnitToCUnitString(acc.FrozenFund())
	pledgeFund := core.NcUnitToCUnitString(acc.PledgeFund())
	return &rpcpb.AssetResponse{
		Balance:    balance,
		FrozenFund: frozenFund,
		PledgeFund: pledgeFund,
	}, nil
}

// Return the p2p node info.
func (s *ApiService) GetActiveCount(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.ActiveCountResponse, error) {
	streamManager := s.gt.NetService().Node().StreamManager()
	return &rpcpb.ActiveCountResponse{ActiveCount: streamManager.ActivePeersCount()}, nil
}

// GetPendingTransactionsSize get current tx pool pending transaction size
func (api *ApiService) GetPendingTransactionsSize(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.PendingTransactionsSize, error) {
	pendingTxSize := api.chain.TxPool().GetPendingTxSize()
	return &rpcpb.PendingTransactionsSize{Size_: uint64(pendingTxSize)}, nil
}

// GetPendingTransactions get current tx pool pending transactions
func (api *ApiService) GetPendingTransactions(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.PendingTransaction, error) {
	transactions, err := api.chain.TxPool().GetPendingTransactions()
	if err != nil {
		return nil, err
	}

	txs := make([]*rpcpb.Transaction, len(transactions))
	for i, tx := range transactions {
		txs[i] = api.txToRpcpbTx(tx)
	}
	return &rpcpb.PendingTransaction{Txs: txs}, nil
}
func (s *ApiService) txToRpcpbTx(tx *core.Transaction) *rpcpb.Transaction {
	pbTx := &rpcpb.Transaction{
		Hash:      tx.Hash().String(),
		ChainId:   tx.ChainId(),
		From:      tx.From().String(),
		Nonce:     tx.Nonce(),
		Type:      tx.GetData().Type,
		Priority:  tx.Priority(),
		Timestamp: tx.Timestamp(),
		Memo:      tx.GetMemo(),
		GasLimit:  tx.GasLimit().String(),
	}

	if tx.GetSign() != nil {
		pbTx.Signature = tx.GetHexSignature()
	}

	if tx.Value() != nil {
		pbTx.Value = core.NcUnitToCUnitString(tx.Value())
	}
	if tx.To() != nil {
		pbTx.To = tx.To().String()
	}
	//if tx.Type() == core.ContractDeployTx {
	//	contractAddr, _ := tx.GenerateContractAddress()
	//	pbTx.To = contractAddr.String()
	//}

	if tx.GetData().Msg != nil && len(tx.GetData().Msg) > 0 {
		pbTx.Data = byteutils.Hex(tx.GetData().Msg)
	}
	return pbTx
}

// GetContractAuthorization get account`s contract authorization information
func (api *ApiService) GetContractAuthorization(ctx context.Context, req *rpcpb.GetContractAuthorizationRequest) (*rpcpb.GetContractAuthorizationResponse, error) {

	addr, err := core.AddressParse(req.Address)
	if err != nil {
		return nil, err
	}

	contractAddr, err := core.AddressParse(req.Contract)
	contract, err := api.chain.GetContract(contractAddr)
	if err != nil {
		return nil, err
	}

	//check execute authorize
	birthTx, err := api.chain.GetTransaction(contract.BirthTransaction())
	if err != nil {
		return nil, err
	}
	owner := false
	if byteutils.Equal(addr.Bytes(), birthTx.From().Bytes()) { //check owner
		owner = true
	}
	//get function list
	funcList, err := contract.GetContractFuncList()
	if err != nil {
		return nil, err
	}
	authorizations := make([]*rpcpb.Authorization, 0)
	for i := 0; i < len(funcList); i++ {
		auth := &rpcpb.Authorization{
			Type:     state.FuncAuthType,
			Function: funcList[i],
		}
		if !owner {
			result, _ := contract.CheckPermission(state.FuncAuthType+"_"+"", addr.String(), funcList[i])
			if result {
				auth.Rule = state.FuncAllowRule
			} else {
				auth.Rule = state.FuncForbidRule
			}
		} else {
			auth.Rule = state.FuncAllowRule
		}
		authorizations = append(authorizations, auth)
	}
	for i := 0; i < len(funcList); i++ {
		auth := &rpcpb.Authorization{
			Type:     state.RoleAuthType,
			Function: funcList[i],
		}
		if !owner {
			x := 0
			cmds := make([]string, 0)
			cmds = append(cmds, state.AddCommand, state.ModifyCommand, state.DelCommand)
			for _, cmd := range cmds {
				result, _ := contract.CheckPermission(state.RoleAuthType+"_"+cmd, addr.String(), funcList[i])
				if result && cmd == state.AddCommand {
					x |= 1 << 0
				} else if result && cmd == state.ModifyCommand {
					x |= 1 << 1
				} else if result && cmd == state.DelCommand {
					x |= 1 << 2
				}
			}
			// 支持1.3以上
			// if x == 0b0001 {
			// 	auth.Rule = state.RoleAddRule
			// } else if x == 0b0010 {
			// 	auth.Rule = state.RoleModifyRule
			// } else if x == 0b0100 {
			// 	auth.Rule = state.RoleDelRule
			// } else if x == 0b0011 {
			// 	auth.Rule = state.RoleAddAndModifyRule
			// } else if x == 0b0101 {
			// 	auth.Rule = state.RoleAddAndDelRule
			// } else if x == 0b0110 {
			// 	auth.Rule = state.RoleModifyAndDelRule
			// } else if x == 0b0111 {
			// 	auth.Rule = state.RoleAddModifyAndDelRule
			// }
			if x == 1 {
				auth.Rule = state.RoleAddRule
			} else if x == 2 {
				auth.Rule = state.RoleModifyRule
			} else if x == 4 {
				auth.Rule = state.RoleDelRule
			} else if x == 3 {
				auth.Rule = state.RoleAddAndModifyRule
			} else if x == 5 {
				auth.Rule = state.RoleAddAndDelRule
			} else if x == 6 {
				auth.Rule = state.RoleModifyAndDelRule
			} else if x == 7 {
				auth.Rule = state.RoleAddModifyAndDelRule
			}
		} else {
			auth.Rule = state.RoleAddModifyAndDelRule
		}
		authorizations = append(authorizations, auth)
	}
	return &rpcpb.GetContractAuthorizationResponse{
		Authorizations: authorizations,
	}, nil
}

// Subscribe ..
func (api *ApiService) Subscribe(req *rpcpb.SubscribeRequest, gs rpcpb.ApiService_SubscribeServer) error {
	eventSub := core.NewEventSubscriber(1024, req.Topics)
	api.gt.EventEmitter().Register(eventSub)
	defer api.gt.EventEmitter().Deregister(eventSub)

	var err error
	for {
		select {
		case <-gs.Context().Done():
			return gs.Context().Err()
		case event := <-eventSub.EventChan():
			err = gs.Send(&rpcpb.SubscribeResponse{Topic: event.Topic, Data: event.Data})
			if err != nil {
				return err
			}
		}
	}
}

// GetContractFunctions get contract all function
func (api *ApiService) GetContractFunctions(ctx context.Context, req *rpcpb.GetContractFunctionsRequest) (*rpcpb.GetContractFunctionsResponse, error) {
	contractAddr, err := core.AddressParse(req.Contract)
	if err != nil {
		return nil, err
	}
	contract, err := api.chain.GetContract(contractAddr)
	if err != nil {
		return nil, err
	}
	//get function list
	funcList, err := contract.GetContractFuncList()
	if err != nil {
		return nil, err
	}
	return &rpcpb.GetContractFunctionsResponse{
		Functions: funcList,
	}, nil
}

func (api *ApiService) GetAccountContracts(ctx context.Context, req *rpcpb.GetAccountContractsRequest) (*rpcpb.GetAccountContractsResponse, error) {
	addr, err := core.AddressParse(req.Address)
	if err != nil {
		return nil, err
	}
	if addr.IsContractAddress() {
		return nil, AddressIsContractAddressError
	}
	worldState := api.chain.TailBlock().WorldState()
	acc, err := account.GetAccountByAddress(req.Address, worldState)
	if err != nil {
		return nil, err
	}
	contracts := make([]string, 0)
	contractIntegrals := acc.ContractIntegral()
	if contractIntegrals != nil {
		for _, integral := range contractIntegrals {
			contracts = append(contracts, integral.Address)
		}
	}
	return &rpcpb.GetAccountContractsResponse{
		Contracts: contracts,
	}, nil
}

//// get best block by height
//func (api *ApiService) GetBlocksByHeight(ctx context.Context, req *rpcpb.BlockHeightAndFull) (*rpcpb.BlockListResponse, error) {
//	if req.Height == 0 {
//		return nil, BlockHeightError
//	}
//	blocks := api.chain.GetBlocksByHeight(req.Height)
//	if blocks == nil || len(blocks) == 0 {
//		return nil, BlockNotExistError
//	}
//
//	bestBlockIndex, hashs := api.chain.GetIndexAndHashesByHeight(req.Height)
//	if hashs == nil || len(hashs) == 0 || bestBlockIndex < 0 {
//		return nil, BlockNotExistError
//	}
//	blockListResponse := make([]*rpcpb.BlockResponse, len(blocks))
//
//	bestBlockHash := hashs[bestBlockIndex].String()
//	bestBlock := false
//	for i, block := range blocks {
//		bestBlock = bestBlockHash == block.Hash().String()
//		blockListResponse[i], _ = blockToRpcpbBlockResponse(block, req.FullFillTransaction, bestBlock)
//	}
//
//	return &rpcpb.BlockListResponse{Blocks: blockListResponse}, nil
//}

// get creditIndex by address
//func (api *ApiService) GetCreditIndex(ctx context.Context, req *rpcpb.Address) (*rpcpb.CreditIndexResponse, error) {
//	if api.chain.FixedBlock() == nil {
//		return nil, NoConfirmBlockError
//	}
//	worldState := api.chain.FixedBlock().WorldState()
//	acc, err := account.GetAccountByAddress(req.Address, worldState)
//	if err != nil {
//		return nil, err
//	}
//	creditIndex := &rpcpb.CreditIndexResponse{
//		CreditIndex: core.ZeroString,
//	}
//
//	if acc.CreditIndex() != nil {
//		creditIndex.CreditIndex = acc.CreditIndex().String()
//	}
//	return creditIndex, nil
//}

//func getBlockByHash(blockHash string, chain *core.BlockChain) (*core.Block, error) {
//	if len(blockHash) == 0 {
//		return nil, BlockHashIsEmptyError
//	}
//	blockHashBytes, err := byteutils.FromHex(blockHash)
//	if err != nil {
//		return nil, err
//	}
//
//	block, err := core.LoadBlockFromStorage(blockHashBytes, chain)
//	return block, err
//}

//func (s *ApiService) rpcpbTxToCoreTx(txRequest *rpcpb.Transaction) (*core.Transaction, error) {
//	if len(txRequest.Hash) != hexHashLength {
//		return nil, HashLengthIsNot128Error
//	}
//	if len(txRequest.Signature) != hexSignLength {
//		return nil, SignLengthIsNot128Error
//	}
//	if len(txRequest.PubKey) != hexPubKeyLength {
//		return nil, PubKeyLengthInvalidError
//	}
//
//	signBytes, err := byteutils.FromHex(txRequest.Signature)
//	if err != nil {
//		logging.VLog().WithFields(logrus.Fields{
//			"error": err,
//			"sign":  txRequest.Signature,
//		}).Debug("tx signature is not hex string")
//		return nil, TxSignIsNotHexStringError
//	}
//
//	hashBytes, err := byteutils.FromHex(txRequest.Hash)
//	if err != nil {
//		logging.VLog().WithFields(logrus.Fields{
//			"error":  err,
//			"txHash": txRequest.Hash,
//		}).Debug("tx hash is not hex string")
//		return nil, JsonTxHashIsNotHexStringError
//	}
//
//	var dataBytes []byte
//	if len(txRequest.Data) > 0 {
//		dataBytes, err = byteutils.FromHex(txRequest.Data)
//		if err != nil {
//			logging.VLog().WithFields(logrus.Fields{
//				"error": err,
//				"data":  txRequest.Data,
//			}).Debug("tx data is not hex string")
//			return nil, DataInvalidError
//		}
//	}
//
//	pubKeyBytes, err := byteutils.FromHex(txRequest.PubKey)
//	if err != nil {
//		logging.VLog().WithFields(logrus.Fields{
//			"error":  err,
//			"pubKey": txRequest.PubKey,
//		}).Debug("tx public key is not hex string")
//		return nil, PubKeyIsNotHexStringError
//	}
//
//	am := s.gt.AccountManager()
//	from, err := am.AddressIsValid(txRequest.From)
//	if err != nil {
//		logging.VLog().WithFields(logrus.Fields{
//			"error": err,
//			"from":  txRequest.From,
//		}).Debug("from address invalid")
//		return nil, err
//	}
//
//	if from.IsContractAddress() {
//		return nil, FromAddressIsContractAddressError
//	}
//
//	var to *core.Address
//	if len(txRequest.To) > 0 {
//		to, err = am.AddressIsValid(txRequest.To)
//		if err != nil {
//			logging.VLog().WithFields(logrus.Fields{
//				"error": err,
//				"to":    txRequest.To,
//			}).Debug("to address invalid")
//			return nil, err
//		}
//	}
//
//	var value *big.Int
//	if len(txRequest.Value) > 0 {
//		success := true
//		value, success = new(big.Int).SetString(txRequest.Value, 0)
//		if !success {
//			logging.VLog().WithFields(logrus.Fields{
//				"value": txRequest.Value,
//			}).Debug("to address invalid")
//			return nil, JsonTxValueInvalidError
//		}
//	}
//
//	chainId := s.gt.BlockChain().ChainId()
//	if txRequest.ChainId != chainId {
//		logging.VLog().WithFields(logrus.Fields{
//			"blockchain id":   chainId,
//			"jsonTx chain Id": txRequest.ChainId,
//		}).Debug("to address invalid")
//		return nil, JsonTxChainIdInvalidError
//	}
//
//	fee, success := new(big.Int).SetString(txRequest.Fee, 0)
//	if !success {
//		logging.VLog().WithFields(logrus.Fields{
//			"fee": txRequest.Fee,
//		}).Debug("to address invalid")
//		return nil, JsonTxFeeInvalidError
//	}
//
//	if len(txRequest.Type) == 0 {
//		return nil, JsonTxTypeIsEmptyError
//	}
//
//	err = core.CheckTxType(txRequest.Type)
//	if err != nil {
//		logging.VLog().WithFields(logrus.Fields{
//			"txType": txRequest.Type,
//		}).Debug(err.Error())
//		return nil, err
//	}
//
//	priority := txRequest.Priority
//	if priority > core.PriorityHigh {
//		logging.VLog().WithFields(logrus.Fields{
//			"priority": priority,
//		}).Debug("tx priority out of range")
//		return nil, TxPriorityInvalidError
//	}
//
//	corePbTx := &corepb.Transaction{
//		Hash:      hashBytes,
//		From:      from.Bytes(),
//		Nonce:     txRequest.Nonce,
//		ChainId:   chainId,
//		//Fee:       fee.Bytes(),
//		Timestamp: txRequest.Timestamp,
//		Priority:  priority,
//	}
//	if to != nil {
//		corePbTx.To = to.Bytes()
//	}
//	if value != nil {
//		corePbTx.Value = value.Bytes()
//	}
//
//	//Data
//	data := &corepb.Data{
//		Type: txRequest.Type,
//		Msg:  dataBytes,
//	}
//	corePbTx.Data = data
//
//	//signature
//	signature := &corepb.Signature{
//		Signer: pubKeyBytes,
//		Data:   signBytes,
//	}
//	corePbTx.Sign = signature
//
//	coreTx := new(core.Transaction)
//	err = coreTx.FromProto(corePbTx)
//	if err != nil {
//		return nil, err
//	}
//	return coreTx, nil
//}
