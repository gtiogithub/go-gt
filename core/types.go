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
	"errors"
	"regexp"
)

// MessageType
const (
	MessageTypeNewBlock                   = "newblock"
	MessageTypeParentBlockDownloadRequest = "dlblock"
	MessageTypeBlockDownloadResponse      = "dlreply"
	MessageTypeNewTx                      = "newtx"

	ContractDeploySucceed = "DeploySucceed"

	ComPressTimes = 3
)

const (
	PledgeTx              = "PledgeTx"
	NormalTx              = "NormalTx"
	ComplexTx             = "ComplexTx"
	ContractDeployTx      = "ContractDeployTx"
	ContractInvokeTx      = "ContractInvokeTx"
	ContractChangeStateTx = "ContractChangeStateTx"
	AuthorizeTx           = "AuthorizeTx"
	ReportTx              = "ReportTx"
)

const (
	//ElectionAllocateFactor = 100
	VoteExpiryFactor = 2
	RelieveFactor    = 1
)

var (
	PublicFuncNameChecker = regexp.MustCompile("^[a-zA-Z$][A-Za-z0-9_$]*$")
	// DefaultLimitsOfTotalMemorySize default limits of total memory size
	DefaultLimitsOfTotalMemorySize uint64 = 40 * 1000 * 1000
)

var (
	ErrInvalidGenesis                = errors.New("invalid genesis config")
	ErrInvalidAddressFormat          = errors.New("address: invalid address format")
	ErrInvalidAddressType            = errors.New("address: invalid address type")
	ErrInvalidAddressChecksum        = errors.New("address: invalid address checksum")
	ErrTxPoolFull                    = errors.New("tx pool is full")
	ErrInvalidArgument               = errors.New("invalid argument(s)")
	ErrUnknownTxType                 = errors.New("unknown transaction type")
	ErrTxType                        = errors.New("transaction type error")
	ErrInvalidCVM                    = errors.New("invalid cvm")
	ErrInvalidSignAmount             = errors.New("invalid witness signs amount")
	ErrNilArgument                   = errors.New("argument(s) is nil")
	ErrInvalidAmount                 = errors.New("invalid amount")
	ErrInsufficientBalance           = errors.New("insufficient balance")
	ErrInvalidProtoToBlock           = errors.New("protobuf message cannot be converted into Block")
	ErrInvalidProtoToBlockHeader     = errors.New("protobuf message cannot be converted into BlockHeader")
	ErrInvalidProtoToBlockMemo       = errors.New("protobuf message cannot be converted into BlockMemo")
	ErrInvalidProtoToBlockFundEntity = errors.New("protobuf message cannot be converted into BlockFundEntity")
	ErrInvalidProtoToTransaction     = errors.New("protobuf message cannot be converted into Transaction")

	ErrInvalidTransfer         = errors.New("transfer error: overflow or insufficient balance")
	ErrInvalidRefundPledgeFund = errors.New("refund pledge fund error: overflow or insufficient pledge fund")

	ErrDuplicatedTransaction     = errors.New("duplicated transaction")
	ErrSmallTransactionNonce     = errors.New("cannot accept a transaction with smaller nonce")
	ErrLargeTransactionNonce     = errors.New("cannot accept a transaction with too bigger nonce")
	ErrPackTransactionElapseLess = errors.New("pack transactions elapse less than 0")
	ErrInvalidDagBlock           = errors.New("block's dag is incorrect")

	ErrDuplicatedBlock                  = errors.New("duplicated block")
	ErrInvalidChainID                   = errors.New("invalid transaction chainID")
	ErrInvalidTransactionHash           = errors.New("invalid transaction hash")
	ErrInvalidBlockHeaderChainID        = errors.New("invalid block header chainId")
	ErrInvalidBlockHash                 = errors.New("invalid block hash")
	ErrInvalidBlockSign                 = errors.New("invalid block signature")
	ErrInvalidBlockOutput               = errors.New("invalid block output quantity")
	ErrInvalidRewardsOrPledges          = errors.New("invalid rewards or pledges")
	ErrInvalidTransactionSigner         = errors.New("invalid transaction signer")
	ErrInvalidTransactionSign           = errors.New("invalid transaction signature")
	ErrInvalidPublicKey                 = errors.New("invalid public key")
	ErrInvalidTransactionSignatureEmpty = errors.New("transaction signature is empty")

	ErrMissingParentBlock                                = errors.New("cannot find the block's parent block in storage")
	ErrInvalidBlockCannotFindParentInLocalAndTrySync     = errors.New("invalid block received, sync its parent from others")
	ErrInvalidBlockCannotFindParentInLocalAndTryDownload = errors.New("invalid block received, download its parent from others")
	ErrLinkToWrongParentBlock                            = errors.New("link the block to a block who is not its parent")
	ErrCloneAccountState                                 = errors.New("failed to clone account state")

	ErrInvalidBlockStateRoot     = errors.New("invalid block state root hash")
	ErrInvalidBlockTxsRoot       = errors.New("invalid block txs root hash")
	ErrInvalidBlockEventsRoot    = errors.New("invalid block events root hash")
	ErrInvalidBlockConsensusRoot = errors.New("invalid block consensus root hash")

	ErrContractBalanceNotEnough = errors.New("contract account balance not enough")

	ErrAddOutputQuantity = errors.New("add block output quantity error")
	ErrRefundFund        = errors.New("refund fund to contributor error")

	ErrRewardContributor = errors.New("reward contributor error")

	ErrCannotRevertFixed = errors.New("cannot revert latest fixed block")

	// nvm error
	ErrExecutionFailed = errors.New("execution failed")
	ErrUnexpected      = errors.New("Unexpected sys error")
	// multi nvm error
	ErrInnerExecutionFailed = errors.New("multi execution failed")
	ErrCreateInnerTx        = errors.New("Failed to create inner transaction")

	ErrContractCheckFailed = errors.New("contract check failed")
	ErrNotFoundBlockByHash = errors.New("block is not found by hash")

	ErrInvalidDeploySource       = errors.New("invalid source of deploy handler")
	ErrInvalidDeploySourceType   = errors.New("invalid source type of deploy handler")
	ErrInvalidCallFunction       = errors.New("invalid function of call handler")
	ErrInvalidChangeState        = errors.New("invalid argument fo change state")
	ErrInvalidAuthorizeArguments = errors.New("invalid arguments of authorize handler")
	ErrInvalidVote               = errors.New("invalid arguments of pledge handler")

	ErrPledgeTransactionAddressNotEqual = errors.New("pledge transaction from-address not equal to to-address")

	ErrContractTransactionAddressNotEqual = errors.New("contract transaction from-address not equal to to-address")

	ErrOutOfGasLimit   = errors.New("out of gas limit")
	ErrInvalidGasLimit = errors.New("invalid gas limit, should be in (0, 5*10^10]")

	ErrContractFeeTooLow = errors.New("base contract fee is too low.")

	ErrTxDataHandlerOutOfMaxLength = errors.New("data's handler is out of max data length")

	ErrInvalidTxHandlerType = errors.New("invalid transaction data handler type")

	ErrInvalidTransactionResultEvent  = errors.New("invalid transaction result event, the last event in tx's events should be result event")
	ErrNotFoundTransactionResultEvent = errors.New("transaction result event is not found ")

	ErrInvalidElectionResultEvent  = errors.New("invalid election result event, the last event in tx's events should be result event")
	ErrNotFoundElectionResultEvent = errors.New("election result event is not found ")

	ErrInvalidContractAuthFlag = errors.New("invalid contract init authorized flag")
	ErrInvalidAuthorizeType    = errors.New("invalid authorize type,should be in (0,1) ")

	ErrInvalidFuncRule = errors.New("invalid func rule value")

	ErrInvalidRoleRule = errors.New("invalid role rule value")

	ErrInvalidAuthorizeAddress = errors.New("invalid invalid argument \"address\"")

	ErrInvalidFunctionName = errors.New("invalid function name")

	ErrContractStateCheckFailed = errors.New("contract state check failed.")
	ErrNotBlockInCanonicalChain = errors.New("cannot find the block in canonical chain")
	ErrVRFProofFailed           = errors.New("VRF proof failed")
)
