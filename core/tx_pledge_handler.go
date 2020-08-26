package core

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/util/logging"
	"math/big"
)

const (
	LoginWitness  = "1"
	LogoutWitness = "2"
)

type PledgeHandler struct {
	PeerId     string
	Address    string
	VoteType   string
	PledgeFund string
}

// LoadPledgeHandler from bytes
func LoadPledgeHandler(bytes []byte) (*PledgeHandler, error) {
	handler := &PledgeHandler{}
	if err := json.Unmarshal(bytes, handler); err != nil {
		return nil, ErrInvalidArgument
	}
	return NewPledgeHandler(handler.PeerId, handler.Address, handler.VoteType, handler.PledgeFund), nil
}

// NewPledgeHandler with data
func NewPledgeHandler(peerId, address, voteType, pledgeFund string) *PledgeHandler {
	return &PledgeHandler{
		PeerId:     peerId,
		Address:    address,
		VoteType:   voteType,
		PledgeFund: pledgeFund,
	}
}

// ToBytes serialize handler
func (handler *PledgeHandler) ToBytes() ([]byte, error) {
	return json.Marshal(handler)
}

// BaseGasCount returns base gas count
func (handler *PledgeHandler) BaseGasCount() *big.Int {
	return big.NewInt(0)
}

func (handler *PledgeHandler) Before(tx *Transaction, block *Block, ws WorldState, config *ChainConfig) error {
	minPledge := config.MinPledge

	switch handler.VoteType {
	case LoginWitness:
		var err error
		pledgeFund := big.NewInt(0)
		if len(handler.PledgeFund) > 0 {
			pledgeFund, err = CUintStringToNcUintBigInt(handler.PledgeFund)
			if err != nil {
				return err
			}
		}
		if pledgeFund.Cmp(minPledge) < 0 {
			logging.CLog().WithFields(logrus.Fields{
				"value":          pledgeFund.String(),
				"required value": minPledge.String(),
			}).Debug(ErrPledgeFundNotEnough.Error())
			return ErrPledgeFundNotEnough
		}
	case LogoutWitness:
		fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Error("Failed to get from account")
			return err
		}
		if fromAcc.PledgeFund().Cmp(big.NewInt(0)) <= 0 {
			return ErrAccountNotJoinElection
		}
	default:
		return ErrInvalidVoteType
	}
	return nil
}

// Execute the pledge handler in tx, call a function
func (handler *PledgeHandler) Execute(limitedGas *big.Int, tx *Transaction, block *Block, ws WorldState) (*big.Int, string, error) {
	if block == nil || tx == nil || ws == nil {
		return zero, "", ErrNilArgument
	}

	if !tx.From().Equals(tx.To()) {
		return zero, "", ErrPledgeTransactionAddressNotEqual
	}

	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get from account")
		return zero, "", err
	}

	switch handler.VoteType {
	case LoginWitness:
		var subErr, addPledgeErr error
		pledgeFund, err := CUintStringToNcUintBigInt(handler.PledgeFund)
		if err != nil {
			return zero, "", err
		}
		subErr = fromAcc.SubBalance(pledgeFund) // sub balance
		if subErr == nil {
			addPledgeErr = fromAcc.AddPledgeFund(pledgeFund) // add pledge
		}

		if subErr != nil || addPledgeErr != nil {
			logging.VLog().WithFields(logrus.Fields{
				"subErr":       subErr,
				"addPledgeErr": addPledgeErr,
				"tx":           tx,
				"fromBalance":  fromAcc.Balance(),
				"block":        block,
			}).Error("Failed to transfer value, unexpected error")
			return zero, "", ErrInvalidTransfer
		}
		electionInfo := &state.JoinElectionInfo{
			PeerId:     handler.PeerId,
			Address:    handler.Address,
			PledgeFund: handler.PledgeFund,
			TxHash:     tx.hash.String(),
		}

		council, err := ws.GetCouncil(block.TermId())
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"termId": block.TermId(),
			}).Error("Get Council exception")
			return zero, "", err
		}

		cycleCount := uint64(council.Meta.Config.WitnessCount * council.Meta.Config.WitnessCount * council.Meta.Config.FloatingCycle)

		electionInfo.JoinHeight = block.Height()
		electionInfo.ExpiryHeight = electionInfo.JoinHeight + cycleCount*VoteExpiryFactor
		electionInfo.RelieveHeight = electionInfo.ExpiryHeight + cycleCount*RelieveFactor

		bytesElection, err := json.Marshal(electionInfo)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"PeerId":     handler.PeerId,
				"Address":    handler.Address,
				"PledgeFund": handler.PledgeFund,
			}).Error("marshal election message  error")
			return zero, "", err
		}
		if err := ws.JoinElection(bytesElection); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"PeerId":     handler.PeerId,
				"Address":    handler.Address,
				"PledgeFund": handler.PledgeFund,
				"tx.hash":    tx.hash.Hex(),
			}).Error("Join Election Exception")
			return zero, "", err
		}
	case LogoutWitness:
		cancelElectionInfo := state.CancelElectionInfo{
			Address: handler.Address,
			TxHash:  tx.hash.String(),
		}
		bytesElection, err := json.Marshal(cancelElectionInfo)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"Address": handler.Address,
			}).Error("marshal cancel election message  error")
			return zero, "", err
		}
		err = ws.CancelElection(bytesElection)
		if err != nil {
			return zero, "", err
		}
	default:
		return zero, "", ErrInvalidVoteType
	}

	return zero, "", nil
}

func (handler *PledgeHandler) After(tx *Transaction, block *Block, ws WorldState, config *ChainConfig, result string) error {
	return nil
}
