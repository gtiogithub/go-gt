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
	"math/big"

	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/util/byteutils"
	"github.com/gogo/protobuf/proto"
)

type BlockMemo struct {
	rewards []*corepb.BlockFundEntity
	pledge  []*corepb.BlockFundEntity
}

func (bm *BlockMemo) Rewards() []*corepb.BlockFundEntity {
	return bm.rewards
}

func (bm *BlockMemo) Pledge() []*corepb.BlockFundEntity {
	return bm.pledge
}

// FromProto converts proto BlockMemo to domain BlockMemo
func (bm *BlockMemo) FromProto(msg proto.Message) error {
	if msg != nil {
		if msg, ok := msg.(*corepb.BlockMemo); ok {
			if msg.Rewards != nil && len(msg.Rewards) > 0 {
				if bm.rewards == nil {
					bm.rewards = make([]*corepb.BlockFundEntity, 0)
				}
				for _, entity := range msg.Rewards {
					bm.rewards = append(bm.rewards, &corepb.BlockFundEntity{
						Address:    entity.Address,
						Balance:    entity.Balance,
						FrozenFund: entity.FrozenFund,
						PledgeFund: entity.PledgeFund,
					})
				}
			}

			if msg.Pledge != nil && len(msg.Pledge) > 0 {
				if bm.pledge == nil {
					bm.pledge = make([]*corepb.BlockFundEntity, 0)
				}
				for _, entity := range msg.Pledge {
					bm.pledge = append(bm.pledge, &corepb.BlockFundEntity{
						Address:    entity.Address,
						Balance:    entity.Balance,
						FrozenFund: entity.FrozenFund,
						PledgeFund: entity.PledgeFund,
					})
				}
			}
			return nil
		}
		return ErrInvalidProtoToBlockMemo
	}
	return ErrInvalidProtoToBlockMemo
}

// ToProto converts domain BlockMemo to proto BlockMemo
func (bm *BlockMemo) ToProto() (proto.Message, error) {
	memo := new(corepb.BlockMemo)
	if bm.rewards != nil && len(bm.rewards) > 0 {
		memo.Rewards = make([]*corepb.BlockFundEntity, 0)
		for _, entity := range bm.rewards {
			memo.Rewards = append(memo.Rewards, &corepb.BlockFundEntity{
				Address:    entity.Address,
				Balance:    entity.Balance,
				FrozenFund: entity.FrozenFund,
				PledgeFund: entity.PledgeFund,
			})
		}
	}
	if bm.pledge != nil && len(bm.pledge) > 0 {
		memo.Pledge = make([]*corepb.BlockFundEntity, 0)
		for _, entity := range bm.pledge {
			memo.Pledge = append(memo.Pledge, &corepb.BlockFundEntity{
				Address:    entity.Address,
				Balance:    entity.Balance,
				FrozenFund: entity.FrozenFund,
				PledgeFund: entity.PledgeFund,
			})
		}
	}
	return memo, nil
}

// BlockHeader
type BlockHeader struct {
	chainId    uint32
	height     uint64
	timestamp  int64
	termId     uint64
	coinbase   *Address
	parentHash byteutils.Hash
	hash       byteutils.Hash

	stateRoot     byteutils.Hash
	txsRoot       byteutils.Hash
	consensusRoot byteutils.Hash
	eventsRoot    byteutils.Hash
	output        *big.Int
	sign          *corepb.Signature
	memo          *BlockMemo

	// rand
	random *corepb.Random
}

// return events Root
func (h *BlockHeader) EventsRoot() []byte { return h.eventsRoot }

// return tx root
func (h *BlockHeader) TxsRoot() []byte { return h.txsRoot }

// return parent's hash
func (h *BlockHeader) ParentHash() []byte { return h.parentHash }

// return timestamp
func (h *BlockHeader) Timestamp() int64 { return h.timestamp }

// return chain id
func (h *BlockHeader) ChainId() uint32 { return h.chainId }

// return coinbase
func (h *BlockHeader) Coinbase() *Address { return h.coinbase }

// return hash
func (h *BlockHeader) Hash() []byte { return h.hash }

// return height
func (h *BlockHeader) Height() uint64 { return h.height }

// return the header's signature
func (h *BlockHeader) Sign() *corepb.Signature {
	sign := *h.sign
	return &sign
}

// FromProto converts proto BlockHeader to domain BlockHeader
func (h *BlockHeader) FromProto(msg proto.Message) error {
	if msg, ok := msg.(*corepb.BlockHeader); ok {
		if msg != nil {
			h.chainId = msg.ChainId
			coinbase, err := AddressParseFromBytes(msg.Coinbase)
			if err != nil {
				return ErrInvalidProtoToBlockHeader
			}
			h.coinbase = coinbase
			h.stateRoot = msg.StateRoot
			h.txsRoot = msg.TxsRoot
			h.eventsRoot = msg.EventsRoot
			h.consensusRoot = msg.ConsensusRoot
			h.parentHash = msg.ParentHash
			h.height = msg.Height
			h.termId = msg.TermId
			h.timestamp = msg.Timestamp
			h.hash = msg.Hash
			h.sign = msg.Sign
			bm := new(BlockMemo)
			bm.FromProto(msg.Memo)
			h.memo = bm
			h.output = new(big.Int).SetBytes(msg.Output)
			h.random = msg.Random
			return nil
		}
		return ErrInvalidProtoToBlockHeader
	}
	return ErrInvalidProtoToBlockHeader
}

// ToProto converts domain BlockHeader to proto BlockHeader
func (h *BlockHeader) ToProto() (proto.Message, error) {
	memo, _ := h.memo.ToProto()
	return &corepb.BlockHeader{
		Hash:          h.hash,
		ParentHash:    h.parentHash,
		Coinbase:      h.coinbase.address,
		ChainId:       h.chainId,
		Timestamp:     h.timestamp,
		Height:        h.height,
		TermId:        h.termId,
		StateRoot:     h.stateRoot,
		TxsRoot:       h.txsRoot,
		EventsRoot:    h.eventsRoot,
		ConsensusRoot: h.consensusRoot,
		Sign:          h.sign,
		Memo:          memo.(*corepb.BlockMemo),
		Output:        h.output.Bytes(),
		Random:        h.random,
	}, nil
}
