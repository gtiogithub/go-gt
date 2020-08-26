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
	"gt.pro/gtio/go-gt/crypto/ed25519/vrf"
	"gt.pro/gtio/go-gt/crypto/hash"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

type linkedBlock struct {
	block       *Block
	chain       *BlockChain
	hash        byteutils.Hash
	parentHash  byteutils.Hash
	parentBlock *linkedBlock
	childBlocks map[byteutils.HexHash]*linkedBlock
}

func newLinkedBlock(block *Block, chain *BlockChain) *linkedBlock {
	return &linkedBlock{
		block:       block,
		chain:       chain,
		hash:        block.Hash(),
		parentHash:  block.ParentHash(),
		parentBlock: nil,
		childBlocks: make(map[byteutils.HexHash]*linkedBlock),
	}
}

func (lb *linkedBlock) LinkParent(parentBlock *linkedBlock) {
	lb.parentBlock = parentBlock
	parentBlock.childBlocks[lb.hash.Hex()] = lb
}

// Dispose dispose linkedBlock
func (lb *linkedBlock) Dispose() {
	// clear pointer
	lb.block = nil
	lb.chain = nil
	// cut the relationship with children
	for _, v := range lb.childBlocks {
		v.parentBlock = nil
	}
	lb.childBlocks = nil
	// cut the relationship whit parent
	if lb.parentBlock != nil {
		delete(lb.parentBlock.childBlocks, lb.hash.Hex())
		lb.parentBlock = nil
	}
}

func (lb *linkedBlock) travelToLinkAndReturnAllValidBlocks(parentBlock *Block) ([]*Block, []*Block, error) {

	if err := lb.block.LinkParentBlock(lb.chain, parentBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"parent": parentBlock,
			"block":  lb.block,
			"err":    err,
		}).Error("Failed to link the block with its parent.")
		return nil, nil, err
	}

	// prepare vrf inputs
	var ancestorHash, parentSeed []byte
	if lb.block.Height() == 2 {
		parentSeed = parentBlock.header.hash
	} else {
		parentSeed = parentBlock.header.random.VrfSeed
	}

	council, err := parentBlock.WorldState().GetCouncil(parentBlock.TermId())
	if err != nil {
		return nil, nil, err
	}
	baseHeight := uint64(council.Meta.Config.WitnessCount * council.Meta.Config.WitnessCount * council.Meta.Config.FloatingCycle * 2)
	if lb.block.Height() > baseHeight {
		b := lb.chain.GetBlockOnCanonicalChainByHeight(lb.block.Height() - baseHeight)
		if b == nil {
			cur := lb
			for i := uint64(0); i < baseHeight; i++ {
				if cur.parentBlock == nil {
					cur = nil
					break
				}
				cur = cur.parentBlock
			}
			if cur == nil {
				return nil, nil, ErrNotBlockInCanonicalChain
			}
			b = cur.block
		}
		ancestorHash = b.Hash()
	} else {
		ancestorHash = lb.chain.GenesisBlock().Hash()
	}

	if err := vrfProof(lb.block, ancestorHash, parentSeed); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err":      err,
			"lb.block": lb.block,
		}).Error("VRF proof failed.")
		return nil, nil, ErrVRFProofFailed
	}

	if err := lb.block.VerifyExecution(parentBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": lb.block,
			"err":   err,
		}).Error("Failed to execute block.")
		return nil, nil, err
	}

	allBlocks := []*Block{lb.block}
	tailBlocks := make([]*Block, 0)

	if len(lb.childBlocks) == 0 {
		tailBlocks = append(tailBlocks, lb.block)
	}

	for _, clb := range lb.childBlocks {
		a, b, err := clb.travelToLinkAndReturnAllValidBlocks(lb.block)
		if err == nil {
			allBlocks = append(allBlocks, a...)
			tailBlocks = append(tailBlocks, b...)
		}
		//} else if err == ErrNotBlockInCanonicalChain {
		//	tailBlocks = append(tailBlocks, lb.block)
		//}
	}

	return allBlocks, tailBlocks, nil
}

func vrfProof(block *Block, ancestorHash, parentSeed []byte) error {
	pk := vrf.PublicKey(block.Signature().Signer)
	data := hash.Sha3256(ancestorHash, parentSeed)
	if !pk.Verify(data, block.header.random.VrfSeed, block.header.random.VrfProof) {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
		}).Error("VRF proof failed.")
		return ErrVRFProofFailed
	}
	return nil
}
