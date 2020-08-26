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
package psec

import (
	"errors"
)

const (
	Fault = 1

	PP                     = 100
	PA                     = 200
	CM                     = 300
	REPLY                  = 400
	MaxMiningDuration      = int64(10 * 365 * 24 * 60 * 60)
	ElectionAllocateFactor = 100
)

var (
	ErrMiningBlockTimeOut       = errors.New("mining block timeout")
	ErrAppendNewBlockFailed     = errors.New("failed to append new block to real chain")
	ErrCannotMintWhenDisable    = errors.New("cannot mint block now, waiting for enable it again")
	ErrCannotMintWhenPending    = errors.New("cannot mint block now, waiting for cancel suspended again")
	ErrVerifyPreprepareMsgError = errors.New("verify preprepare msg sign error")
	ErrVerifyprepareMsgError    = errors.New("verify prepare msg sign error")
	ErrSeqIdIsTooLow            = errors.New("msg seq id is too low")
	ErrInvalidBlockProposer     = errors.New("invalid block proposer")
	ErrBlockHeightTooLow        = errors.New("the proposed block height is too low ")

	ErrInvalidPaSender = errors.New("invalid prepare message sender")
)

// Errors in psec state
var (
	ErrClonePeriodTrie     = errors.New("Failed to clone period trie")
	ErrCloneVoteTrie       = errors.New("Failed to clone vote trie")
	ErrCloneEventTrie      = errors.New("Failed to clone event trie")
	ErrCloneCouncil        = errors.New("Failed to clone council")
	ErrCloneForbidVoteTrie = errors.New("Failed to clone forbid vote trie")
	ErrCloneOverdueTrie    = errors.New("Failed to clone overdue trie")

	ErrCloneNextPeriodTrie = errors.New("Failed to clone next period trie")
	ErrCloneWitnessTrie    = errors.New("Failed to clone witness trie")
	ErrCloneCandidatesTrie = errors.New("Failed to clone candidates trie")
	ErrCloneMintCntTrie    = errors.New("Failed to clone mint count trie")
	ErrNotBlockForgTime    = errors.New("now is not time to forg block")
	ErrFoundNilProposer    = errors.New("found a nil proposer")

	ErrVoteOutOfLimit = errors.New("The number of votes has exceeded the limit.")

	ErrUnableElectionDuration = errors.New("This account is temporarily unavailable for election.")
)
