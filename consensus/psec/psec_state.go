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
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	consensuspb "gt.pro/gtio/go-gt/consensus/pb"
	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/core/state"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"gt.pro/gtio/go-gt/util/byteutils"
	"gt.pro/gtio/go-gt/util/logging"
	"gt.pro/gtio/go-gt/util/sorted"
	"math"
	"math/big"
	"sort"
	"strconv"
)

type State struct {
	termId     uint64
	eventTrie  *trie.Trie
	reportTrie *trie.Trie

	councilTrie    *trie.Trie //key termId , value witnesses
	voteTrie       *trie.Trie
	overdueTrie    *trie.Trie
	forbidVoteTrie *trie.Trie

	council   *Council
	chain     *core.BlockChain
	consensus core.Consensus
	voteMap   map[string]*VoteInfo
}

type ReportInfo struct {
	TxHash     string
	Prosecutor string
	ReportType string
	Report     *core.Report
}

type PeriodRoot struct {
	CouncilRoot    []byte `json:"council_root"`
	VoteRoot       []byte `json:"vote_root"`
	OverdueRoot    []byte `json:"overdue_root"`
	ForbidVoteRoot []byte `json:"forbid_vote_root"`
}

type VoteInfo struct {
	voteType string
	data     []byte
	nextVote *VoteInfo
}

type CampaignInfo struct {
	PeerId        string
	Address       string
	PledgeFund    string
	JoinHeight    uint64
	ExpiryHeight  uint64
	RelieveHeight uint64
	ElectStatus   byte
	TxHashes      []string
}

// NewState create a new psec state
func (psec *Psec) NewState(root *consensuspb.ConsensusRoot, db cdb.Storage, needChangeLog bool) (state.ConsensusState, error) {
	var councilRoot byteutils.Hash
	var voteRoot byteutils.Hash
	var overdueRoot byteutils.Hash
	var forbidVoteRoot byteutils.Hash
	var eventRoot byteutils.Hash
	var reportRoot byteutils.Hash

	var termId uint64
	var timestamp int64
	if root != nil {
		//periodRoot = root.PeriodRoot
		termId = root.TermId
		timestamp = root.Timestamp
		eventRoot = root.EventRoot

		reportRoot = root.ReportRoot
		if root.PeriodRoot != nil && len(root.PeriodRoot) > 0 {
			periodRoot := &PeriodRoot{}
			if err := json.Unmarshal(root.PeriodRoot, periodRoot); err != nil {
				return nil, err
			}
			councilRoot = periodRoot.CouncilRoot
			voteRoot = periodRoot.VoteRoot
			overdueRoot = periodRoot.OverdueRoot
			forbidVoteRoot = periodRoot.ForbidVoteRoot
		}

	} else {
		termId = 1
		timestamp = core.GenesisTimestamp
	}
	councilTrie, err := trie.NewTrie(councilRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}
	voteTrie, err := trie.NewTrie(voteRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}
	eventTrie, err := trie.NewTrie(eventRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}

	overdueTrie, err := trie.NewTrie(overdueRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}

	forbidVoteTrie, err := trie.NewTrie(forbidVoteRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}

	reportTrie, err := trie.NewTrie(reportRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}
	var council *Council
	if councilRoot != nil {
		byteCouncil, err := councilTrie.Get(byteutils.FromUint64(termId))
		if err != nil {
			return nil, err
		}
		council = new(Council)
		if err := council.FromBytes(byteCouncil, db, needChangeLog); err != nil {
			return nil, err
		}
	} else {
		council, err = NewCouncil(psec.chain, timestamp, needChangeLog)
		if err != nil {
			return nil, err
		}
	}

	cState := &State{
		termId:         termId,
		council:        council,
		councilTrie:    councilTrie,
		voteTrie:       voteTrie,
		overdueTrie:    overdueTrie,
		forbidVoteTrie: forbidVoteTrie,
		eventTrie:      eventTrie,
		reportTrie:     reportTrie,
		chain:          psec.chain,
		voteMap:        make(map[string]*VoteInfo),
		consensus:      psec,
	}
	return cState, nil
}

// Replay a pesc
func (ps *State) Replay(done state.ConsensusState) error {
	state := done.(*State)
	if _, err := ps.councilTrie.Replay(state.councilTrie); err != nil {
		return err
	}
	if _, err := ps.voteTrie.Replay(state.voteTrie); err != nil {
		return err
	}
	if _, err := ps.overdueTrie.Replay(state.overdueTrie); err != nil {
		return err
	}
	if _, err := ps.forbidVoteTrie.Replay(state.forbidVoteTrie); err != nil {
		return err
	}
	if _, err := ps.eventTrie.Replay(state.eventTrie); err != nil {
		return err
	}
	if _, err := ps.reportTrie.Replay(state.reportTrie); err != nil {
		return err
	}
	if err := ps.council.Replay(state.council); err != nil {
		return err
	}
	if state.voteMap != nil && len(state.voteMap) > 0 {
		if ps.voteMap == nil {
			ps.voteMap = make(map[string]*VoteInfo)
		}

		for key, val := range state.voteMap {
			if vote, ok := ps.voteMap[key]; ok {
				cur := vote
				for {
					if cur.nextVote == nil {
						cur.nextVote = val
						break
					} else {
						cur = cur.nextVote
					}
				}
				ps.voteMap[key] = vote
			} else {
				ps.voteMap[key] = val
			}
		}
	}

	return nil
}

// Clone a pesc context
func (ps *State) Clone() (state.ConsensusState, error) {
	var err error
	councilTrie, err := ps.councilTrie.Clone()
	if err != nil {
		return nil, ErrClonePeriodTrie
	}
	voteTrie, err := ps.voteTrie.Clone()
	if err != nil {
		return nil, ErrCloneVoteTrie
	}

	overdueTrie, err := ps.overdueTrie.Clone()
	if err != nil {
		return nil, ErrCloneOverdueTrie
	}

	forbidVoteTrie, err := ps.forbidVoteTrie.Clone()
	if err != nil {
		return nil, ErrCloneForbidVoteTrie
	}

	eventTrie, err := ps.eventTrie.Clone()
	if err != nil {
		return nil, ErrCloneEventTrie
	}

	reportTrie, err := ps.reportTrie.Clone()
	if err != nil {
		return nil, ErrCloneEventTrie
	}

	council, err := ps.council.Clone()
	if err != nil {
		return nil, ErrCloneCouncil
	}
	return &State{
		termId:         ps.termId,
		councilTrie:    councilTrie,
		voteTrie:       voteTrie,
		overdueTrie:    overdueTrie,
		forbidVoteTrie: forbidVoteTrie,
		eventTrie:      eventTrie,
		reportTrie:     reportTrie,
		council:        council,
		chain:          ps.chain,
		consensus:      ps.consensus,
	}, nil
}

// RootHash hash pesc state
func (ps *State) RootHash() *consensuspb.ConsensusRoot {

	consensusRoot := &consensuspb.ConsensusRoot{
		TermId:     ps.termId,
		Timestamp:  ps.council.council.Meta.Timestamp,
		EventRoot:  ps.eventTrie.RootHash(),
		ReportRoot: ps.reportTrie.RootHash(),
	}

	periodRoot := &PeriodRoot{
		CouncilRoot:    ps.councilTrie.RootHash(),
		VoteRoot:       ps.voteTrie.RootHash(),
		OverdueRoot:    ps.overdueTrie.RootHash(),
		ForbidVoteRoot: ps.forbidVoteTrie.RootHash(),
	}
	consensusRoot.PeriodRoot, _ = json.Marshal(periodRoot)

	return consensusRoot
}

func (ps *State) String() string {

	return fmt.Sprintf(`{"termId": %s, "period": "%s","vote": "%s","event":"%s"}`,
		ps.termId,
		byteutils.Hex(ps.councilTrie.RootHash()),
		byteutils.Hex(ps.voteTrie.RootHash()),
		byteutils.Hex(ps.eventTrie.RootHash()),
	)
}

func (ps *State) GetCouncil(termId uint64) (*corepb.Council, error) {
	bytes, err := ps.councilTrie.Get(byteutils.FromUint64(termId))
	if err != nil {
		return nil, err
	}
	council := new(Council)
	if err := council.FromBytes(bytes, ps.chain.Storage(), false); err != nil {
		return nil, err
	}
	return council.council, nil
}

func (ps *State) JoinElection(joinInfo byteutils.Hash) error {
	joinElectionInfo := &state.JoinElectionInfo{}
	if err := json.Unmarshal(joinInfo, joinElectionInfo); err != nil {
		return err
	}

	if vote, ok := ps.voteMap[joinElectionInfo.Address]; ok {
		cur := vote
		for {
			if cur.nextVote == nil {
				cur.nextVote = &VoteInfo{
					voteType: core.LoginWitness,
					data:     joinInfo[:],
					nextVote: nil,
				}
				break
			} else {
				cur = cur.nextVote
			}
		}
		ps.voteMap[joinElectionInfo.Address] = vote
	} else {
		ps.voteMap[joinElectionInfo.Address] = &VoteInfo{
			voteType: core.LoginWitness,
			data:     joinInfo[:],
			nextVote: nil,
		}
	}
	return nil
}

func (ps *State) CancelElection(election byteutils.Hash) error {
	cancelElectionInfo := &state.CancelElectionInfo{}
	if err := json.Unmarshal(election, cancelElectionInfo); err != nil {
		return err
	}
	if vote, ok := ps.voteMap[cancelElectionInfo.Address]; ok {
		cur := vote
		for {
			if cur.nextVote == nil {
				cur.nextVote = &VoteInfo{
					voteType: core.LogoutWitness,
					data:     election[:],
					nextVote: nil,
				}
				break
			} else {
				cur = cur.nextVote
			}
		}
		ps.voteMap[cancelElectionInfo.Address] = vote
	} else {
		ps.voteMap[cancelElectionInfo.Address] = &VoteInfo{
			voteType: core.LogoutWitness,
			data:     election[:],
			nextVote: nil,
		}
	}
	return nil

}

func (ps *State) RecordEvil(txHash byteutils.Hash, address, reportType string, report byteutils.Hash) error {
	reportObj := &core.Report{}
	if err := json.Unmarshal(report, reportObj); err != nil {
		return err
	}
	key := trie.HashDomains(strconv.FormatInt(reportObj.Timestamp, 10), reportType, reportObj.Malefactor, address)
	reportInfo := &ReportInfo{
		TxHash:     txHash.String(),
		Prosecutor: address,
		ReportType: reportType,
		Report:     reportObj,
	}

	bytes, err := json.Marshal(reportInfo)
	if err != nil {
		return err
	}
	_, err = ps.reportTrie.Put(key, bytes)
	if err != nil {
		return err
	}
	return nil
}

func (ps *State) processBlockVoteInfo(ws state.WorldState, height uint64) ([]*state.ElectionEvent, error) {
	events := make([]*state.ElectionEvent, 0)
	if ps.voteMap != nil && len(ps.voteMap) > 0 {
		for _, vote := range ps.voteMap {
			cur := vote
			for {
				if cur.voteType == core.LoginWitness {
					joinElectionInfo := &state.JoinElectionInfo{}
					if err := json.Unmarshal(cur.data, joinElectionInfo); err != nil {
						return nil, err
					}
					bytes, err := ps.voteTrie.Get([]byte(joinElectionInfo.Address))
					if err != nil && err != cdb.ErrKeyNotFound {
						return nil, err
					}

					if bytes != nil {
						oldElection := &CampaignInfo{}
						if err := json.Unmarshal(bytes, oldElection); err != nil {
							return nil, err
						}
						oldPledgeFund, err := core.CUintStringToNcUintBigInt(oldElection.PledgeFund)
						if err != nil {
							return nil, err
						}
						pledgeFund, err := core.CUintStringToNcUintBigInt(joinElectionInfo.PledgeFund)
						if err != nil {
							return nil, err
						}
						oldElection.PledgeFund = core.NcUnitToCUnitString(new(big.Int).Add(oldPledgeFund, pledgeFund))

						oldElection.TxHashes = append(oldElection.TxHashes, joinElectionInfo.TxHash)
						sort.Strings(oldElection.TxHashes)
						bytesElection, err := json.Marshal(oldElection)
						if err != nil {
							return nil, err
						}
						_, err = ps.voteTrie.Put([]byte(joinElectionInfo.Address), bytesElection)
						if err != nil {
							return nil, err
						}
					} else {
						forbidBytes, err := ps.forbidVoteTrie.Get([]byte(joinElectionInfo.Address))
						if err != nil && err != cdb.ErrKeyNotFound {
							return nil, err
						}

						if forbidBytes != nil {
							forbidHeight := byteutils.Uint64(forbidBytes)
							if joinElectionInfo.JoinHeight <= forbidHeight {
								event := &state.ElectionEvent{
									Address:    joinElectionInfo.Address,
									Hashes:     make([]string, 0),
									Selected:   -1,
									Role:       "normal",
									PledgeFund: joinElectionInfo.PledgeFund,
									Score:      0,
								}

								err = ps.recordElectResult(&state.VoteEvent{
									Address:    joinElectionInfo.Address,
									Status:     "-1",
									Cause:      "The ban on voting has not expired",
									PledgeFund: joinElectionInfo.PledgeFund,
								}, height, []string{joinElectionInfo.TxHash})

								if err != nil {
									return nil, err
								}

								event.Hashes = append(event.Hashes, joinElectionInfo.TxHash)
								events = append(events, event)

								if err := ps.refundPledgeFund(joinElectionInfo.Address, joinElectionInfo.PledgeFund, ws); err != nil {
									return nil, err
								}
								//return nil,ErrUnableElectionDuration
								continue
							}
						}
						campaignInfo := &CampaignInfo{
							PeerId:        joinElectionInfo.PeerId,
							Address:       joinElectionInfo.Address,
							PledgeFund:    joinElectionInfo.PledgeFund,
							JoinHeight:    joinElectionInfo.JoinHeight,
							ExpiryHeight:  joinElectionInfo.ExpiryHeight,
							RelieveHeight: joinElectionInfo.RelieveHeight,
							ElectStatus:   0,
							TxHashes:      make([]string, 0),
						}
						campaignInfo.TxHashes = append(campaignInfo.TxHashes, joinElectionInfo.TxHash)
						bytesElection, err := json.Marshal(campaignInfo)
						if err != nil {
							return nil, err
						}
						_, err = ps.voteTrie.Put([]byte(joinElectionInfo.Address), bytesElection)
						if err != nil {
							return nil, err
						}

						//process forbid vote
						_, err = ps.forbidVoteTrie.Put([]byte(joinElectionInfo.Address), byteutils.FromUint64(joinElectionInfo.RelieveHeight))
						if err != nil {
							return nil, err
						}

						//process
						overdueBytes, err := ps.overdueTrie.Get(byteutils.FromUint64(joinElectionInfo.ExpiryHeight))
						if err != nil && err != cdb.ErrKeyNotFound {
							return nil, err
						}

						overdueAddresses := make([]string, 0)
						if overdueBytes != nil {
							if err := json.Unmarshal(overdueBytes, &overdueAddresses); err != nil {
								return nil, err
							}
						}
						overdueAddresses = append(overdueAddresses, joinElectionInfo.Address)
						sort.Strings(overdueAddresses)
						logging.CLog().WithFields(logrus.Fields{
							"overdueAddresses": overdueAddresses,
						}).Info("all addresses")
						newAddressesBytes, err := json.Marshal(overdueAddresses)
						if err != nil {
							return nil, err
						}
						_, err = ps.overdueTrie.Put(byteutils.FromUint64(joinElectionInfo.ExpiryHeight), newAddressesBytes)
						if err != nil {
							return nil, err
						}
					}
				} else if cur.voteType == core.LogoutWitness {
					cancelElectionInfo := &state.CancelElectionInfo{}
					if err := json.Unmarshal(cur.data, cancelElectionInfo); err != nil {
						return nil, err
					}

					bytes, err := ps.voteTrie.Get([]byte(cancelElectionInfo.Address))
					if err != nil && err != cdb.ErrKeyNotFound {
						return nil, err
					}
					if bytes == nil {
						err = ps.recordElectResult(&state.VoteEvent{
							Address:    cancelElectionInfo.Address,
							Status:     "-2",
							Cause:      "There is no voting information for this account",
							PledgeFund: "0",
						}, height, []string{cancelElectionInfo.TxHash})

						if err != nil {
							return nil, err
						}
						//return core.ErrAccountNotJoinElection
						continue
					}

					campaignInfo := &CampaignInfo{}
					if err := json.Unmarshal(bytes, campaignInfo); err != nil {
						return nil, err
					}

					if campaignInfo.ElectStatus == 1 {
						err = ps.recordElectResult(&state.VoteEvent{
							Address:    cancelElectionInfo.Address,
							Status:     "-3",
							Cause:      "The election success account observation period is not over",
							PledgeFund: "0",
						}, height, []string{cancelElectionInfo.TxHash})

						if err != nil {
							return nil, err
						}
						continue
					}

					if err := ps.refundPledgeFund(campaignInfo.Address, campaignInfo.PledgeFund, ws); err != nil {
						return nil, err
					}

					events = append(events, &state.ElectionEvent{
						Address:    campaignInfo.Address,
						Hashes:     campaignInfo.TxHashes,
						Selected:   0,
						Role:       "normal",
						PledgeFund: campaignInfo.PledgeFund,
						Score:      0,
					})

					err = ps.recordElectResult(&state.VoteEvent{
						Address:    cancelElectionInfo.Address,
						Status:     "2",
						Cause:      "Successful return of pledge funds",
						PledgeFund: campaignInfo.PledgeFund,
					}, height, campaignInfo.TxHashes)

					if err != nil {
						return nil, err
					}

					overdueBytes, err := ps.overdueTrie.Get(byteutils.FromUint64(campaignInfo.ExpiryHeight))
					if err != nil {
						return nil, err
					}

					addresses := make([]string, 0)
					if err := json.Unmarshal(overdueBytes, &addresses); err != nil {
						return nil, err
					}
					newAddresses := make([]string, 0)
					for _, address := range addresses {
						if cancelElectionInfo.Address == address {
							continue
						}
						newAddresses = append(newAddresses, address)
					}
					sort.Strings(newAddresses)
					newAddressBytes, err := json.Marshal(newAddresses)
					if err != nil {
						return nil, err
					}
					_, err = ps.overdueTrie.Put(byteutils.FromUint64(campaignInfo.ExpiryHeight), newAddressBytes)
					if err != nil {
						return nil, err
					}
					_, err = ps.forbidVoteTrie.Del([]byte(cancelElectionInfo.Address))
					if err != nil {
						return nil, err
					}

					_, err = ps.voteTrie.Del([]byte(cancelElectionInfo.Address))
					if err != nil {
						return nil, err
					}

				}
				if cur.nextVote != nil {
					cur = cur.nextVote
				} else {
					break
				}
			}
		}
	}
	return events, nil
}

func (ps *State) validConsensusAddress(addr string) bool {
	panels := ps.council.council.Panels
	if panels != nil && len(panels) > 0 {
		for _, panel := range panels {
			if panel.Leader.Address == addr {
				return true
			}
			if panel.Members != nil && len(panel.Members) > 0 {
				for _, member := range panel.Members {
					if member.Address == addr {
						return true
					}
				}
			}
		}
	}
	return false
}

// NextConsensusState return the new state after some seconds elapsed
func (ps *State) NextConsensusState(info []byte, ws state.WorldState) (state.ConsensusState, []*state.ElectionEvent, error) {
	statistics := &state.ChangeStateInfo{}
	if err := json.Unmarshal(info, statistics); err != nil {
		return nil, nil, err
	}
	allEvents := make([]*state.ElectionEvent, 0)
	config := ps.council.council.Meta.Config
	var err error
	endBlock := false
	if statistics.Height == ps.council.council.Meta.TenureEndHeight {
		endBlock = true
	}
	if endBlock {
		config, err = ps.chain.LoadSystemConfig()
		if err != nil {
			return nil, nil, err
		}
	}

	events, err := ps.processBlockVoteInfo(ws, statistics.Height)
	if err != nil {
		return nil, nil, err
	}
	allEvents = append(allEvents, events...)

	miner, err := core.AddressParse(statistics.Miner)
	if err != nil {
		return nil, nil, err
	}

	phaseKey := append(byteutils.FromUint64(ps.termId), byteutils.FromUint32(ps.council.phaseNum)...)
	phaseMinerRoot, err := ps.council.minerTrie.Get(phaseKey)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, nil, err
	}
	var phaseMinerTrie *trie.Trie
	if phaseMinerRoot != nil {
		phaseMinerTrie, err = trie.NewTrie(phaseMinerRoot, ps.council.storage, false)
		if err != nil {
			return nil, nil, err
		}
	} else {
		phaseMinerTrie, err = trie.NewTrie(nil, ps.council.storage, false)
		if err != nil {
			return nil, nil, err
		}
	}

	newPhaseMinerRoot, err := phaseMinerTrie.Put(miner.Bytes(), miner.Bytes())
	if err != nil {
		return nil, nil, err
	}

	_, err = ps.council.minerTrie.Put(phaseKey, newPhaseMinerRoot)
	if err != nil {
		return nil, nil, err
	}

	if statistics.Participators != nil && len(statistics.Participators) > 0 {
		for k, _ := range statistics.Participators {
			participator, err := core.AddressParse(k)
			if err != nil {
				return nil, nil, err
			}
			count, err := ps.council.participatorTrie.Get(participator.Bytes())
			if err != nil && err != cdb.ErrKeyNotFound {
				return nil, nil, err
			}
			if count == nil {
				_, err = ps.council.participatorTrie.Put(participator.Bytes(), byteutils.FromInt64(1))
				if err != nil {
					return nil, nil, err
				}
				ps.council.council.State.ParticipatorCnt++
			} else {
				_, err = ps.council.participatorTrie.Put(participator.Bytes(), byteutils.FromInt64(byteutils.Int64(count)+1))
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	_, err = ps.council.heightTrie.Put(byteutils.FromUint64(statistics.Height), byteutils.FromInt64(statistics.Timestamp))
	if err != nil {
		return nil, nil, err
	}

	ps.council.council.State.NormalTxCnt += statistics.NormalTxCnt
	ps.council.council.State.ContractTxCnt += statistics.ContractTxCnt

	//report process
	WitnessCnt := uint64(ps.council.council.Meta.Config.WitnessCount)
	heightDiff := (statistics.Height + 1 - uint64(ps.council.phaseNum)*WitnessCnt) - ps.council.council.Meta.TenureStartHeight
	phaseEndBlock := heightDiff == 0

	if phaseEndBlock {
		if err := ps.processReport(ws); err != nil {
			return nil, nil, err
		}
	}

	nextTermId := ps.termId
	var voteTrie *trie.Trie
	var panels []*corepb.Panel

	if endBlock {

		//process next council
		nextTermId++

		//choose witnesses
		panels, err = ps.chooseNextPanels(statistics.Height, ws, config)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err":    err,
				"height": statistics.Height,
				"config": config,
			}).Info("[chooseNextPanels] get next panels failed")
			return nil, nil, err
		}
		participatorTrie, err := trie.NewTrie(nil, ps.council.storage, false)
		if err != nil {
			return nil, nil, err
		}

		tenure := config.WitnessCount * config.WitnessCount * config.FloatingCycle
		newCouncil := &corepb.Council{
			Meta: &corepb.CouncilMeta{
				ChainId:           ps.council.chainId,
				TermId:            nextTermId,
				Timestamp:         statistics.Timestamp + int64(config.BlockInterval),
				TenureStartHeight: statistics.Height + 1,
				TenureEndHeight:   statistics.Height + uint64(tenure),
				Config:            config,
			},
			Panels: panels,
			State: &corepb.PeriodState{
				NormalTxCnt:     0,
				ContractTxCnt:   0,
				ParticipatorCnt: 0,
			},
		}
		ps.council.phaseNum = 1
		ps.council.council = newCouncil
		ps.council.participatorTrie = participatorTrie
		//ps.council.minerTrie = minerTrie
	}

	voteTrie, err = ps.voteTrie.Clone()
	if err != nil {
		return nil, nil, ErrCloneVoteTrie
	}

	overdueTrie, err := ps.overdueTrie.Clone()
	if err != nil {
		return nil, nil, ErrCloneOverdueTrie
	}

	forbidVoteTrie, err := ps.forbidVoteTrie.Clone()
	if err != nil {
		return nil, nil, ErrCloneForbidVoteTrie
	}

	if phaseEndBlock && statistics.Height > ps.council.council.Meta.TenureStartHeight {
		err = ps.getNextPhaseProposer()
		if err != nil {
			return nil, nil, err
		}
	}

	councilTrie, err := ps.councilTrie.Clone()
	if err != nil {
		return nil, nil, err
	}

	reportTrie, err := ps.reportTrie.Clone()
	if err != nil {
		return nil, nil, err
	}

	eventTrie, err := ps.eventTrie.Clone()
	if err != nil {
		return nil, nil, ErrCloneEventTrie
	}

	nextCouncil, err := ps.council.Clone()
	if err != nil {
		return nil, nil, err
	}

	byteCouncil, err := nextCouncil.ToBytes()
	if err != nil {
		return nil, nil, err
	}
	_, err = councilTrie.Put(byteutils.FromUint64(nextTermId), byteCouncil)
	if err != nil {
		return nil, nil, err
	}
	consensusState := &State{
		termId:         nextTermId,
		councilTrie:    councilTrie,
		reportTrie:     reportTrie,
		eventTrie:      eventTrie,
		voteTrie:       voteTrie,
		overdueTrie:    overdueTrie,
		forbidVoteTrie: forbidVoteTrie,
		council:        nextCouncil,
		chain:          ps.chain,
		consensus:      ps.consensus,
	}

	events, err = consensusState.clearOverdueVote(panels, statistics.Height, ws)
	if err != nil {
		return nil, nil, err
	}
	allEvents = append(allEvents, events...)
	return consensusState, allEvents, nil
}

func (ps *State) processReport(ws state.WorldState) error {
	if ps.termId == 1 {
		return nil
	}
	var startHeight, endHeight uint64
	var blockInterval int64
	var witnessCount int32
	if ps.council.phaseNum == 1 {
		if ps.termId == 2 {
			return nil
		}
		termId := ps.termId - 1
		tempCouncil, err := ps.GetCouncil(termId)
		if err != nil {
			return err
		}
		config := tempCouncil.Meta.Config
		tenure := tempCouncil.Meta.TenureEndHeight - tempCouncil.Meta.TenureStartHeight + 1
		phaseCount := tenure / uint64(config.WitnessCount)

		startHeight = tempCouncil.Meta.TenureStartHeight + (phaseCount-1)*uint64(config.WitnessCount)
		endHeight = startHeight + uint64(config.WitnessCount)
		blockInterval = int64(config.BlockInterval)
		witnessCount = config.WitnessCount
	} else {
		config := ps.council.council.Meta.Config
		startHeight = ps.council.council.Meta.TenureStartHeight + uint64((ps.council.phaseNum-1-1)*uint32(config.WitnessCount))
		endHeight = startHeight + uint64(config.WitnessCount)
		blockInterval = int64(config.BlockInterval)
		witnessCount = config.WitnessCount
	}

	startTimeBytes, err := ps.council.heightTrie.Get(byteutils.FromUint64(startHeight))
	if err != nil {
		return err
	}
	startTimestamp := byteutils.Int64(startTimeBytes)
	endTimeBytes, err := ps.council.heightTrie.Get(byteutils.FromUint64(endHeight))
	if err != nil {
		return err
	}
	endTimestamp := byteutils.Int64(endTimeBytes)

	fault := witnessCount / 3
	for timestamp := startTimestamp; timestamp < endTimestamp; timestamp += blockInterval {
		prefix := trie.HashDomainsPrefix(strconv.FormatInt(timestamp, 10))
		iter, err := ps.reportTrie.Iterator(prefix)
		if err != nil {
			continue
		}
		reportMap := make(map[string]map[string]*ReportInfo)
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
			prefixKey := byteutils.Hex(iter.Key()[0:18])
			key := byteutils.Hex(iter.Key()[18:])
			reportNode := &ReportInfo{}
			if err := json.Unmarshal(iter.Value(), reportNode); err != nil {
				return err
			}
			itemMap, ok := reportMap[prefixKey]
			if !ok {
				itemMap = make(map[string]*ReportInfo)
			}
			itemMap[key] = reportNode
			reportMap[prefixKey] = itemMap
		}
		if len(reportMap) > 0 {
			for _, itemMap := range reportMap {
				if int32(len(itemMap)) > fault {
					err := ps.penalizeEvil(itemMap, witnessCount, ws)
					if err != nil {
						return err
					}
				}
			}
		}

	}
	return nil
}

func (ps *State) penalizeEvil(reports map[string]*ReportInfo, witnessCount int32, ws state.WorldState) error {
	reportReward := core.BlockReward / int64(witnessCount)
	reward := big.NewInt(reportReward)
	strReward := core.NcUnitToCUnitString(reward)

	for _, report := range reports {
		prosecutor, err := core.AddressParse(report.Prosecutor)
		if err != nil {
			return err
		}
		prosecutorAcc, err := ws.GetOrCreateAccount(prosecutor.Bytes())
		if err != nil {
			return err
		}
		if err := prosecutorAcc.AddBalance(reward); err != nil {
			return err
		}

		rewardEvent := state.ReportRewardEvent{
			Prosecutor: report.Prosecutor,
			Timestamp:  report.Report.Timestamp,
			Malefactor: report.Report.Malefactor,
			Amount:     strReward,
		}
		rewardData, err := json.Marshal(rewardEvent)
		event := &state.Event{
			Topic: core.TopicReportReward,
			Data:  string(rewardData),
		}

		txHash, err := byteutils.FromHex(report.TxHash)
		key := append(txHash, byteutils.FromUint64(1)...)

		bytes, err := json.Marshal(event)
		if err != nil {
			return err
		}

		_, err = ps.eventTrie.Put(key, bytes)
		if err != nil {
			return err
		}

		malefactor, err := core.AddressParse(report.Report.Malefactor)
		if err != nil {
			return err
		}
		malefactorAcc, err := ws.GetOrCreateAccount(malefactor.Bytes())
		if err != nil {
			return err
		}
		malefactorAcc.SetEvil(ps.termId)
		if err := malefactorAcc.IncreaseIntegral(ps.termId, state.DoEvil); err != nil {
			return err
		}
		if err := malefactorAcc.SubPledgeFund(reward); err != nil {
			return err
		}

		doEvilEvent := state.DoEvilEvent{
			Malefactor:    report.Report.Malefactor,
			EvilType:      report.ReportType,
			PenaltyAmount: strReward,
			Timestamp:     report.Report.Timestamp,
		}

		doEvilData, err := json.Marshal(doEvilEvent)
		punishmentEvent := &state.Event{
			Topic: core.TopicDoEvilPunishment,
			Data:  string(doEvilData),
		}

		key = append(txHash, byteutils.FromUint64(2)...)

		bytes, err = json.Marshal(punishmentEvent)
		if err != nil {
			return err
		}

		_, err = ps.eventTrie.Put(key, bytes)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ps *State) clearOverdueVote(panels []*corepb.Panel, height uint64, ws state.WorldState) ([]*state.ElectionEvent, error) {
	if panels != nil && len(panels) > 0 {
		for _, panel := range panels {

			if err := ps.changeVoteInfo(panel.Leader.Address, height); err != nil {
				return nil, err
			}
			if panel.Members != nil && len(panel.Members) > 0 {
				for _, member := range panel.Members {
					if err := ps.changeVoteInfo(member.Address, height); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	overdueBytes, err := ps.overdueTrie.Get(byteutils.FromUint64(height))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	events := make([]*state.ElectionEvent, 0)
	if overdueBytes != nil {
		addresses := make([]string, 0)
		if err := json.Unmarshal(overdueBytes, &addresses); err != nil {
			return nil, err
		}
		for _, address := range addresses {
			bytes, err := ps.voteTrie.Get([]byte(address))
			if err != nil {
				return nil, err
			}
			campaignInfo := &CampaignInfo{}
			if err := json.Unmarshal(bytes, campaignInfo); err != nil {
				return nil, err
			}
			if err := ps.refundPledgeFund(campaignInfo.Address, campaignInfo.PledgeFund, ws); err != nil {
				return nil, err
			}
			events = append(events, &state.ElectionEvent{
				Address:    campaignInfo.Address,
				Hashes:     campaignInfo.TxHashes,
				Selected:   0,
				Role:       "normal",
				PledgeFund: campaignInfo.PledgeFund,
				Score:      0,
			})
			err = ps.recordElectResult(&state.VoteEvent{
				Address:    campaignInfo.Address,
				PledgeFund: campaignInfo.PledgeFund,
				Status:     "0",
				Cause:      "The voting information for this account was not selected",
			}, height, campaignInfo.TxHashes)
			if err != nil {
				return nil, err
			}

			_, err = ps.voteTrie.Del([]byte(address))
			if err != nil {
				return nil, err
			}
		}
		_, err = ps.overdueTrie.Del(byteutils.FromUint64(height))
		if err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (ps *State) changeVoteInfo(address string, height uint64) error {
	bytes, err := ps.voteTrie.Get([]byte(address))
	if err != nil {
		return err
	}
	campaignInfo := &CampaignInfo{}
	if err := json.Unmarshal(bytes, campaignInfo); err != nil {
		return err
	}
	campaignInfo.JoinHeight = height
	campaignInfo.ElectStatus = 1

	config := ps.council.council.Meta.Config
	cycleCount := uint64(config.WitnessCount * config.WitnessCount * config.FloatingCycle)

	overdueBytes, err := ps.overdueTrie.Get(byteutils.FromUint64(campaignInfo.ExpiryHeight))
	if err != nil {
		return err
	}

	addresses := make([]string, 0)
	if err := json.Unmarshal(overdueBytes, &addresses); err != nil {
		return err
	}
	newAddresses := make([]string, 0)
	for _, item := range addresses {
		if address == item {
			continue
		}
		newAddresses = append(newAddresses, item)
	}
	sort.Strings(newAddresses)
	newAddressBytes, err := json.Marshal(newAddresses)
	if err != nil {
		return err
	}
	_, err = ps.overdueTrie.Put(byteutils.FromUint64(campaignInfo.ExpiryHeight), newAddressBytes)
	if err != nil {
		return err
	}
	campaignInfo.ExpiryHeight = campaignInfo.JoinHeight + cycleCount*core.VoteExpiryFactor

	overdueBytes, err = ps.overdueTrie.Get(byteutils.FromUint64(campaignInfo.ExpiryHeight))
	if err != nil && err != cdb.ErrKeyNotFound {
		return err
	}

	addresses = make([]string, 0)
	if overdueBytes != nil {
		if err := json.Unmarshal(overdueBytes, &addresses); err != nil {
			return err
		}
	}
	addresses = append(addresses, address)
	sort.Strings(addresses)
	newAddressesBytes, err := json.Marshal(addresses)
	if err != nil {
		return err
	}

	_, err = ps.overdueTrie.Put(byteutils.FromUint64(campaignInfo.ExpiryHeight), newAddressesBytes)
	if err != nil {
		return err
	}
	campaignInfo.RelieveHeight = campaignInfo.ExpiryHeight + cycleCount*core.RelieveFactor
	_, err = ps.forbidVoteTrie.Put([]byte(address), byteutils.FromUint64(campaignInfo.RelieveHeight))
	if err != nil {
		return err
	}
	newCampaignInfoBytes, err := json.Marshal(campaignInfo)
	if err != nil {
		return err
	}
	_, err = ps.voteTrie.Put([]byte(address), newCampaignInfoBytes)
	if err != nil {
		return err
	}
	return nil
}

func (ps *State) getNextPhaseProposer() error {
	ps.council.phaseNum++
	panels := ps.council.council.Panels
	if panels != nil && len(panels) > 0 {
		//phaseKey := trie.HashDomains(strconv.FormatUint(ps.termId,10),strconv.FormatUint(uint64(ps.council.phaseNum-1),10))
		phaseKey := append(byteutils.FromUint64(ps.termId), byteutils.FromUint32(ps.council.phaseNum-1)...)
		phaseMinerRoot, err := ps.council.minerTrie.Get(phaseKey)
		if err != nil && err != cdb.ErrKeyNotFound {
			return err
		}

		if err != nil {
			return nil
		}

		phaseMinerTrie, err := trie.NewTrie(phaseMinerRoot, ps.council.storage, false)
		if err != nil {
			return err
		}

		for index, panel := range panels {
			addr, err := core.AddressParse(panel.Leader.Address)
			if err != nil {
				logging.CLog().WithFields(logrus.Fields{
					"err":     err,
					"address": panel.Leader.Address,
				}).Info("[getNextPhaseProposer] get next phase proposer failed")
				return err
			}
			_, err = phaseMinerTrie.Get(addr.Bytes())
			if err != nil && err != cdb.ErrKeyNotFound {
				return err
			}
			if err != nil {
				oldLeader := &corepb.Member{
					PeerId:     panel.Leader.PeerId,
					Address:    panel.Leader.Address,
					PledgeFund: panel.Leader.PledgeFund,
				}
				if panel.Members != nil && len(panel.Members) > 0 {
					panel.Leader = panel.Members[0]
					panel.Members[0] = panel.Members[1]
					panel.Members[1] = panel.Members[2]
					panel.Members[2] = oldLeader
				}
			}
			ps.council.council.Panels[index] = panel
		}
	}
	return nil
}

func (ps *State) FetchElectionEvent(txHash byteutils.Hash) (*state.ElectionEvent, error) {
	bytes, err := ps.eventTrie.Get(txHash)
	if err != nil {
		if err == cdb.ErrKeyNotFound {
			return nil, core.ErrNotFoundElectionResultEvent
		}
		return nil, err
	}
	event := new(state.ElectionEvent)
	if err = json.Unmarshal(bytes, event); err != nil {
		return nil, err
	}
	return event, err
}

// credit index
type score struct {
	election *CampaignInfo
	address  string
	value    int64
}

// compare credit index
func scoreCmp(a interface{}, b interface{}) int {
	aScore := a.(*score)
	bScore := b.(*score)
	if aScore.value > bScore.value {
		return 1
	}
	if aScore.value < bScore.value {
		return -1
	}

	//equal score
	if aScore.address > bScore.address {
		return -1
	}

	if aScore.address < bScore.address {
		return 1
	}

	return 0
}

func (ps *State) chooseNextPanels(height uint64, ws state.WorldState, config *corepb.SystemConfig) ([]*corepb.Panel, error) {

	iter, err := ps.voteTrie.Iterator(nil)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err != nil {
		return nil, nil
	}

	exist, err := iter.Next()
	if err != nil {
		return nil, err
	}

	allPeers := make(map[string]bool)
	validSuperNodes := make(map[string]*CampaignInfo, 0)
	allElections := make([]*CampaignInfo, 0)
	for exist {
		campaignInfo := &CampaignInfo{}
		if err := json.Unmarshal(iter.Value(), campaignInfo); err != nil {
			return nil, err
		}
		if _, ok := allPeers[campaignInfo.PeerId]; !ok {
			allElections = append(allElections, campaignInfo)
			if config.SuperNodes != nil && len(config.SuperNodes) > 0 {
				for _, node := range config.SuperNodes {
					if node.Address == campaignInfo.Address {
						validSuperNodes[campaignInfo.Address] = campaignInfo
						break
					}
				}
			}
			allPeers[campaignInfo.PeerId] = true
		}
		exist, err = iter.Next()
		if err != nil {
			return nil, err
		}
	}

	// calc credit
	selected := make([]*score, 0)
	scores := sorted.NewSlice(scoreCmp)
	if len(allElections) > 0 {
		participatorCnt := ps.council.council.State.ParticipatorCnt
		if participatorCnt == 0 {
			participatorCnt = 1
		}

		avgNormal := ps.council.council.State.NormalTxCnt / participatorCnt
		avgContract := ps.council.council.State.ContractTxCnt / participatorCnt

		termId := ps.termId

		perPledge := new(big.Int).SetBytes(config.MinPledge)

		for _, electionInfo := range allElections {
			var ts, cs uint64
			var deduction, production uint64
			address, err := core.AddressParse(electionInfo.Address)
			if err != nil {
				return nil, err
			}
			account, _ := ws.GetOrCreateAccount(address.Bytes())
			integral := account.CreditIntegral(termId)

			if integral.Normal >= avgNormal {
				ts = 20
			} else {
				ts = 20 * integral.Normal / avgNormal
			}

			if integral.Contract >= avgContract {
				cs = 30
			} else {
				cs = 30 * integral.Contract / avgContract
			}

			production = 0
			for i := termId; i >= termId-5 && i > 0; i-- {
				tempIntegral := account.CreditIntegral(i)
				production += tempIntegral.CollectBlock
			}

			//if doEvils == 0 {
			//	deduction = 0
			//} else if doEvils == 1 {
			//	deduction = 20
			//} else {
			//	deduction = 20 * (2<<doEvils - 1)
			//}

			deduction = 0
			termDiff := account.Evil() - ps.termId
			if account.Evil() != 0 && account.Evil()-termDiff <= 5 {
				deduction = 20 * (5 - termDiff + 1)
			}

			tenure := uint64(config.WitnessCount * config.WitnessCount * config.FloatingCycle)

			contribution := big.NewInt(0)
			contractIntegral := account.ContractIntegral()
			for _, item := range contractIntegral {
				heightDiff := height - item.CreatedHeight
				if heightDiff > tenure {
					j := heightDiff % tenure
					k := heightDiff / tenure
					periodCount := k
					if j > 0 {
						periodCount++
					}
					itemContractAddr, _ := core.AddressParse(item.Address)
					itemContractAccount, _ := ws.GetOrCreateAccount(itemContractAddr.Bytes())
					l := new(big.Int).Div(new(big.Int).SetBytes(itemContractAccount.ContractIntegral()[0].GetContractTxCount()), big.NewInt(int64(periodCount)))
					contribution = new(big.Int).Add(contribution, l)
				}
			}

			a := new(big.Int).Add(big.NewInt(int64(ts+cs+production)), contribution)
			b, err := core.CUintStringToNcUintBigInt(electionInfo.PledgeFund)
			if err != nil {
				return nil, err
			}

			pledgeScore := new(big.Int).Div(b, perPledge)
			if pledgeScore.Cmp(big.NewInt(20)) == 1 {
				pledgeScore = big.NewInt(20)
			}

			index := new(big.Int).Add(a, pledgeScore)
			if index.Cmp(big.NewInt(int64(deduction))) == -1 {
				index = big.NewInt(0)
			} else {
				index = index.Sub(index, big.NewInt(int64(deduction)))
			}

			if _, ok := validSuperNodes[electionInfo.Address]; !ok {
				scores.Push(&score{
					election: electionInfo,
					address:  electionInfo.Address,
					value:    index.Int64(),
				})
			} else {
				selected = append(selected, &score{
					election: electionInfo,
					address:  electionInfo.Address,
					value:    index.Int64(),
				})
			}

			if account != nil {
				_ = account.SetCreditIndex(index)
				logging.VLog().WithFields(logrus.Fields{
					"tx_account":   account.Address().String(),
					"credit_index": index.Int64(),
				}).Debug("tx change account credit")
			}
		}
	}

	superNodeCnt := len(validSuperNodes)

	length := scores.Len()
	WITNUM := int(config.WitnessCount)
	ALLNUM := int(config.WitnessCount * 4)
	chooseNum1 := WITNUM - superNodeCnt
	chooseNum2 := ALLNUM - superNodeCnt

	if length >= chooseNum1 && length < chooseNum2 {
		for i := 1; i <= chooseNum1; i++ {
			cr := scores.Index(length - i).(*score)
			selected = append(selected, cr)
			logging.VLog().WithFields(logrus.Fields{
				"address": cr.address,
				"score":   cr.value,
			}).Info("Elect a Node")
			err := ps.recordElectResult(&state.VoteEvent{
				Address:    cr.election.Address,
				PledgeFund: cr.election.PledgeFund,
				Status:     "1",
				Cause:      "",
			}, height, cr.election.TxHashes)
			if err != nil {
				return nil, err
			}
		}
	} else if length >= chooseNum2 {
		for i := 1; i <= chooseNum2; i++ {
			cr := scores.Index(length - i).(*score)
			selected = append(selected, cr)
			logging.VLog().WithFields(logrus.Fields{
				"address": cr.address,
				"score":   cr.value,
			}).Info("Elect a Node")
			err := ps.recordElectResult(&state.VoteEvent{
				Address:    cr.election.Address,
				PledgeFund: cr.election.PledgeFund,
				Status:     "1",
				Cause:      "",
			}, height, cr.election.TxHashes)
			if err != nil {
				return nil, err
			}
		}
	}

	panels := make([]*corepb.Panel, WITNUM)
	switch len(selected) {
	case WITNUM:
		for i, score := range selected {
			panel := &corepb.Panel{}
			pledgeFund, err := core.CUintStringToNcUintBigInt(score.election.PledgeFund)
			if err != nil {
				return nil, err
			}
			panel.Leader = &corepb.Member{
				PeerId:     score.election.PeerId,
				Address:    score.election.Address,
				PledgeFund: pledgeFund.Bytes(),
			}
			panels[i] = panel
		}
	case ALLNUM:
		for i, score := range selected {
			panel := &corepb.Panel{}
			pledgeFund, err := core.CUintStringToNcUintBigInt(score.election.PledgeFund)
			if err != nil {
				return nil, err
			}
			panel.Leader = &corepb.Member{
				PeerId:     score.election.PeerId,
				Address:    score.election.Address,
				PledgeFund: pledgeFund.Bytes(),
			}

			panel.Members = make([]*corepb.Member, 3)
			for j := 0; j < 3; j++ {
				score2 := selected[i*3+WITNUM+j]
				pledgeFund2, err := core.CUintStringToNcUintBigInt(score2.election.PledgeFund)
				if err != nil {
					return nil, err
				}
				panel.Members[j] = &corepb.Member{
					PeerId:     score2.election.PeerId,
					Address:    score2.election.Address,
					PledgeFund: pledgeFund2.Bytes(),
				}
			}
			panels[i] = panel

			if i == WITNUM-1 {
				break
			}
		}
	default:
		panels = nil
	}
	return panels, nil
}

func (ps *State) recordElectResult(voteEvent *state.VoteEvent, height uint64, txHashes []string) error {
	voteData, err := json.Marshal(voteEvent)
	event := &state.Event{
		Topic: core.TopicVoteResult,
		Data:  string(voteData),
	}
	bytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	for _, hash := range txHashes {
		txHash, err := byteutils.FromHex(hash)
		key := append(txHash, byteutils.FromUint64(height)...)
		_, err = ps.eventTrie.Put(key, bytes)
		if err != nil {
			return err
		}
	}
	return nil
}

//refund pledge fund when not selected
func (ps *State) refundPledgeFund(addr string, fund string, ws state.WorldState) error {
	address, err := core.AddressParse(addr)
	if err != nil {
		return err
	}
	account, _ := ws.GetOrCreateAccount(address.Bytes())
	pledgeFund, err := core.CUintStringToNcUintBigInt(fund)
	if err != nil {
		return err
	}
	err = account.AddBalance(pledgeFund)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":     err,
			"account": account.Address(),
		}).Error("[refundPledgeFund] add balance failed")
		return err
	}
	err = account.SubPledgeFund(pledgeFund)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err":     err,
			"value":   fund,
			"account": account.Address(),
		}).Error("[refundPledgeFund] refund pledge fund failed")
		return err
	}
	return nil
}

func calcWitness(vrf []byte, panels []uint32, k uint32) uint32 {
	var v1, v2 uint32
	bIdx := k / 8
	bits1 := k % 8
	bits2 := 8 + bits1 // L - 8 + bits1
	if k >= 512 {
		return math.MaxUint32
	}

	v1 = uint32(vrf[bIdx]) >> bits1
	if bIdx+1 < uint32(len(vrf)) {
		v2 = uint32(vrf[bIdx+1])
	} else {
		v2 = uint32(vrf[0])
	}

	v2 = v2 & ((1 << bits2) - 1)
	v := (v2 << (8 - bits1)) + v1
	v = v % uint32(len(panels))
	return panels[v]
}
