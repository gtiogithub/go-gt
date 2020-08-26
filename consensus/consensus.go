package consensus

import (
	"errors"

	"gt.pro/gtio/go-gt/consensus/psec"
	"gt.pro/gtio/go-gt/core"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
)

const (
	CONSENSUS_PSEC = "psec"
)

func NewConsensus(cType string, db cdb.Storage, cfg *config.Config, chain *core.BlockChain) (core.Consensus, error) {
	if cType == "" {
		cType = CONSENSUS_PSEC
	}
	var engine core.Consensus
	var err error
	switch cType {
	case CONSENSUS_PSEC:
		engine = psec.NewPsec(db, cfg, chain)
		if engine == nil {
			err = errors.New("Failed to new psec consensus")
		}
	default:
		err = errors.New("Invalid consensus types.")
	}
	logging.CLog().Infof("ConsensusType:%s", cType)
	return engine, err
}
