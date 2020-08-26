package psec

import (
	consensuspb "gt.pro/gtio/go-gt/consensus/pb"
	"gt.pro/gtio/go-gt/core"
	corepb "gt.pro/gtio/go-gt/core/pb"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/trie"
	"github.com/gogo/protobuf/proto"
)

type Council struct {
	chainId          uint32
	council          *corepb.Council
	phaseNum         uint32
	participatorTrie *trie.Trie
	minerTrie        *trie.Trie
	heightTrie       *trie.Trie
	storage          cdb.Storage
}

func (c *Council) ToBytes() ([]byte, error) {
	content, err := proto.Marshal(c.council)
	if err != nil {
		return nil, err
	}
	councilRoot := &consensuspb.CouncilRoot{
		PhaseNum:         c.phaseNum,
		ParticipatorRoot: c.participatorTrie.RootHash(),
		MinerRoot:        c.minerTrie.RootHash(),
		HeightRoot:       c.heightTrie.RootHash(),
		Content:          content[:],
	}
	return proto.Marshal(councilRoot)
}

func (c *Council) FromBytes(bytes []byte, storage cdb.Storage, needChangeLog bool) error {
	var err error

	pbCouncilRoot := &consensuspb.CouncilRoot{}
	if err = proto.Unmarshal(bytes, pbCouncilRoot); err != nil {
		return err
	}

	pbCouncil := &corepb.Council{}
	if err = proto.Unmarshal(pbCouncilRoot.Content, pbCouncil); err != nil {
		return err
	}
	c.phaseNum = pbCouncilRoot.PhaseNum
	c.chainId = pbCouncil.Meta.ChainId
	c.storage = storage
	c.council = pbCouncil
	participatorTrie, err := trie.NewTrie(pbCouncilRoot.ParticipatorRoot, storage, needChangeLog)
	if err != nil {
		return err
	}
	c.participatorTrie = participatorTrie

	minerTrie, err := trie.NewTrie(pbCouncilRoot.MinerRoot, storage, needChangeLog)
	if err != nil {
		return err
	}
	c.minerTrie = minerTrie

	heightTrie, err := trie.NewTrie(pbCouncilRoot.HeightRoot, storage, needChangeLog)
	if err != nil {
		return err
	}
	c.heightTrie = heightTrie

	return nil
}

// Replay a Council
func (c *Council) Replay(done *Council) error {

	if _, err := c.participatorTrie.Replay(done.participatorTrie); err != nil {
		return err
	}
	if _, err := c.minerTrie.Replay(done.minerTrie); err != nil {
		return err
	}
	if _, err := c.heightTrie.Replay(done.heightTrie); err != nil {
		return err
	}
	return nil
}

func (c *Council) Clone() (*Council, error) {
	participatorTrie, err := c.participatorTrie.Clone()
	if err != nil {
		return nil, err
	}

	minerTrie, err := c.minerTrie.Clone()
	if err != nil {
		return nil, err
	}
	heightTrie, err := c.heightTrie.Clone()
	if err != nil {
		return nil, err
	}

	bytePbCouncil, err := proto.Marshal(c.council)
	if err != nil {
		return nil, err
	}
	council := new(corepb.Council)
	if err := proto.Unmarshal(bytePbCouncil, council); err != nil {
		return nil, err
	}
	return &Council{
		chainId:          c.chainId,
		phaseNum:         c.phaseNum,
		council:          council,
		participatorTrie: participatorTrie,
		minerTrie:        minerTrie,
		heightTrie:       heightTrie,
		storage:          c.storage,
	}, nil
}

func (c *Council) isWitness(miner string) bool {
	panels := c.council.Panels
	if panels == nil || len(panels) == 0 {
		return false
	}
	flag := false
	for _, panel := range panels {
		if panel.Leader.Address == miner {
			flag = true
			break
		}
	}
	return flag
}
func NewCouncil(chain *core.BlockChain, timestamp int64, needChangeLog bool) (*Council, error) {
	storage := chain.Storage()
	participatorTrie, err := trie.NewTrie(nil, storage, needChangeLog)
	if err != nil {
		return nil, err
	}

	minerTrie, err := trie.NewTrie(nil, storage, needChangeLog)
	if err != nil {
		return nil, err
	}

	heightTrie, err := trie.NewTrie(nil, storage, needChangeLog)
	if err != nil {
		return nil, err
	}

	council := &corepb.Council{
		Meta: &corepb.CouncilMeta{
			ChainId:           chain.ChainId(),
			TermId:            1,
			Timestamp:         timestamp,
			TenureStartHeight: 1,
			TenureEndHeight:   2,
			Config:            core.NewNormalSysConfig(),
		},
		Panels: make([]*corepb.Panel, 0),
		State: &corepb.PeriodState{
			NormalTxCnt:     0,
			ContractTxCnt:   0,
			ParticipatorCnt: 0,
		},
	}

	return &Council{
		chainId:          chain.ChainId(),
		phaseNum:         1,
		council:          council,
		participatorTrie: participatorTrie,
		minerTrie:        minerTrie,
		heightTrie:       heightTrie,
		storage:          storage,
	}, nil
}
