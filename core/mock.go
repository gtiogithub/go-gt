package core

import (
	"gt.pro/gtio/go-gt/network"
	"gt.pro/gtio/go-gt/storage/cdb"
	"gt.pro/gtio/go-gt/util/config"
)

type MockGt struct {
	config     *config.Config
	chain      *BlockChain
	netService network.Service
	am         AccountManager
	genesis    *Genesis
	storage    cdb.Storage
	consensus  Consensus
	emitter    *EventEmitter
	cvm        CVM
}

func (n *MockGt) Genesis() *Genesis {
	return n.genesis
}

func (n *MockGt) BlockChain() *BlockChain {
	return n.chain
}
func (n *MockGt) NetService() network.Service {
	return n.netService
}
func (n *MockGt) AccountManager() AccountManager {
	return n.am
}
func (n *MockGt) Consensus() Consensus {
	return n.consensus
}
func (n *MockGt) Config() *config.Config {
	return n.config
}
func (n *MockGt) Storage() cdb.Storage {
	return n.storage
}
func (n *MockGt) Cvm() CVM {
	return n.cvm
}
func (n *MockGt) Stop() {

}

func (n *MockGt) EventEmitter() *EventEmitter {
	return n.emitter
}

type MockNetService struct{}

func (n MockNetService) Start() error                                  { return nil }
func (n MockNetService) Stop()                                         {}
func (n MockNetService) Node() *network.Node                           { return nil }
func (n MockNetService) Register(...*network.Subscriber)               {}
func (n MockNetService) Deregister(...*network.Subscriber)             {}
func (n MockNetService) Broadcast(string, network.Serializable, int)   {}
func (n MockNetService) Relay(string, network.Serializable, int)       {}
func (n MockNetService) SendMessage(string, []byte, string, int) error { return nil }
func (n MockNetService) SendMessageToPeers(messageName string, data []byte, priority int, filter network.PeerFilterAlgorithm) []string {
	return nil
}
func (n MockNetService) SendMessageToPeer(messageName string, data []byte, priority int, peerID string) error {
	return nil
}
func (n MockNetService) SendMessageToPeerOrBroadcast(messageName string, messageContent network.Serializable, priority int, peerID string) error {
	return nil
}
func (n MockNetService) ClosePeer(peerID string, reason error) {}
func (n MockNetService) AddPeer(peerID string)                 {}

// MockGenesisConf return mock genesis conf
func MockGenesisConf() *Genesis {
	config := &Genesis{
		ChainId:    23,
		SuperNodes: make([]*TokenDistribution, 0),
		Funds:      make([]*TokenDistribution, 0),
	}
	config.Funds = append(config.Funds, &TokenDistribution{
		Address: "C111EH4eWSoyedthp96FmGmbGK85SwzaU7UDR",
		Value:   "12740000000000000",
	})
	config.Funds = append(config.Funds, &TokenDistribution{
		Address: "C111ESWEjtXGzb5z7gmtphrTqCaQVUVpJdfsT",
		Value:   "9100000000000000",
	})
	config.Funds = append(config.Funds, &TokenDistribution{
		Address: "C111Fz5hiDDgZ4mJZB9BxT72ffFjUCduBPbZq",
		Value:   "9100000000000000",
	})
	config.Funds = append(config.Funds, &TokenDistribution{
		Address: "C111BDqzbRby2sWSKLva75hhpybWRbfHN1VNw",
		Value:   "9100000000000000",
	})
	config.Funds = append(config.Funds, &TokenDistribution{
		Address: "C111FgcZN2D6w6KHMrghidRQrL1umQ6Q7n7om",
		Value:   "4550000000000000",
	})
	return config
}

func NewMockGt(am AccountManager, consensus Consensus, cvm CVM, eventEmitter *EventEmitter,
	db cdb.Storage, config *config.Config, chain *BlockChain, ns network.Service) *MockGt {

	gt := &MockGt{
		genesis:    MockGenesisConf(),
		config:     config,
		storage:    db,
		emitter:    eventEmitter,
		am:         am,
		netService: ns,
		cvm:        cvm,
	}

	chain.BlockPool().RegisterInNetwork(gt.netService)
	gt.chain = chain
	chain.genesis = gt.genesis
	chain.consensus = consensus
	gt.consensus = consensus
	return gt
}
