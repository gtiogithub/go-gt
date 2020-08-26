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

package conf

import (
	"gt.pro/gtio/go-gt/util/config"
)

const (
	DefaultChainID       = 1
	DefaultDataDIR       = "data"
	DefaultKeyDir        = "keydir"
	DefaultBlockPoolSize = 128

	Chain = "chain"
)

type ChainConfig struct {
	ChainId       uint32 `yaml:"chain_id"`
	Datadir       string `yaml:"datadir"`
	Keydir        string `yaml:"keydir"`
	Coinbase      string `yaml:"coinbase"`
	Genesis       string `yaml:"genesis"`
	BlockPoolSize int32  `yaml:"block_pool_size"`
}

func GetChainConfig(conf *config.Config) *ChainConfig {
	chainConfig := new(ChainConfig)
	conf.GetObject(Chain, chainConfig)
	if chainConfig.ChainId <= 0 {
		chainConfig.ChainId = DefaultChainID
	}
	if chainConfig.Datadir == "" {
		chainConfig.Datadir = DefaultDataDIR
	}
	if chainConfig.Keydir == "" {
		chainConfig.Keydir = chainConfig.Datadir + "/" + DefaultKeyDir
	}
	if chainConfig.BlockPoolSize <= 0 {
		chainConfig.BlockPoolSize = DefaultBlockPoolSize
	}
	return chainConfig
}

func SetChainConfig(conf *config.Config, chainCfg *ChainConfig) {
	conf.Set(Chain, chainCfg)
}
