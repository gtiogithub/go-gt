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

package dfs

import "gt.pro/gtio/go-gt/util/config"

const (
	DFS = "dfs"
)

type DFSConfig struct {
	HdfsPrefix []string `yaml:"hdfs_prefix"`
}

func GetDfsConfig(config *config.Config) *DFSConfig {
	rpcConfig := new(DFSConfig)
	config.GetObject(DFS, rpcConfig)
	return rpcConfig
}

func SetDfsConfig(config *config.Config, dfsConfig *DFSConfig) {
	config.Set(DFS, dfsConfig)
}
