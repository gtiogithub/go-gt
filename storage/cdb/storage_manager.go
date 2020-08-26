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

package cdb

import (
	"errors"
	"fmt"
	"os"

	"gt.pro/gtio/go-gt/conf"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/sirupsen/logrus"
)

const (
	TypeLevelDB  = "levelDB"
	TypeBadgerDB = "badgerDB"
	database     = "database"
)

type DbConfig struct {
	DbType      string `yaml:"db_type"`
	EnableBatch bool   `yaml:"enable_batch"`
	DbDir       string `yaml:"db_dir"`
}

func GetDbConfig(config *config.Config) *DbConfig {
	dbConf := new(DbConfig)
	config.GetObject(database, dbConf)
	if dbConf != nil {
		if dbConf.DbType == "" {
			dbConf.DbType = TypeLevelDB
		}
	} else {
		dbConf = NewDefaultDbConfig()
	}
	if dbConf.DbDir == "" {
		chaincfg := conf.GetChainConfig(config)
		dbPath := chaincfg.Datadir + string(os.PathSeparator) + "chain"
		dbConf.DbDir = dbPath
	}
	return dbConf
}

func SetDbConfig(conf *config.Config, dbConfig *DbConfig) {
	conf.Set(database, dbConfig)
}

func NewDefaultDbConfig() *DbConfig {
	return &DbConfig{
		TypeLevelDB,
		false,
		"",
	}
}

func NewDB(config *config.Config) (Storage, error) {
	dbcfg := GetDbConfig(config)
	if dbcfg.DbType == TypeLevelDB {
		db, err := NewLevelDB(dbcfg, 16, 500)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"dir": dbcfg.DbDir,
				"err": err,
			}).Error("Failed to new a levelDB instance.")
			return nil, err
		}
		return db, nil
	} else if dbcfg.DbType == TypeBadgerDB {
		db, err := NewBadgerDB(dbcfg)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"dir": dbcfg.DbDir,
				"err": err,
			}).Error("Failed to new a Badger DB instance.")
			return nil, err
		}
		return db, nil
	} else {
		return nil, errors.New(fmt.Sprintf("Does not support the %s database.", dbcfg.DbType))
	}
}
