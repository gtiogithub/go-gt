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

package main

import (
	"github.com/sirupsen/logrus"
	"gt.pro/gtio/go-gt/gt"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
	"os"
)

func main() {
	strings := os.Args
	configPath := ""
	if len(strings) == 2 {
		configPath = strings[1]
	}
	gtConf, err := config.InitConfig(configPath)
	gt, err := gt.NewGt(gtConf)
	// init log.
	logConf := logging.GetLogConfig(gtConf)
	logging.Init(logConf.LogFile, logConf.LogLevel, logConf.LogRotationTime, logConf.LogAge)

	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to new Gt.")
		return
	}
	gt.Setup()
	gt.Run()
}
