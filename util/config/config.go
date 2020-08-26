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

package config

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

const (
	DefaultConfigPath = "conf/conf.yaml"
)

var _config *Config

type Config struct {
	data     []byte
	cache    map[string]interface{}
	filePath string
	mu       sync.Mutex
}

type conf struct {
	Network struct {
		Seed                 []string `yaml:"seed"`
		Listen               []string `yaml:"listen"`
		PrivateKey           string   `yaml:"private_key"`
		NetworkId            int      `yaml:"network_id"`
		StreamLimits         int      `yaml:"stream_limits"`
		ReservedStreamLimits int      `yaml:"reserved_stream_limits"`
	}
	Chain struct {
		ChainId  int    `yaml:"chain_id"`
		Coinbase string `yaml:"coinbase"`
		Genesis  string `yaml:"genesis"`
	}
	Log struct {
		LogLevel        string `yaml:"log_level"`
		LogFile         string `yaml:"log_file"`
		LogRotationTime int    `yaml:"log_rotationTime"`
		LogAge          int    `yaml:"log_age"`
	}
	Rpc struct {
		RpcListen  []string `yaml:"rpc_listen"`
		HttpListen []string `yaml:"http_listen"`
		HttpModule []string `yaml:"http_module"`
		HttpCors   []string `yaml:"http_cors"`
		HttpLimits uint32   `yaml:"http_limits"`
	}
	Stats struct {
		EnableMetrics bool `yaml:"enable_metrics"`
		InfluxDB      struct {
			Host     string `yaml:"host"`
			DB       string `yaml:"db"`
			User     string `yaml:"user"`
			Password string `yaml:"password"`
		}
	}
	Monitor struct {
		Pprof struct {
			HttpListen string `yaml:"http_listen"`
			CpuProfile string `yaml:"cpuprofile"`
			MemProfile string `yaml:"memprofile"`
		}
	}

	DFS struct {
		HdfsPrefix []string `yaml:"hdfs_prefix"`
	}
}

func InitConfig(fileName string) (*Config, error) {
	if _config != nil {
		return _config, nil
	}
	if fileName == "" {
		fileName = DefaultConfigPath
	}

	if _, err := os.Stat(fileName); err != nil { // default conf not exist
		_config, err = NewDefaultFileConfig(fileName)
		if err != nil {
			return nil, err
		}
	} else {
		_config, err = NewFileConfig(fileName)
		if err != nil {
			return nil, err
		}
	}
	return _config, nil
}

func Get(key string) interface{} {
	conf, err := InitConfig("")
	if err == nil {
		return conf.Get(key)
	}
	return nil
}

func GetInt(key string) int {
	conf, err := InitConfig("")
	if err == nil {
		return conf.GetInt(key)
	}
	return 0
}

func GetString(key string) string {
	conf, err := InitConfig("")
	if err == nil {
		return conf.GetString(key)
	}
	return ""
}

func NewDefaultFileConfig(fileName string) (*Config, error) {
	c := make(map[interface{}]interface{})
	cfg := conf{}

	cfg.Network.Seed = append(cfg.Network.Seed, "/ip4/127.0.0.1/tcp/8880/ipfs/12D3KooWSuivaexv9gTrtzzDQMUbAemqnuseEu9CJXmJgV8fAAws")
	cfg.Network.Listen = append(cfg.Network.Listen, "0.0.0.0:8880")
	cfg.Network.PrivateKey = "conf/network/key"
	cfg.Network.NetworkId = 1

	cfg.Chain.ChainId = 23
	cfg.Chain.Genesis = "conf/genesis.yaml"

	cfg.Log.LogLevel = "debug"
	cfg.Log.LogFile = "logs"
	cfg.Log.LogRotationTime = 3600
	cfg.Log.LogAge = 86400

	cfg.Rpc.RpcListen = []string{"127.0.0.1:8518"}
	cfg.Rpc.HttpListen = []string{"127.0.0.1:8519"}
	cfg.Rpc.HttpModule = append(cfg.Rpc.HttpModule, "admin")
	cfg.Rpc.HttpModule = append(cfg.Rpc.HttpModule, "api")
	cfg.Rpc.HttpCors = []string{"*"}
	cfg.Rpc.HttpLimits = 128

	cfg.Stats.EnableMetrics = false
	cfg.Stats.InfluxDB.Host = "http://192.168.21.8:8096"
	cfg.Stats.InfluxDB.DB = "gt"
	cfg.Stats.InfluxDB.User = "admin"
	cfg.Stats.InfluxDB.Password = "admin"

	cfg.Monitor.Pprof.HttpListen = "0.0.0.0:8888"
	cfg.Monitor.Pprof.CpuProfile = "cpuprofile.tmp"
	cfg.Monitor.Pprof.MemProfile = "memprofile.tmp"

	c["network"] = cfg.Network
	c["chain"] = cfg.Chain
	c["log"] = cfg.Log
	c["rpc"] = cfg.Rpc
	c["stats"] = cfg.Stats
	c["monitor"] = cfg.Monitor
	c["dfs"] = cfg.DFS

	data, err := yaml.Marshal(&c)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	config := new(Config)
	config.filePath = fileName
	config.data = data
	config.cache = make(map[string]interface{})
	return config, nil
}

func NewFileConfig(fileName string) (*Config, error) {
	if fileName == "" {
		return nil, errors.New("filename is empty path")
	}
	in, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic("Failed to read the config file:" + fileName + ". err:" + err.Error())
	}
	if len(in) == 0 {
		panic("the " + fileName + " content is empty")
	}
	config := new(Config)
	config.filePath = fileName
	config.data = in
	config.cache = make(map[string]interface{})
	return config, nil
}

func NewMemConfig() (*Config, error) {
	c := make(map[string]interface{})
	cfg := conf{}

	cfg.Network.Seed = append(cfg.Network.Seed, "/ip4/127.0.0.1/tcp/8880/ipfs/12D3KooWSuivaexv9gTrtzzDQMUbAemqnuseEu9CJXmJgV8fAAws")
	cfg.Network.Listen = append(cfg.Network.Listen, "0.0.0.0:8880")
	cfg.Network.PrivateKey = "conf/network/key"
	cfg.Network.NetworkId = 1

	cfg.Chain.ChainId = 23
	cfg.Chain.Genesis = "conf/genesis.yaml"

	cfg.Log.LogLevel = "debug"
	cfg.Log.LogFile = "logs"
	cfg.Log.LogRotationTime = 3600
	cfg.Log.LogAge = 86400

	cfg.Rpc.RpcListen = []string{"127.0.0.1:8518"}
	cfg.Rpc.HttpListen = []string{"127.0.0.1:8519"}
	cfg.Rpc.HttpModule = append(cfg.Rpc.HttpModule, "admin")
	cfg.Rpc.HttpModule = append(cfg.Rpc.HttpModule, "api")
	cfg.Rpc.HttpCors = []string{"*"}
	cfg.Rpc.HttpLimits = 128

	cfg.Stats.EnableMetrics = false
	cfg.Stats.InfluxDB.Host = "http://192.168.21.8:8096"
	cfg.Stats.InfluxDB.DB = "gt"
	cfg.Stats.InfluxDB.User = "admin"
	cfg.Stats.InfluxDB.Password = "admin"

	cfg.Monitor.Pprof.HttpListen = "0.0.0.0:8888"
	cfg.Monitor.Pprof.CpuProfile = "cpuprofile.tmp"
	cfg.Monitor.Pprof.MemProfile = "memprofile.tmp"

	c["network"] = cfg.Network
	c["chain"] = cfg.Chain
	c["log"] = cfg.Log
	c["rpc"] = cfg.Rpc
	c["stats"] = cfg.Stats
	c["monitor"] = cfg.Monitor
	c["dfs"] = cfg.DFS

	data, err := yaml.Marshal(&c)
	if err != nil {
		log.Fatal(err)
	}

	config := new(Config)
	config.filePath = ""
	config.data = data
	config.cache = make(map[string]interface{})
	return config, nil
}

func (c *Config) GetString(key string) string {
	v := c.Get(key)
	if v != nil && reflect.TypeOf(v).Kind() == reflect.String {
		return v.(string)
	}
	return ""
}

func (c *Config) GetInt(key string) int {
	v := c.Get(key)
	if v != nil && reflect.TypeOf(v).Kind() == reflect.Int {
		return v.(int)
	}
	return 0
}

func (c *Config) Get(key string) interface{} {
	for keyName, _ := range c.cache {
		if keyName == key {
			return c.cache[key]
		}
	}

	keys := strings.Split(key, "/")
	if len(keys) == 0 {
		return nil
	}

	m := make(map[interface{}]interface{})
	err := yaml.Unmarshal(c.data, m)
	if err != nil {
		return nil
	}
	for i := 0; i < len(keys); i++ {
		if m[keys[i]] != nil {
			if i < len(keys)-1 {
				if reflect.TypeOf(m[keys[i]]).Kind() == reflect.Map {
					m = (m[keys[i]]).(map[interface{}]interface{})
				} else {
					return nil
				}
			} else {
				v := m[keys[len(keys)-1]]
				c.cache[key] = v
				return v
			}
		} else {
			return nil
		}
	}
	return nil
}

func (c *Config) GetObject(key string, destObj interface{}) interface{} {
	keys := strings.Split(key, "/")
	if len(keys) == 0 {
		return nil
	}

	m := make(map[interface{}]interface{})
	err := yaml.Unmarshal(c.data, m)
	if err != nil {
		return nil
	}
	for i := 0; i < len(keys); i++ {
		if m[keys[i]] != nil {
			if i < len(keys)-1 {
				if reflect.TypeOf(m[keys[i]]).Kind() == reflect.Map {
					m = (m[keys[i]]).(map[interface{}]interface{})
				} else {
					return nil
				}
			} else {
				out, err := yaml.Marshal(m[keys[i]])
				if err == nil {
					err = yaml.Unmarshal(out, destObj)
					if err != nil {
						log.Println(err)
					}
					return destObj
				}
			}
		} else {
			return nil
		}
	}
	return nil
}

func (c *Config) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := strings.Split(key, "/")
	if len(keys) == 0 {
		return
	}
	m := make(map[interface{}]interface{})
	err := yaml.Unmarshal(c.data, m)
	if err != nil {
		return
	}
	tempMap := m
	for i := 0; i < len(keys); i++ {
		if i == len(keys)-1 {
			tempMap[keys[i]] = value
		} else {
			if tempMap[keys[i]] == nil {
				tempMap[keys[i]] = make(map[interface{}]interface{})
			}
			tempMap = (tempMap[keys[i]]).(map[interface{}]interface{})
		}
	}
	tempData, err := yaml.Marshal(m)
	if err == nil {
		c.data = tempData
	}
}
