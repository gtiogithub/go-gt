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

package metrics

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"gt.pro/gtio/go-gt/conf"
	"gt.pro/gtio/go-gt/util/config"
	"gt.pro/gtio/go-gt/util/logging"
	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-metrics/exp"
)

const (
	interval = 2 * time.Second
	chainID  = "chainID"
	// MetricsEnabledFlag metrics enable flag
	MetricsEnabledFlag = "metrics"

	stats = "stats"
)

type StatsConfig struct {
	EnableMetrics bool `yaml:"enable_metrics"`
	Influxdb      Influxdb
	MetricsTags   map[string]string `yaml:"metrics_tags"`
}

type Influxdb struct {
	Host     string `yaml:"host"`
	Db       string `yaml:"db"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

func GetStatsConfig(conf *config.Config) *StatsConfig {
	statscfg := new(StatsConfig)
	conf.GetObject(stats, statscfg)

	return statscfg
}

func SetStatsConfig(conf *config.Config, statsCfg *StatsConfig) {
	conf.Set(stats, statsCfg)
}

var (
	enable = false
	quitCh chan (bool)
)

func init() {
	quitCh = make(chan bool, 1)
	for _, arg := range os.Args {
		if strings.TrimLeft(arg, "-") == MetricsEnabledFlag {
			EnableMetrics()
			return
		}
	}
}

// EnableMetrics enable the metrics service
func EnableMetrics() {
	enable = true
	exp.Exp(metrics.DefaultRegistry)
}

// Start metrics monitor
func Start(config *config.Config) {
	logging.VLog().Info("Starting Metrics...")

	go (func() {
		cfg := GetStatsConfig(config)
		if cfg.MetricsTags == nil {
			cfg.MetricsTags = make(map[string]string)
		}
		chaincfg := conf.GetChainConfig(config)
		cfg.MetricsTags[chainID] = fmt.Sprintf("%d", chaincfg.ChainId)
		go collectSystemMetrics()
		InfluxDBWithTags(metrics.DefaultRegistry, interval, cfg.Influxdb.Host, cfg.Influxdb.Db, cfg.Influxdb.User, cfg.Influxdb.Password, cfg.MetricsTags)
		logging.VLog().Info("Started Metrics.")
	})()

	logging.VLog().Info("Started Metrics.")
}

func collectSystemMetrics() {
	memstats := make([]*runtime.MemStats, 2)
	for i := 0; i < len(memstats); i++ {
		memstats[i] = new(runtime.MemStats)
	}

	allocs := metrics.GetOrRegisterMeter("system_allocs", nil)

	// totalAllocs := metrics.GetOrRegisterMeter("system_total_allocs", nil)
	sys := metrics.GetOrRegisterMeter("system_sys", nil)
	frees := metrics.GetOrRegisterMeter("system_frees", nil)
	heapInuse := metrics.GetOrRegisterMeter("system_heapInuse", nil)
	stackInuse := metrics.GetOrRegisterMeter("system_stackInuse", nil)
	releases := metrics.GetOrRegisterMeter("system_release", nil)

	for i := 1; ; i++ {
		select {
		case <-quitCh:
			return
		default:
			runtime.ReadMemStats(memstats[i%2])
			allocs.Mark(int64(memstats[i%2].Alloc - memstats[(i-1)%2].Alloc))

			sys.Mark(int64(memstats[i%2].Sys - memstats[(i-1)%2].Sys))
			frees.Mark(int64(memstats[i%2].Frees - memstats[(i-1)%2].Frees))
			heapInuse.Mark(int64(memstats[i%2].HeapInuse - memstats[(i-1)%2].HeapInuse))
			stackInuse.Mark(int64(memstats[i%2].StackInuse - memstats[(i-1)%2].StackInuse))
			releases.Mark(int64(memstats[i%2].HeapReleased - memstats[(i-1)%2].HeapReleased))

			time.Sleep(2 * time.Second)
		}
	}

}

// Stop metrics monitor
func Stop() {
	logging.VLog().Info("Stopping Metrics...")

	quitCh <- true
}

// NewCounter create a new metrics Counter
func NewCounter(name string) metrics.Counter {
	if !enable {
		return new(metrics.NilCounter)
	}
	return metrics.GetOrRegisterCounter(name, metrics.DefaultRegistry)
}

// NewMeter create a new metrics Meter
func NewMeter(name string) metrics.Meter {
	if !enable {
		return new(metrics.NilMeter)
	}
	return metrics.GetOrRegisterMeter(name, metrics.DefaultRegistry)
}

// NewTimer create a new metrics Timer
func NewTimer(name string) metrics.Timer {
	if !enable {
		return new(metrics.NilTimer)
	}
	return metrics.GetOrRegisterTimer(name, metrics.DefaultRegistry)
}

// NewGauge create a new metrics Gauge
func NewGauge(name string) metrics.Gauge {
	if !enable {
		return new(metrics.NilGauge)
	}
	return metrics.GetOrRegisterGauge(name, metrics.DefaultRegistry)
}

// NewHistogramWithUniformSample create a new metrics History with Uniform Sample algorithm.
func NewHistogramWithUniformSample(name string, reservoirSize int) metrics.Histogram {
	if !enable {
		return new(metrics.NilHistogram)
	}
	return metrics.GetOrRegisterHistogram(name, nil, metrics.NewUniformSample(reservoirSize))
}
