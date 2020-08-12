// Package towrap wraps two versions of Traffic Ops clients to give up-to-date
// information, possibly using legacy API versions.
package towrap

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/apache/trafficcontrol/lib/go-log"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_monitor/config"
	client "github.com/apache/trafficcontrol/traffic_ops/client"

	jsoniter "github.com/json-iterator/go"
)

const localHostIP = "127.0.0.1"

// ErrNilSession is the error returned by operations performed on a nil session.
var ErrNilSession = errors.New("nil session")

// ByteTime is a structure for associating a set of raw data with some CDN
// Snapshot statistics, and a certain time.
type ByteTime struct {
	bytes []byte
	time  time.Time
	stats *tc.CRConfigStats
}

// ByteMapCache is a thread-access-safe map of cache server hostnames to
// ByteTime structures.
type ByteMapCache struct {
	cache *map[string]ByteTime
	m     *sync.RWMutex
}

// NewByteMapCache constructs a new, empty ByteMapCache.
func NewByteMapCache() ByteMapCache {
	return ByteMapCache{m: &sync.RWMutex{}, cache: &map[string]ByteTime{}}
}

// Set sets the entry given by 'key' to a new ByteTime structure with the given
// raw data ('newBytes') and the given statistics ('stats') at the current time.
func (c ByteMapCache) Set(key string, newBytes []byte, stats *tc.CRConfigStats) {
	c.m.Lock()
	defer c.m.Unlock()
	(*c.cache)[key] = ByteTime{bytes: newBytes, stats: stats, time: time.Now()}
}

// Get retrieves the raw data, associated time, and statistics of the entry
// given by 'key'.
func (c ByteMapCache) Get(key string) ([]byte, time.Time, *tc.CRConfigStats) {
	c.m.RLock()
	defer c.m.RUnlock()
	if byteTime, ok := (*c.cache)[key]; !ok {
		return nil, time.Time{}, nil
	} else {
		return byteTime.bytes, byteTime.time, byteTime.stats
	}
}

func (s TrafficOpsSessionThreadsafe) BackupFileExists() bool {
	if _, err := os.Stat(s.CRConfigBackupFile); !os.IsNotExist(err) {
		if _, err = os.Stat(s.TMConfigBackupFile); !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

// CRConfigStat represents a set of statistics from a CDN Snapshot requested at
// a particular time.
type CRConfigStat struct {
	// Err contains any error that may have occurred when obtaining the
	// statistics.
	Err error `json:"error"`
	// ReqAddr is the network address from which the statistics were requested.
	ReqAddr string `json:"request_address"`
	// ReqTime is the time at which the request for statistics was made.
	ReqTime time.Time `json:"request_time"`
	// Stats contains the actual statistics.
	Stats tc.CRConfigStats `json:"stats"`
}

// CopyCRConfigStat makes a deep copy of a slice of CRConfigStats.
func CopyCRConfigStat(old []CRConfigStat) []CRConfigStat {
	newStats := make([]CRConfigStat, len(old))
	copy(newStats, old)
	return newStats
}

// CRConfigHistoryThreadsafe stores history in a circular buffer.
type CRConfigHistoryThreadsafe struct {
	hist   *[]CRConfigStat
	m      *sync.RWMutex
	limit  *uint64
	length *uint64
	pos    *uint64
}

// NewCRConfigHistoryThreadsafe constructs a new, empty
// CRConfigHistoryThreadsafe - this is the ONLY way to safely create a
// CRConfigHistoryThreadsafe, using the zero value of the structure will cause
// all operations to encounter segmentation faults, and there is no way to
// preempt this.
//
// 'limit' indicates the size of the circular buffer - effectively the number of
// entries it will be capable of storing.
func NewCRConfigHistoryThreadsafe(limit uint64) CRConfigHistoryThreadsafe {
	hist := make([]CRConfigStat, limit, limit)
	length := uint64(0)
	pos := uint64(0)
	return CRConfigHistoryThreadsafe{hist: &hist, m: &sync.RWMutex{}, limit: &limit, length: &length, pos: &pos}
}

// Add adds the given stat to the history. Does not add new additions with the
// same remote address and CRConfig Date as the previous.
func (h CRConfigHistoryThreadsafe) Add(i *CRConfigStat) {
	h.m.Lock()
	defer h.m.Unlock()

	if *h.length != 0 {
		last := (*h.hist)[(*h.pos-1)%*h.limit]
		datesEqual := (i.Stats.DateUnixSeconds == nil && last.Stats.DateUnixSeconds == nil) || (i.Stats.DateUnixSeconds != nil && last.Stats.DateUnixSeconds != nil && *i.Stats.DateUnixSeconds == *last.Stats.DateUnixSeconds)
		cdnsEqual := (i.Stats.CDNName == nil && last.Stats.CDNName == nil) || (i.Stats.CDNName != nil && last.Stats.CDNName != nil && *i.Stats.CDNName == *last.Stats.CDNName)
		reqAddrsEqual := i.ReqAddr == last.ReqAddr
		if reqAddrsEqual && datesEqual && cdnsEqual {
			return
		}
	}

	(*h.hist)[*h.pos] = *i
	*h.pos = (*h.pos + 1) % *h.limit
	if *h.length < *h.limit {
		*h.length++
	}
}

// Get retrieves the stored history of CRConfigStat entries.
func (h CRConfigHistoryThreadsafe) Get() []CRConfigStat {
	h.m.RLock()
	defer h.m.RUnlock()
	if *h.length < *h.limit {
		return CopyCRConfigStat((*h.hist)[:*h.length])
	}
	newStats := make([]CRConfigStat, *h.limit)
	copy(newStats, (*h.hist)[*h.pos:])
	copy(newStats[*h.length-*h.pos:], (*h.hist)[:*h.pos])
	return newStats
}

// Len gives the number of currently stored items in the buffer.
//
// An uninitialized buffer has zero length.
func (h CRConfigHistoryThreadsafe) Len() uint64 {
	if h.length == nil {
		return 0
	}
	return *h.length
}

// TrafficOpsSessionThreadsafe provides access to the Traffic Ops client safe
// for multiple goroutines. This fulfills the ITrafficOpsSession interface.
type TrafficOpsSessionThreadsafe struct {
	session            **client.Session // pointer-to-pointer, because we're given a pointer from the Traffic Ops package, and we don't want to copy it.
	m                  *sync.Mutex
	lastCRConfig       ByteMapCache
	crConfigHist       CRConfigHistoryThreadsafe
	CRConfigBackupFile string
	TMConfigBackupFile string
}

// NewTrafficOpsSessionThreadsafe returns a new threadsafe
// TrafficOpsSessionThreadsafe wrapping the given `Session`.
func NewTrafficOpsSessionThreadsafe(s *client.Session, histLimit uint64, cfg config.Config) TrafficOpsSessionThreadsafe {
	return TrafficOpsSessionThreadsafe{
		CRConfigBackupFile: cfg.CRConfigBackupFile,
		crConfigHist:       NewCRConfigHistoryThreadsafe(histLimit),
		lastCRConfig:       NewByteMapCache(),
		m:                  &sync.Mutex{},
		session:            &s,
		TMConfigBackupFile: cfg.TMConfigBackupFile,
	}
}

// Initialized tells whether or not the TrafficOpsSessionThreadsafe has been
// properly initialized (by calling 'Update').
func (s TrafficOpsSessionThreadsafe) Initialized() bool {
	return s.session != nil && *s.session != nil
}

// Set sets the internal Traffic Ops session. This is safe for multiple
// goroutines, being aware they will race.
func (s TrafficOpsSessionThreadsafe) Set(session *client.Session) {
	s.m.Lock()
	defer s.m.Unlock()
	*s.session = session
}

// getThreadsafeSession is used internally to get a copy of the session pointer,
// or nil if it doesn't exist. This should not be used outside
// TrafficOpsSessionThreadsafe, and never stored, because part of the purpose of
// rafficOpsSessionThreadsafe is to store a pointer to the Session pointer, so
// it can be updated by one goroutine and immediately used by another. This
// should only be called immediately before using the session, since someone
// else may update it concurrently.
func (s TrafficOpsSessionThreadsafe) get() *client.Session {
	s.m.Lock()
	defer s.m.Unlock()
	if s.session == nil || *s.session == nil {
		return nil
	}
	return *s.session
}

func (s TrafficOpsSessionThreadsafe) CRConfigHistory() []CRConfigStat {
	return s.crConfigHist.Get()
}

func (s *TrafficOpsSessionThreadsafe) CRConfigValid(crc *tc.CRConfig, cdn string) error {
	if crc.Stats.CDNName == nil {
		return errors.New("CRConfig.Stats.CDN missing")
	}
	if crc.Stats.DateUnixSeconds == nil {
		return errors.New("CRConfig.Stats.Date missing")
	}

	// Note this intentionally takes intended CDN, rather than trusting
	// crc.Stats
	lastCrc, lastCrcTime, lastCrcStats := s.lastCRConfig.Get(cdn)

	if lastCrc == nil {
		return nil
	}
	if lastCrcStats.DateUnixSeconds == nil {
		log.Warnln("TrafficOpsSessionThreadsafe.CRConfigValid returning no error, but last CRConfig Date was missing!")
		return nil
	}
	if lastCrcStats.CDNName == nil {
		log.Warnln("TrafficOpsSessionThreadsafe.CRConfigValid returning no error, but last CRConfig CDN was missing!")
		return nil
	}
	if *lastCrcStats.CDNName != *crc.Stats.CDNName {
		return errors.New("CRConfig.Stats.CDN " + *crc.Stats.CDNName + " different than last received CRConfig.Stats.CDNName " + *lastCrcStats.CDNName + " received at " + lastCrcTime.Format(time.RFC3339Nano))
	}
	if *lastCrcStats.DateUnixSeconds > *crc.Stats.DateUnixSeconds {
		return errors.New("CRConfig.Stats.Date " + strconv.FormatInt(*crc.Stats.DateUnixSeconds, 10) + " older than last received CRConfig.Stats.Date " + strconv.FormatInt(*lastCrcStats.DateUnixSeconds, 10) + " received at " + lastCrcTime.Format(time.RFC3339Nano))
	}
	return nil
}

// CRConfigRaw returns the CRConfig from the Traffic Ops. This is safe for
// multiple goroutines.
func (s TrafficOpsSessionThreadsafe) CRConfigRaw(cdn string) ([]byte, error) {

	ss := s.get()

	var remoteAddr string

	if ss == nil {
		return nil, ErrNilSession
	}

	b, reqInf, err := ss.GetCRConfig(cdn)
	if err == nil {
		remoteAddr = reqInf.RemoteAddr.String()
		ioutil.WriteFile(s.CRConfigBackupFile, b, 0644)
	} else {
		if s.BackupFileExists() {
			b, err = ioutil.ReadFile(s.CRConfigBackupFile)
			if err != nil {
				err = errors.New("file Read Error: " + err.Error())
				return nil, err
			}
			remoteAddr = localHostIP
			log.Errorln("Error getting CRConfig from traffic_ops, backup file exists, reading from file")
			err = nil
		} else {
			return nil, ErrNilSession
		}
	}

	hist := &CRConfigStat{
		Err:     err,
		ReqAddr: remoteAddr,
		ReqTime: time.Now(),
		Stats:   tc.CRConfigStats{},
	}
	defer s.crConfigHist.Add(hist)

	if err != nil {
		return b, err
	}

	crc := &tc.CRConfig{}
	json := jsoniter.ConfigFastest
	if err = json.Unmarshal(b, crc); err != nil {
		err = errors.New("invalid JSON: " + err.Error())
		hist.Err = err
		return b, err
	}
	hist.Stats = crc.Stats

	if err = s.CRConfigValid(crc, cdn); err != nil {
		err = errors.New("invalid CRConfig: " + err.Error())
		hist.Err = err
		return b, err
	}

	s.lastCRConfig.Set(cdn, b, &crc.Stats)
	return b, nil
}

// LastCRConfig returns the last CRConfig requested from CRConfigRaw, and the
// time it was returned. This is designed to be used in conjunction with a
// poller which regularly calls CRConfigRaw. If no last CRConfig exists, because
// CRConfigRaw has never been called successfully, this calls CRConfigRaw once
// to try to get the CRConfig from Traffic Ops.
func (s TrafficOpsSessionThreadsafe) LastCRConfig(cdn string) ([]byte, time.Time, error) {
	crConfig, crConfigTime, _ := s.lastCRConfig.Get(cdn)
	if crConfig == nil {
		b, err := s.CRConfigRaw(cdn)
		return b, time.Now(), err
	}
	return crConfig, crConfigTime, nil
}

// TrafficMonitorConfigMapRaw returns the Traffic Monitor config map from the
// Traffic Ops, directly from the monitoring.json endpoint. This is not usually
// what is needed, rather monitoring needs the snapshotted CRConfig data, which
// is filled in by `LegacyTrafficMonitorConfigMap`. This is safe for multiple
// goroutines.
func (s TrafficOpsSessionThreadsafe) trafficMonitorConfigMapRaw(cdn string) (*tc.TrafficMonitorConfigMap, error) {
	ss := s.get()
	if ss == nil {
		return nil, ErrNilSession
	}

	configMap, _, err := ss.GetTrafficMonitorConfigMap(cdn)

	if err == nil {
		err = configMap.Valid()
	}

	if err != nil {
		// Default error case, no backup file exists
		if !s.BackupFileExists() {
			return nil, err
		}

		b, err := ioutil.ReadFile(s.TMConfigBackupFile)
		if err != nil {
			return nil, errors.New("reading TMConfigBackupFile: " + err.Error())
		}

		log.Errorln("Error getting configMap from traffic_ops, backup file exists, reading from file")
		json := jsoniter.ConfigFastest
		if err := json.Unmarshal(b, &configMap); err != nil {
			return nil, errors.New("unmarhsalling backup file monitoring.json: " + err.Error())
		}
		return configMap, err
	}

	json := jsoniter.ConfigFastest
	data, err := json.Marshal(*configMap)
	if err == nil {
		ioutil.WriteFile(s.TMConfigBackupFile, data, 0644)
	}

	return configMap, err
}

// LegacyTrafficMonitorConfigMap returns the Traffic Monitor config map from the
// Traffic Ops. This is safe for multiple goroutines.
func (s TrafficOpsSessionThreadsafe) TrafficMonitorConfigMap(cdn string) (*tc.TrafficMonitorConfigMap, error) {
	mc, err := s.trafficMonitorConfigMapRaw(cdn)
	if err != nil {
		return nil, fmt.Errorf("getting monitor config map: %v", err)
	}

	crcData, err := s.CRConfigRaw(cdn)
	if err != nil {
		return nil, fmt.Errorf("getting CRConfig: %v", err)
	}

	crConfig := tc.CRConfig{}
	json := jsoniter.ConfigFastest
	if err := json.Unmarshal(crcData, &crConfig); err != nil {
		return nil, fmt.Errorf("unmarshalling CRConfig JSON : %v", err)
	}

	mc, err = CreateMonitorConfig(crConfig, mc)
	if err != nil {
		return nil, fmt.Errorf("creating Traffic Monitor Config: %v", err)
	}

	return mc, nil
}

// CreateMonitorConfig modifies the passed TrafficMonitorConfigMap to add the
// Traffic Monitors and Delivery Services found in a CDN Snapshot, and wipe out
// all of those that already existed in the configuration map.
func CreateMonitorConfig(crConfig tc.CRConfig, mc *tc.TrafficMonitorConfigMap) (*tc.TrafficMonitorConfigMap, error) {
	// For unknown reasons, this function used to overwrite the passed set of
	// TrafficServer objects. That was problematic, tc.CRConfig structures don't
	// contain the same amount of information about their "equivalent"
	// ContentServers.
	// TODO: This is still overwriting TM instances found in the monitoring
	// config - why? It's also doing that for Delivery Services, but that's
	// necessary until issue #3528 is resolved.

	// Dump the "live" monitoring.json monitors, and populate with the
	// "snapshotted" CRConfig
	mc.TrafficMonitor = map[string]tc.TrafficMonitor{}
	for name, mon := range crConfig.Monitors {
		// monitorProfile = *mon.Profile
		m := tc.TrafficMonitor{}
		if mon.Port != nil {
			m.Port = *mon.Port
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing Port field\n", name)
		}
		if mon.IP6 != nil {
			m.IP6 = *mon.IP6
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing IP6 field\n", name)
		}
		if mon.IP != nil {
			m.IP = *mon.IP
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing IP field\n", name)
		}
		m.HostName = name
		if mon.FQDN != nil {
			m.FQDN = *mon.FQDN
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing FQDN field\n", name)
		}
		if mon.Profile != nil {
			m.Profile = *mon.Profile
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing Profile field\n", name)
		}
		if mon.Location != nil {
			m.Location = *mon.Location
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing Location field\n", name)
		}
		if mon.ServerStatus != nil {
			m.ServerStatus = string(*mon.ServerStatus)
		} else {
			log.Warnf("Creating monitor config: CRConfig monitor %s missing ServerStatus field\n", name)
		}
		mc.TrafficMonitor[name] = m
	}

	// Dump the "live" monitoring.json DeliveryServices, and populate with the
	// "snapshotted" CRConfig but keep using the monitoring.json thresholds,
	// because they're not in the CRConfig.
	rawDeliveryServices := mc.DeliveryService
	mc.DeliveryService = map[string]tc.TMDeliveryService{}
	for name, _ := range crConfig.DeliveryServices {
		if rawDS, ok := rawDeliveryServices[name]; ok {
			// use the raw DS if it exists, because the CRConfig doesn't have
			// thresholds or statuses
			mc.DeliveryService[name] = rawDS
		} else {
			mc.DeliveryService[name] = tc.TMDeliveryService{
				XMLID:              name,
				TotalTPSThreshold:  0,
				ServerStatus:       "REPORTED",
				TotalKbpsThreshold: 0,
			}
		}
	}
	return mc, nil
}
