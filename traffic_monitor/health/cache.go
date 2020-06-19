package health

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
	"fmt"
	"time"

	"github.com/apache/trafficcontrol/lib/go-log"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/lib/go-util"
	"github.com/apache/trafficcontrol/traffic_monitor/cache"
	"github.com/apache/trafficcontrol/traffic_monitor/config"
	"github.com/apache/trafficcontrol/traffic_monitor/peer"
	"github.com/apache/trafficcontrol/traffic_monitor/threadsafe"
	"github.com/apache/trafficcontrol/traffic_monitor/todata"
)

// GetVitals Gets the vitals to decide health on in the right format
func GetVitals(newResult *cache.Result, prevResult *cache.Result, mc *tc.TrafficMonitorConfigMap) {
	if newResult.Error != nil {
		log.Errorf("cache_health.GetVitals() called with an errored Result!")
		return
	}

	if newResult.InterfaceVitals == nil {
		newResult.InterfaceVitals = map[string]cache.Vitals{}
	}

	// proc.loadavg -- we're using the 1 minute average (!?)
	newResult.Vitals.LoadAvg = newResult.Statistics.Loadavg.One

	for ifaceName, iface := range newResult.Interfaces() {
		ifaceVitals := cache.Vitals{
			BytesIn:    iface.BytesIn,
			BytesOut:   iface.BytesOut,
			MaxKbpsOut: iface.Speed * 1000,
		}

		if prevResult != nil && prevResult.InterfaceVitals != nil && prevResult.InterfaceVitals[ifaceName].BytesOut != 0 {
			elapsedTimeInSecs := float64(newResult.Time.UnixNano()-prevResult.Time.UnixNano()) / 1000000000
			ifaceVitals.KbpsOut = int64(float64((ifaceVitals.BytesOut-prevResult.InterfaceVitals[ifaceName].BytesOut)*8/1000) / elapsedTimeInSecs)
		}
		newResult.InterfaceVitals[ifaceName] = ifaceVitals

		// Overflow possible
		newResult.Vitals.BytesOut += iface.BytesOut
		newResult.Vitals.BytesIn += iface.BytesIn
		// TODO JvD: Should we really be running this code every second for every cache polled????? I don't think so.
		newResult.Vitals.MaxKbpsOut += iface.Speed * 1000
	}

	if prevResult != nil && prevResult.Vitals.BytesOut != 0 {
		elapsedTimeInSecs := float64(newResult.Time.UnixNano()-prevResult.Time.UnixNano()) / 1000000000
		newResult.Vitals.KbpsOut = int64(float64((newResult.Vitals.BytesOut-prevResult.Vitals.BytesOut)*8/1000) / elapsedTimeInSecs)
	}

}

func EvalCacheWithStatusInfo(result cache.ResultInfo, mc *tc.TrafficMonitorConfigMap, status tc.CacheStatus, serverInfo tc.TrafficServer) (bool, string, string) {
	availability := AvailableStr
	if !result.Available {
		availability = UnavailableStr
	}
	switch {
	case status == tc.CacheStatusInvalid:
		log.Errorf("Cache %v got invalid status from Traffic Ops '%v' - treating as OFFLINE\n", result.ID, serverInfo.ServerStatus)
		return false, eventDesc(status, availability+"; invalid status"), ""
	case status == tc.CacheStatusAdminDown:
		return false, eventDesc(status, availability), ""
	case status == tc.CacheStatusOffline:
		log.Errorf("Cache %v set to offline, but still polled\n", result.ID)
		return false, eventDesc(status, availability), ""
	case status == tc.CacheStatusOnline:
		return true, eventDesc(status, availability), ""
	case result.Error != nil:
		return false, eventDesc(status, fmt.Sprintf("%v", result.Error)), ""
	case result.Statistics.NotAvailable == true:
		return false, eventDesc(status, fmt.Sprintf("system.notAvailable == %v", result.Statistics.NotAvailable)), ""
	}
	return result.Available, eventDesc(status, availability), ""
}

const AvailableStr = "available"
const UnavailableStr = "unavailable"

// EvalCache returns whether the given cache should be marked available, a boolean of whether the result was over ipv4 (false means it was ipv6), a string describing why, and which stat exceeded a threshold. The `stats` may be nil, for pollers which don't poll stats.
// The availability of EvalCache MAY NOT be used to directly set the cache's local availability, because the threshold stats may not be part of the poller which produced the result. Rather, if the cache was previously unavailable from a threshold, it must be verified that threshold stat is in the results before setting the cache to available.
// The resultStats may be nil, and if so, won't be checked for thresholds. For example, the Health poller doesn't have Stats.
// TODO change to return a `cache.AvailableStatus`
func EvalCache(result cache.ResultInfo, resultStats *threadsafe.ResultStatValHistory, mc *tc.TrafficMonitorConfigMap, interfaceName string) (bool, bool, string, string) {
	serverInfo, ok := mc.TrafficServer[string(result.ID)]
	if !ok {
		log.Errorf("Cache %v missing from from Traffic Ops Monitor Config - treating as OFFLINE\n", result.ID)
		return false, result.UsingIPv4, "ERROR - server missing in Traffic Ops monitor config", ""
	}
	status := tc.CacheStatusFromString(serverInfo.ServerStatus)
	if status == tc.CacheStatusOnline {
		// return here first, even though EvalCacheWithStatus checks online, because we later assume that if EvalCacheWithStatus returns true, to return false if thresholds are exceeded; but, if the cache is ONLINE, we don't want to check thresholds.
		return true, result.UsingIPv4, eventDesc(status, AvailableStr), ""
	}

	serverProfile, ok := mc.Profile[serverInfo.Profile]
	if !ok {
		log.Errorf("Cache %v profile %v missing from from Traffic Ops Monitor Config - treating as OFFLINE\n", result.ID, serverInfo.Profile)
		return false, result.UsingIPv4, "ERROR - server profile missing in Traffic Ops monitor config", ""
	}

	avail, eventDescVal, eventMsg := EvalCacheWithStatusInfo(result, mc, status, serverInfo)
	if !avail {
		return avail, result.UsingIPv4, eventDescVal, eventMsg
	}

	computedStats := cache.ComputedStats()

	for stat, threshold := range serverProfile.Parameters.Thresholds {
		resultStat := interface{}(nil)
		if computedStatF, ok := computedStats[stat]; ok {
			dummyCombinedstate := tc.IsAvailable{} // the only stats which use combinedState are things like isAvailable, which don't make sense to ever be thresholds.
			resultStat = computedStatF(result, serverInfo, serverProfile, dummyCombinedstate, interfaceName)
		} else {
			if resultStats == nil {
				continue
			}
			resultStatHistory := resultStats.Load(stat)
			if len(resultStatHistory) == 0 {
				continue
			}
			resultStat = resultStatHistory[0].Val
		}

		resultStatNum, ok := util.ToNumeric(resultStat)
		if !ok {
			log.Errorf("health.EvalCache threshold stat %s was not a number: %v", stat, resultStat)
			continue
		}

		if !inThreshold(threshold, resultStatNum) {
			return false, result.UsingIPv4, eventDesc(status, exceedsThresholdMsg(stat, threshold, resultStatNum)), stat
		}
	}

	return avail, result.UsingIPv4, eventDescVal, eventMsg
}

func EvalAggregate(result cache.ResultInfo, resultStats *threadsafe.ResultStatValHistory, mc *tc.TrafficMonitorConfigMap) (bool, bool, string, string) {
	serverInfo, ok := mc.TrafficServer[string(result.ID)]
	if !ok {
		log.Errorf("Cache %v missing from from Traffic Ops Monitor Config - treating as OFFLINE\n", result.ID)
		return false, result.UsingIPv4, "ERROR - server missing in Traffic Ops monitor config", ""
	}
	status := tc.CacheStatusFromString(serverInfo.ServerStatus)
	if status == tc.CacheStatusOnline {
		// return here first, even though EvalCacheWithStatus checks online, because we later assume that if EvalCacheWithStatus returns true, to return false if thresholds are exceeded; but, if the cache is ONLINE, we don't want to check thresholds.
		return true, result.UsingIPv4, eventDesc(status, AvailableStr), ""
	}

	serverProfile, ok := mc.Profile[serverInfo.Profile]
	if !ok {
		log.Errorf("Cache %v profile %v missing from from Traffic Ops Monitor Config - treating as OFFLINE\n", result.ID, serverInfo.Profile)
		return false, result.UsingIPv4, "ERROR - server profile missing in Traffic Ops monitor config", ""
	}

	avail, eventDescVal, eventMsg := EvalCacheWithStatusInfo(result, mc, status, serverInfo)
	if !avail {
		return avail, result.UsingIPv4, eventDescVal, eventMsg
	}

	computedAggregateStats := cache.ComputedAggregateStats()

	for stat, threshold := range serverProfile.Parameters.AggregateThresholds {
		resultStat := interface{}(nil)
		if computedStatF, ok := computedAggregateStats[stat]; ok {
			resultStat = computedStatF(result)
		} else {
			if resultStats == nil {
				continue
			}
			resultStatHistory := resultStats.Load(stat)
			if len(resultStatHistory) == 0 {
				continue
			}
			resultStat = resultStatHistory[0].Val
		}

		resultStatNum, ok := util.ToNumeric(resultStat)
		if !ok {
			log.Errorf("health.EvalCache threshold stat %s was not a number: %v", stat, resultStat)
			continue
		}

		if !inThreshold(threshold, resultStatNum) {
			return false, result.UsingIPv4, eventDesc(status, exceedsThresholdMsg(stat, threshold, resultStatNum)), stat
		}
	}

	return avail, result.UsingIPv4, eventDescVal, eventMsg
}

// CalcAvailability calculates the availability of each cache in results.
// statResultHistory may be nil, in which case stats won't be used to calculate availability.
func CalcAvailability(results []cache.Result, pollerName string, statResultHistory *threadsafe.ResultStatHistory, mc tc.TrafficMonitorConfigMap, toData todata.TOData, localCacheStatusThreadsafe threadsafe.CacheAvailableStatus, localStates peer.CRStatesThreadsafe, events ThreadsafeEvents, protocol config.PollingProtocol) {
	localCacheStatuses := localCacheStatusThreadsafe.Get().Copy()
	statResults := (*threadsafe.ResultStatValHistory)(nil)
	statResultsVal := (*map[string]threadsafe.ResultStatValHistory)(nil)
	processAvailableTuple := func(tuple cache.AvailableTuple, serverInfo tc.TrafficServer) bool {
		switch protocol {
		case config.IPv4Only:
			return tuple.IPv4
		case config.IPv6Only:
			return tuple.IPv6
		case config.Both:
			// only report availability based on defined IP addresses
			if serverInfo.IP == "" {
				return tuple.IPv6
			} else if serverInfo.IP6 == "" {
				return tuple.IPv4
			}
			// if both IP addresses are defined then report availability based on both
			return tuple.IPv4 || tuple.IPv6
		default:
			log.Errorln("received an unknown PollingProtocol: " + protocol.String())
		}
		return false
	}

	for _, result := range results {
		if statResultHistory != nil {
			t := statResultHistory.LoadOrStore(tc.CacheName(result.ID))
			statResultsVal = &t
		}
		serverInfo, ok := mc.TrafficServer[result.ID]
		if !ok {
			log.Errorf("Cache %v missing from from Traffic Ops Monitor Config - treating as OFFLINE\n", result.ID)
		}

		resultInfo := cache.ToInfo(result)
		for interfaceName, _ := range result.Interfaces() {
			if statResultsVal != nil {
				t := (*statResultsVal)[interfaceName]
				statResults = &t
			}
			isAvailable, usingIPv4, whyAvailable, unavailableStat := EvalCache(resultInfo, statResults, &mc, interfaceName)

			// if the cache is now Available, and was previously unavailable due to a threshold, make sure this poller contains the stat which exceeded the threshold.
			previousStatus, hasPreviousStatus := localCacheStatuses[tc.CacheName(result.ID)][interfaceName]
			availableTuple := cache.AvailableTuple{}

			if hasPreviousStatus {
				availableTuple = previousStatus.Available
				availableTuple.SetAvailability(usingIPv4, isAvailable)

				if processAvailableTuple(availableTuple, serverInfo) {
					if !processAvailableTuple(previousStatus.Available, serverInfo) && previousStatus.UnavailableStat != "" {
						if !result.HasStat(previousStatus.UnavailableStat) {
							return
						}
					}
				}
			} else {
				availableTuple.SetAvailability(usingIPv4, isAvailable)
			}

			// update availableTuple so TM UI is updated if one IP is removed
			if availableTuple.IPv4 && serverInfo.IP == "" {
				availableTuple.IPv4 = false
			}
			if availableTuple.IPv6 && serverInfo.IP6 == "" {
				availableTuple.IPv6 = false
			}

			newAvailableState := processAvailableTuple(availableTuple, serverInfo)

			if _, ok := localCacheStatuses[tc.CacheName(result.ID)]; !ok {
				localCacheStatuses[tc.CacheName(result.ID)] = make(map[string]cache.AvailableStatus)
			}

			localCacheStatuses[tc.CacheName(result.ID)][interfaceName] = cache.AvailableStatus{
				Available:          availableTuple,
				ProcessedAvailable: newAvailableState,
				Status:             mc.TrafficServer[string(result.ID)].ServerStatus,
				Why:                whyAvailable,
				UnavailableStat:    unavailableStat,
				Poller:             pollerName,
				LastCheckedIPv4:    usingIPv4,
			} // TODO move within localStates?
		}

		// Compute aggregate data based on each interface
		aggregateStatus := cache.AvailableStatus{
			Available: cache.AvailableTuple{
				IPv4: false,
				IPv6: false,
			},
			ProcessedAvailable: false,
			LastCheckedIPv4:    false,
			Status:             mc.TrafficServer[string(result.ID)].ServerStatus,
			Why:                "",
			UnavailableStat:    "",
			Poller:             pollerName,
		}

		aggIsAvailable, aggUsingIPv4, aggWhyAvailable, aggUnavailableStat := EvalAggregate(cache.ToInfo(result), statResults, &mc)
		aggAvailableTuple := cache.AvailableTuple{}
		aggAvailableTuple.SetAvailability(aggUsingIPv4, aggIsAvailable)
		aggNewAvailableState := processAvailableTuple(aggAvailableTuple, serverInfo)

		if !aggIsAvailable {
			// If aggregate fails then Cache should be marked down
			aggregateStatus.Available = aggAvailableTuple
			aggregateStatus.ProcessedAvailable = aggNewAvailableState
			aggregateStatus.LastCheckedIPv4 = aggUsingIPv4
			aggregateStatus.Why = aggWhyAvailable
			aggregateStatus.UnavailableStat = "aggregate." + aggUnavailableStat

		} else {
			for interfaceName, status := range localCacheStatuses[tc.CacheName(result.ID)] {
				if interfaceName == tc.CacheInterfacesAggregate {
					continue
				}
				aggregateStatus.Available.IPv4 = aggregateStatus.Available.IPv4 || status.Available.IPv4
				aggregateStatus.Available.IPv6 = aggregateStatus.Available.IPv6 || status.Available.IPv6

				// What does this mean on aggregated data?
				// For now assume that if any interface was then the aggregate is
				aggregateStatus.LastCheckedIPv4 = aggregateStatus.LastCheckedIPv4 || status.LastCheckedIPv4

				if status.Why != "" {
					newWhyText := fmt.Sprintf("%s: %s", interfaceName, status.Why)
					if aggregateStatus.Why != "" {
						newWhyText = ", " + newWhyText
					}
					aggregateStatus.Why += newWhyText
				}

				if status.UnavailableStat != "" {
					newUnavailableText := fmt.Sprintf("%s: %s", interfaceName, status.UnavailableStat)
					if aggregateStatus.UnavailableStat != "" {
						newUnavailableText += ", " + newUnavailableText
					}
					aggregateStatus.UnavailableStat = newUnavailableText
				}

				// What does this mean on aggregated data?
				// For now use random status unless a REPORTED status is found
				if tc.CacheStatus(aggregateStatus.Status) != tc.CacheStatusReported {
					aggregateStatus.Status = status.Status
				}

				// Each interface in a cache should always have the same poller
				aggregateStatus.Poller = status.Poller
			}
		}
		aggregateStatus.ProcessedAvailable = processAvailableTuple(aggregateStatus.Available, serverInfo)

		if _, ok := localCacheStatuses[tc.CacheName(result.ID)]; !ok {
			localCacheStatuses[tc.CacheName(result.ID)] = make(map[string]cache.AvailableStatus)
		}
		localCacheStatuses[tc.CacheName(result.ID)][tc.CacheInterfacesAggregate] = aggregateStatus

		localStates.SetCache(tc.CacheName(result.ID), tc.IsAvailable{
			IsAvailable:   aggregateStatus.ProcessedAvailable,
			Ipv4Available: aggregateStatus.Available.IPv4,
			Ipv6Available: aggregateStatus.Available.IPv6,
		})

		if statResultsVal != nil {
			t := (*statResultsVal)[tc.CacheInterfacesAggregate]
			statResults = &t
		}
		if available, ok := localStates.GetCache(tc.CacheName(result.ID)); !ok || available.IsAvailable != aggregateStatus.ProcessedAvailable {
			protocol := "IPv4"
			if !aggregateStatus.LastCheckedIPv4 {
				protocol = "IPv6"
			}
			log.Infof("Changing state for %s was: %t now: %t because %s poller: %v on protocol %v error: %v",
				result.ID, available.IsAvailable, aggregateStatus.ProcessedAvailable, aggregateStatus.Why, pollerName, protocol, result.Error)
			events.Add(Event{Time: Time(time.Now()), Description: "Protocol: (" + protocol + ") " + aggregateStatus.Why +
				" (" + pollerName + ")", Name: result.ID, Hostname: result.ID,
				Type: toData.ServerTypes[tc.CacheName(result.ID)].String(), Available: aggregateStatus.ProcessedAvailable,
				IPv4Available: aggregateStatus.Available.IPv4, IPv6Available: aggregateStatus.Available.IPv6})
		}
		//}
	}
	calculateDeliveryServiceState(toData.DeliveryServiceServers, localStates, toData)
	localCacheStatusThreadsafe.Set(localCacheStatuses)
}

func setErr(newResult *cache.Result, err error) {
	newResult.Error = err
	newResult.Available = false
}

// ExceedsThresholdMsg returns a human-readable message for why the given value exceeds the threshold. It does NOT check whether the value actually exceeds the threshold; call `InThreshold` to check first.
func exceedsThresholdMsg(stat string, threshold tc.HealthThreshold, val float64) string {
	switch threshold.Comparator {
	case "=":
		return fmt.Sprintf("%s not equal (%.2f != %.2f)", stat, val, threshold.Val)
	case ">":
		return fmt.Sprintf("%s too low (%.2f < %.2f)", stat, val, threshold.Val)
	case "<":
		return fmt.Sprintf("%s too high (%.2f > %.2f)", stat, val, threshold.Val)
	case ">=":
		return fmt.Sprintf("%s too low (%.2f <= %.2f)", stat, val, threshold.Val)
	case "<=":
		return fmt.Sprintf("%s too high (%.2f >= %.2f)", stat, val, threshold.Val)
	default:
		return fmt.Sprintf("ERROR: Invalid Threshold: %+v", threshold)
	}
}

func inThreshold(threshold tc.HealthThreshold, val float64) bool {
	switch threshold.Comparator {
	case "=":
		return val == threshold.Val
	case ">":
		return val > threshold.Val
	case "<":
		return val < threshold.Val
	case ">=":
		return val >= threshold.Val
	case "<=":
		return val <= threshold.Val
	default:
		log.Errorf("Invalid Threshold: %+v", threshold)
		return true // for safety, if a threshold somehow gets corrupted, don't start marking caches down.
	}
}

func eventDesc(status tc.CacheStatus, message string) string {
	return fmt.Sprintf("%s - %s", status, message)
}

//calculateDeliveryServiceState calculates the state of delivery services from the new cache state data `cacheState` and the CRConfig data `deliveryServiceServers` and puts the calculated state in the outparam `deliveryServiceStates`
func calculateDeliveryServiceState(deliveryServiceServers map[tc.DeliveryServiceName][]tc.CacheName, states peer.CRStatesThreadsafe, toData todata.TOData) {
	cacheStates := states.GetCaches()

	deliveryServices := states.GetDeliveryServices()
	for deliveryServiceName, deliveryServiceState := range deliveryServices {
		if _, ok := deliveryServiceServers[deliveryServiceName]; !ok {
			log.Infof("CRConfig does not have delivery service %s, but traffic monitor poller does; skipping\n", deliveryServiceName)
			continue
		}
		deliveryServiceState.DisabledLocations = getDisabledLocations(deliveryServiceName, toData.DeliveryServiceServers[deliveryServiceName], cacheStates, toData.ServerCachegroups)
		states.SetDeliveryService(deliveryServiceName, deliveryServiceState)
	}
}

func getDisabledLocations(deliveryService tc.DeliveryServiceName, deliveryServiceServers []tc.CacheName, cacheStates map[tc.CacheName]tc.IsAvailable, serverCacheGroups map[tc.CacheName]tc.CacheGroupName) []tc.CacheGroupName {
	disabledLocations := []tc.CacheGroupName{} // it's important this isn't nil, so it serialises to the JSON `[]` instead of `null`
	dsCacheStates := getDeliveryServiceCacheAvailability(cacheStates, deliveryServiceServers)
	dsCachegroupsAvailable := getDeliveryServiceCachegroupAvailability(dsCacheStates, serverCacheGroups)
	for cg, avail := range dsCachegroupsAvailable {
		if avail {
			continue
		}
		disabledLocations = append(disabledLocations, cg)
	}
	return disabledLocations
}

func getDeliveryServiceCacheAvailability(cacheStates map[tc.CacheName]tc.IsAvailable, deliveryServiceServers []tc.CacheName) map[tc.CacheName]tc.IsAvailable {
	dsCacheStates := map[tc.CacheName]tc.IsAvailable{}
	for _, server := range deliveryServiceServers {
		dsCacheStates[server] = cacheStates[tc.CacheName(server)]
	}
	return dsCacheStates
}

func getDeliveryServiceCachegroupAvailability(dsCacheStates map[tc.CacheName]tc.IsAvailable, serverCachegroups map[tc.CacheName]tc.CacheGroupName) map[tc.CacheGroupName]bool {
	cgAvail := map[tc.CacheGroupName]bool{}
	for cache, available := range dsCacheStates {
		cg, ok := serverCachegroups[cache]
		if !ok {
			log.Errorf("cache %v not found in cachegroups!\n", cache)
			continue
		}
		if _, ok := cgAvail[cg]; !ok || available.IsAvailable {
			cgAvail[cg] = available.IsAvailable
		}
	}
	return cgAvail
}
