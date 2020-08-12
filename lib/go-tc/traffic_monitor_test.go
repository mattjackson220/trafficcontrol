package tc

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

import "encoding/json"
import "fmt"
import "testing"

func ExampleHealthThreshold_String() {
	ht := HealthThreshold{Comparator: ">=", Val: 500}
	fmt.Println(ht)
	// Output: >=500.000000
}

func ExampleTMParameters_UnmarshalJSON() {
	const data = `{
		"health.connection.timeout": 5,
		"health.polling.url": "https://example.com/",
		"health.polling.format": "stats_over_http",
		"history.count": 1,
		"health.threshold.bandwidth": ">50",
		"health.threshold.foo": "<=500"
	}`

	var params TMParameters
	if err := json.Unmarshal([]byte(data), &params); err != nil {
		fmt.Printf("Failed to unmarshal: %v\n", err)
		return
	}
	fmt.Printf("timeout: %d\n", params.HealthConnectionTimeout)
	fmt.Printf("url: %s\n", params.HealthPollingURL)
	fmt.Printf("format: %s\n", params.HealthPollingFormat)
	fmt.Printf("history: %d\n", params.HistoryCount)
	fmt.Printf("# of Thresholds: %d - foo: %s, bandwidth: %s\n", len(params.Thresholds), params.Thresholds["foo"], params.Thresholds["bandwidth"])

	// Output: timeout: 5
	// url: https://example.com/
	// format: stats_over_http
	// history: 1
	// # of Thresholds: 2 - foo: <=500.000000, bandwidth: >50.000000
}

func ExampleTrafficMonitorConfigMap_Valid() {
	mc := &TrafficMonitorConfigMap{
		CacheGroup: map[string]TMCacheGroup{"a": {}},
		Config: map[string]interface{}{
			"peers.polling.interval":  0.0,
			"health.polling.interval": 0.0,
		},
		DeliveryService: map[string]TMDeliveryService{"a": {}},
		Profile:         map[string]TMProfile{"a": {}},
		TrafficMonitor:  map[string]TrafficMonitor{"a": {}},
		TrafficServer:   map[string]TrafficServer{"a": {}},
	}

	fmt.Printf("Validity error: %v", mc.Valid())

	// Output: Validity error: <nil>
}

func TestTrafficMonitorConfigMap_Valid(t *testing.T) {
	var mc *TrafficMonitorConfigMap = nil
	err := mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of nil config map")
	} else {
		t.Logf("Got expected error: checking validity of nil config map: %v", err)
	}
	mc = &TrafficMonitorConfigMap{
		CacheGroup: nil,
		Config: map[string]interface{}{
			"peers.polling.interval":  42.0,
			"health.polling.interval": 24.0,
		},
		DeliveryService: map[string]TMDeliveryService{"a": {}},
		Profile:         map[string]TMProfile{"a": {}},
		TrafficMonitor:  map[string]TrafficMonitor{"a": {}},
		TrafficServer:   map[string]TrafficServer{"a": {}},
	}

	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with nil CacheGroup")
	} else {
		t.Logf("Got expected error: checking validity of config map with nil CacheGroup: %v", err)
	}

	mc.CacheGroup = map[string]TMCacheGroup{}
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with no CacheGroups")
	} else {
		t.Logf("Got expected error: checking validity of config map with no CacheGroups: %v", err)
	}

	mc.CacheGroup["a"] = TMCacheGroup{}
	mc.Config = nil
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with nil Config")
	} else {
		t.Logf("Got expected error: checking validity of config map with nil Config: %v", err)
	}

	mc.Config = map[string]interface{}{}
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with empty Config")
	} else {
		t.Logf("Got expected error: checking validity of config map with empty Config: %v", err)
	}

	mc.Config["peers.polling.interval"] = 42.0
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map without health.polling.interval")
	} else {
		t.Logf("Got expected error: checking validity of config map without health.polling.interval: %v", err)
	}

	delete(mc.Config, "peers.polling.interval")
	mc.Config["health.polling.interval"] = 42.0
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map without peers.polling.interval")
	} else {
		t.Logf("Got expected error: checking validity of config map without peers.polling.interval: %v", err)
	}

	mc.Config["peers.polling.interval"] = 42.0
	// TODO: uncomment these tests when #3528 is resolved
	// mc.DeliveryService = nil
	// err = mc.Valid()
	// if err == nil {
	// 	t.Error("Didn't get expected error checking validity of config map with nil DeliveryService")
	// } else {
	// 	t.Logf("Got expected error: checking validity of config map with nil DeliveryService: %v", err)
	// }

	// mc.DeliveryService = map[string]TMDeliveryService{}
	// err = mc.Valid()
	// if err == nil {
	// 	t.Error("Didn't get expected error checking validity of config map with no DeliveryServices")
	// } else {
	// 	t.Logf("Got expected error: checking validity of config map with no DeliveryServices: %v", err)
	// }

	// mc.DeliveryService["a"] = TMDeliveryService{}
	mc.Profile = nil
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with nil Profile")
	} else {
		t.Logf("Got expected error: checking validity of config map with nil Profile: %v", err)
	}

	mc.Profile = map[string]TMProfile{}
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with no Profiles")
	} else {
		t.Logf("Got expected error: checking validity of config map with no Profiles: %v", err)
	}

	mc.Profile["a"] = TMProfile{}
	mc.TrafficMonitor = nil
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with nil TrafficMonitor")
	} else {
		t.Logf("Got expected error: checking validity of config map with nil TrafficMonitor: %v", err)
	}

	mc.TrafficMonitor = map[string]TrafficMonitor{}
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with no TrafficMonitors")
	} else {
		t.Logf("Got expected error: checking validity of config map with no TrafficMonitors: %v", err)
	}

	mc.TrafficMonitor["a"] = TrafficMonitor{}
	mc.TrafficServer = nil
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with nil TrafficServer")
	} else {
		t.Logf("Got expected error: checking validity of config map with nil TrafficServer: %v", err)
	}

	mc.TrafficServer = map[string]TrafficServer{}
	err = mc.Valid()
	if err == nil {
		t.Error("Didn't get expected error checking validity of config map with no TrafficServers")
	} else {
		t.Logf("Got expected error: checking validity of config map with no TrafficServers: %v", err)
	}
}
