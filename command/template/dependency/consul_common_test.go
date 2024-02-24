// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dependency

// filter is used as a helper for filtering values out of maps.
func filter(data map[string]string, remove []string) map[string]string {
	if data == nil {
		return make(map[string]string)
	}
	for _, k := range remove {
		delete(data, k)
	}
	return data
}

// filterVersionMeta filters out all version information from the returned
// metadata. It allocates the meta map if it is nil to make the tests backward
// compatible with versions < 1.5.2.
func filterVersionMeta(meta map[string]string) map[string]string {
	filteredMeta := []string{
		"raft_version", "serf_protocol_current",
		"serf_protocol_min", "serf_protocol_max", "version",
		"non_voter", "read_replica", "grpc_port", "grpc_tls_port", "consul-version",
	}
	return filter(meta, filteredMeta)
}

// filterAddresses filters out consul >1.7 ipv4/ipv6 specific entries
// from TaggedAddresses entries on nodes, catlog and health services.
func filterAddresses(addrs map[string]string) map[string]string {
	ipvKeys := []string{"lan_ipv4", "wan_ipv4", "lan_ipv6", "wan_ipv6"}
	return filter(addrs, ipvKeys)
}
