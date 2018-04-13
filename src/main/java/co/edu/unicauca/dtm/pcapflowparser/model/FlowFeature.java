package co.edu.unicauca.dtm.pcapflowparser.model;

import java.util.HashSet;
import java.util.Set;

public enum FlowFeature {

	START_TIME("start_time", 0), END_TIME("end_time", 1), ETH_SRC("eth_src", 2), ETH_DST("eth_dst", 3), VLAN_ID(
			"vlan_id", 4), ETH_TYPE("eth_type", 5), IP_SRC("ip_src", 6), IP_DST("ip_dst", 7), IP_PROTO("ip_proto",
					8), PORT_SRC("port_src", 9), PORT_DST("port_dst", 10), TOTAL_SIZE("tot_size", 11), TOTAL_PACKETS(
							"tot_pkts", 12), DURATION("duration", 13), IAT_MEAN("iat_mean", 14), IAT_STD("iat_std",
									15), IAT_MAX("iat_max", 16), IAT_MIN("iat_min", 17), PRIOR_TOS("prior_tos",
											18), TIME_LAST_TO("time_last_to", 19), PACKET_SIZE("size_pkt", 20,
													true), PACKET_IAT("iat_pkt", 21, true);

	/**
	 * 
	 */
	private final String name;

	/**
	 * 
	 */
	private final int id;

	/**
	 * 
	 */
	private final boolean isNFirst;

	/**
	 * @param name
	 * @param id
	 */
	FlowFeature(String name, int id) {
		this.name = name;
		this.id = id;
		this.isNFirst = false;
	}

	/**
	 * @param name
	 * @param id
	 * @param isNFirst
	 */
	FlowFeature(String name, int id, boolean isNFirst) {
		this.name = name;
		this.id = id;
		this.isNFirst = isNFirst;
	}

	/**
	 * @return
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return
	 */
	public int getId() {
		return id;
	}

	/**
	 * @return
	 */
	public boolean isNFirst() {
		return isNFirst;
	}

	/**
	 * @return
	 */
	public static Set<Integer> allFeatureIds() {
		Set<Integer> ids = new HashSet<Integer>();
		for (FlowFeature feature : FlowFeature.values()) {
			ids.add(feature.getId());
		}
		return ids;
	}

	/**
	 * @param features
	 * @return
	 */
	public static Set<Integer> featureIdByName(String features) {
		Set<Integer> ids = new HashSet<Integer>();
		for (String name : features.split(",")) {
			boolean found = false;
			for (FlowFeature feature : FlowFeature.values()) {
				if (name.equalsIgnoreCase(feature.getName())) {
					ids.add(feature.getId());
					found = true;
					break;
				}
			}
			if (!found) {
				return null;
			}
		}
		return ids;
	}

	/**
	 * @param featureIds
	 * @param nFirstPackets
	 * @return
	 */
	public static String csvHeader(Set<Integer> featureIds, int nFirstPackets) {
		StringBuilder header = new StringBuilder();
		for (FlowFeature feature : FlowFeature.values()) {
			// Check if feature is included
			if (featureIds.contains(feature.getId())) {
				// Check if feature is for the N first packets
				if (feature.isNFirst()) {
					// Generate feature for the N first packets
					for (int i = 1; i <= nFirstPackets; i++) {
						header.append(feature.getName()).append(i).append(",");
					}
				} else {
					header.append(feature.getName()).append(",");
				}
			}
		}
		header.deleteCharAt(header.length() - 1);
		return header.toString();
	}

}
