package co.edu.unicauca.dtm.pcapflowparser.model;

public enum FlowFeature {
	
	START_TIME("start_time"),
	END_TIME("end_time"),
	ETH_SRC("eth_src"),
	ETH_DST("eth_dst"),
	VLAN_ID("vlan_id"),
	ETH_TYPE("eth_type"),
	IP_SRC("ip_src"),
	IP_DST("ip_dst"),
	IP_PROTO("ip_proto"),
	PORT_SRC("port_src"),
	PORT_DST("port_dst"),
	TOTAL_SIZE("tot_size"),
	TOTAL_PACKETS("tot_pkts"),
	DURATION("duration"),
	IAT_MEAN("iat_mean"),
	IAT_STD("iat_std"),
	IAT_MAX("iat_max"),
	IAT_MIN("iat_min"),
	PRIOR_TOS("prior_tos"),
	TIME_LAST_TO("time_last_to"),
	PACKET_SIZE("size_pkt", true),
	PACKET_IAT("iat_pkt", true)
	;
	
	/**
	 * 
	 */
	private final String name;
	
	/**
	 * 
	 */
	private final boolean isNFirst;
	
	/**
	 * @param name
	 */
	FlowFeature(String name) {
		this.name = name;
		this.isNFirst = false;
	}
	
	/**
	 * @param name
	 * @param isNFirst
	 */
	FlowFeature(String name, boolean isNFirst) {
		this.name = name;
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
	public boolean isNFirst() {
		return isNFirst;
	}

	/**
	 * @param nFirstPackets
	 * @return
	 */
	public static String getCSVHeader(int nFirstPackets) {
		StringBuilder header = new StringBuilder();
		for (FlowFeature feature : FlowFeature.values()) {
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
		header.deleteCharAt(header.length() - 1);
		return header.toString();
	}

}
