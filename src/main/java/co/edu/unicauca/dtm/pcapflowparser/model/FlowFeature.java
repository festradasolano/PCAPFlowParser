package co.edu.unicauca.dtm.pcapflowparser.model;

public enum FlowFeature {
	
	START_TIME("start_time"),
	END_TIME("end_time"),
	IP_SRC("ip_src"),
	IP_DST("ip_dst"),
	PORT_SRC("port_src"),
	PORT_DST("port_dst"),
	IP_PROTO("ip_proto"),
	ETH_SRC("eth_src"),
	ETH_DST("eth_dst"),
	ETH_TYPE("eth_type"),
	VLAN_ID("vlan_id"),
	PACKET_SIZE("size_pkt", true),
	PACKET_IAT("iat_pkt", true),
	SIZE("size"),
	DURATION("duration"),
	MAX_IDLE_TIME("max_idle_time")
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
