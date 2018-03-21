package co.edu.unicauca.dtm.pcapflowparser.model;

public enum FlowFeature {
	
	TIMESTAMP("timestamp"),
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
	MAX_IDLE_TIME("max_idle_time");
	
	private final String name;
	
	private final boolean isNFirst;
	
	FlowFeature(String name) {
		this.name = name;
		this.isNFirst = false;
	}
	
	FlowFeature(String name, boolean isNFirst) {
		this.name = name;
		this.isNFirst = isNFirst;
	}

}
