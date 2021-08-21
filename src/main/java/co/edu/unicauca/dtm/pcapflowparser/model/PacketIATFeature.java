package co.edu.unicauca.dtm.pcapflowparser.model;

public enum PacketIATFeature {
	
	FLOW_ID("flow_id"), PACKET_NUM("pkt_num"), IAT("iat");
	
	/**
	 * 
	 */
	private final String name;

	/**
	 * @param name
	 */
	PacketIATFeature(String name) {
		this.name = name;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}
	
	/**
	 * @return
	 */
	public static String csvHeader() {
		StringBuilder header = new StringBuilder();
		for (PacketIATFeature feature : PacketIATFeature.values()) {
			header.append(feature.getName()).append(",");
		}
		header.deleteCharAt(header.length() - 1);
		return header.toString();
	}

}
