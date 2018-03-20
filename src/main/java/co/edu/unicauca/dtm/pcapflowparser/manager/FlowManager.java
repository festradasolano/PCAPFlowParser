/*
 * Copyright 2018 Felipe Estrada-Solano <festradasolano at gmail>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package co.edu.unicauca.dtm.pcapflowparser.manager;

import java.util.HashMap;

import co.edu.unicauca.dtm.pcapflowparser.model.Flow;
import co.edu.unicauca.dtm.pcapflowparser.model.Packet;

/**
 * 
 * 
 * Copyright 2018 Felipe Estrada-Solano <festradasolano at gmail>
 * 
 * Distributed under the Apache License, Version 2.0 (see LICENSE for details)
 * 
 * @author festradasolano
 */
public class FlowManager {
	
	/**
	 * 
	 */
	private HashMap<String, Flow> flows;
	
	/**
	 * 
	 */
	long flowTimeout;
	
	/**
	 * 
	 */
	long activityTimeout;
	
	/**
	 * 
	 */
	int initialPackets;
	
	/**
	 * @param flowTimeout flow timeout in seconds
	 * @param activityTimeout activity timeout in seconds
	 * @param initialPackets number of packets at the beginning of a flow for processing features
	 */
	public FlowManager(int flowTimeout, int activityTimeout, int initialPackets) {
		super();
		long secToMicrosec = 1000000;
		this.flowTimeout = (long) flowTimeout * secToMicrosec;
		this.activityTimeout = (long) activityTimeout * secToMicrosec;
		this.initialPackets = initialPackets;
		flows = new HashMap<String, Flow>();
	}
	
	public void addPacket(Packet packet) {
		
	}
	
	public static String generatedFlowId(Packet packet) {
		String flowId = "";
		// Check if TCP/UDP source/destination ports exist
		if (packet.getPortSrc() != 0 && packet.getPortDst() != 0) {
			flowId = "-" + packet.getPortSrc() + "-" + packet.getPortDst();
		}
		// Check if IPv4 protocol exists
		if (packet.getIpProto() != 0) {
			flowId = "-" + packet.getIpProto() + flowId;
		}
		// Check if 
		return null;
	}

}