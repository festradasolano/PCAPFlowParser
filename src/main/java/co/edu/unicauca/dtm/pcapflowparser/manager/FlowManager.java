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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;

import co.edu.unicauca.dtm.pcapflowparser.model.Flow;
import co.edu.unicauca.dtm.pcapflowparser.model.FlowFeature;
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
	long flowIdleTimeout;

	/**
	 * 
	 */
	int nFirstPackets;
	
	/**
	 * 
	 */
	private HashMap<String, Flow> flows;

	/**
	 * 
	 */
	long lastDumpTimestamp;
	
	/**
	 * 
	 */
	long flowCounter;
	
	FileOutputStream output;

	/**
	 * @param flowTimeout
	 *            flow timeout in seconds
	 * @param activityTimeout
	 *            activity timeout in seconds
	 * @param nFirstPackets
	 *            number of packets at the beginning of a flow for processing
	 *            features
	 */
	public FlowManager(String pcapDirName, String outDirPath, int flowIdleTimeout, int nFirstPackets) throws FileNotFoundException {
		super();
		// Set input parameters
		long secToMicrosec = 1000000;
		this.flowIdleTimeout = (long) flowIdleTimeout * secToMicrosec;
		this.nFirstPackets = nFirstPackets;
		// Initialize parameters
		flows = new HashMap<String, Flow>();
		lastDumpTimestamp = 0;
		flowCounter = 0;
		// Check if output CSV file exists
		File csvFile = new File(outDirPath + "/" + pcapDirName + ".csv");
		if (csvFile.exists()) {
			csvFile.delete();
		}
		// Create CSV file writer
		output = new FileOutputStream(csvFile);
		try {
			output.write(String.valueOf(FlowFeature.getCSVHeader(this.nFirstPackets) + "\n").getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @param packet
	 */
	public void addPacket(Packet packet) {
		// Check if the flow timeout passed since the last dump
		if (packet.getTimestamp() - lastDumpTimestamp > flowIdleTimeout) {
			flowCounter = flowCounter + dumpTimedoutFlows(packet.getTimestamp());
			lastDumpTimestamp = packet.getTimestamp();
		}
		// Check if packet belongs to an existing flow
		String flowId = FlowManager.generateFlowId(packet);
		if (flows.containsKey(flowId)) {
			Flow flow = flows.get(flowId);
			// Check if the flow finished due to timestamp
			if (packet.getTimestamp() - flow.getLastSeen() > flowIdleTimeout) {
				// Dump flow information to file
				// Remove flow from list
				flows.remove(flowId);
				flowCounter++;
				// Add flow to list with first packet
				flows.put(flowId, new Flow(packet));
			} else {
				// Update flow information: total length and maximum idle time
				long packetIAT = packet.getTimestamp() - flow.getLastSeen();
				flow.sumUpPacketSize(packet.getSize());
				flow.checkUpdateMaxIdleTime(packetIAT);
				// Check the number of first packets added
				if (flow.getNFirstPacketsAdded() <= nFirstPackets) {
					// Add packet length and inter-arrival time
					flow.addPacketSize(packet.getSize());
					flow.addPacketIAT(packetIAT);
				}
				// Update last seen
				flow.setLastSeen(packet.getTimestamp());
			}
		} // First packet of a flow
		else {
			// Add flow to list with first packet
			flows.put(flowId, new Flow(packet));
		}
	}
	
	/**
	 * @param timestamp
	 * @return
	 */
	private long dumpTimedoutFlows(long timestamp) {
		long dumpedFlows = 0;
		for (String flowId : flows.keySet()) {
			Flow flow = flows.get(flowId);
			if (timestamp - flow.getLastSeen() > flowIdleTimeout) {
				// Dump flow information to file
				// Remove flow from list
				flows.remove(flowId);
				dumpedFlows++;
			}
		}
		return dumpedFlows;
	}

	/**
	 * Generates the identifier of the flow using the source/destination addresses
	 * of either IPv4/Ipv6 or Ethernet, the TCP/UDP source/destination ports, the
	 * IPv4 protocol, and the VLAN identifier. If no values of the aforementioned
	 * fields are available, a mark is used: noAddresses, noPorts, no Protocol, and
	 * noVLAN, respectively.
	 * 
	 * @param packet
	 *            the packet for generating the flow identifier
	 * @return the flow identifier
	 */
	public static String generateFlowId(Packet packet) {
		StringBuilder flowId = new StringBuilder("");
		// Check if IPv4/IPv6 source/destination addresses exist
		if (packet.getIpSrc() != Packet.IP_UNKNOWN && packet.getIpDst() != Packet.IP_UNKNOWN) {
			flowId.append(packet.getIpSrcString());
			flowId.append("-");
			flowId.append(packet.getIpDstString());
			flowId.append("_");
		} // Check if Ethernet source/destination addresses exist
		else if (packet.getEthSrc() != Packet.ETH_UNKNOWN && packet.getEthDst() != Packet.ETH_UNKNOWN) {
			flowId.append(packet.getEthSrcHex());
			flowId.append("-");
			flowId.append(packet.getEthDstHex());
			flowId.append("_");
		} else {
			flowId.append("noAddresses_");
		}
		// Check if TCP/UDP source/destination ports exist
		if (packet.getPortSrc() != 0 && packet.getPortDst() != 0) {
			flowId.append(packet.getPortSrc());
			flowId.append("-");
			flowId.append(packet.getPortDst());
			flowId.append("_");
		} else {
			flowId.append("noPorts_");
		}
		// Check if IPv4 protocol exists
		if (packet.getIpProto() != 0) {
			flowId.append(packet.getIpProto());
			flowId.append("_");
		} else {
			flowId.append("noProtocol_");
		}
		// Check if VLAN ID exists
		if (packet.getVlanId() != 0) {
			flowId.append(packet.getVlanId());
		} else {
			flowId.append("noVLAN");
		}
		return flowId.toString();
	}

}
