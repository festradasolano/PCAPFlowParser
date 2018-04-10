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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
	private long flowActiveTimeout;

	/**
	 * 
	 */
	private long flowIdleTimeout;

	/**
	 * 
	 */
	private int nFirstPackets;

	/**
	 * 
	 */
	private Map<String, Flow> flows;

	/**
	 * Timeout used for cleaning the list of flows (avoid keeping flows that are no
	 * longer active)
	 */
	private long dumpTimeout;

	/**
	 * 
	 */
	private long lastDumpTimestamp;

	/**
	 * 
	 */
	private long flowCounter;

	/**
	 * 
	 */
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
	public FlowManager(String pcapDirName, String outDirPath, int flowActiveTimeout, int flowIdleTimeout,
			int nFirstPackets) throws FileNotFoundException {
		super();
		// Set input parameters
		long secToMicrosec = 1000000;
		this.flowActiveTimeout = (long) flowActiveTimeout * secToMicrosec;
		this.flowIdleTimeout = (long) flowIdleTimeout * secToMicrosec;
		this.nFirstPackets = nFirstPackets;
		// Set dump timeout with the minimum flow timeout (active or idle or none)
		dumpTimeout = 0;
		if (this.flowActiveTimeout > 0 && this.flowIdleTimeout > 0) {
			if (this.flowActiveTimeout < this.flowIdleTimeout) {
				dumpTimeout = this.flowActiveTimeout;
			} else {
				dumpTimeout = this.flowIdleTimeout;
			}
		} else if (this.flowActiveTimeout > 0) {
			dumpTimeout = this.flowActiveTimeout;
		} else if (this.flowIdleTimeout > 0) {
			dumpTimeout = this.flowIdleTimeout;
		}
		// Initialize parameters
		flows = new HashMap<String, Flow>();
		flowCounter = 0;
		lastDumpTimestamp = 0;
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
		// Check if the dump timeout passed since the last dump
		if (dumpTimeout > 0 && packet.getTimestamp() - lastDumpTimestamp > dumpTimeout) {
			dumpTimedOutFlows(packet.getTimestamp());
			lastDumpTimestamp = packet.getTimestamp();
		}
		// Check if packet belongs to an existing flow
		String flowId = FlowManager.generateFlowId(packet);
		if (flows.containsKey(flowId)) {
			Flow flow = flows.get(flowId);
			// Check if the flow finished due to active timeout
			if (flowActiveTimeout > 0 && packet.getTimestamp() - flow.getStartTime() > flowActiveTimeout) {
				// Dump flow information to file
				dumpFlowToFile(flow);
				// Remove flow from list
				flows.remove(flowId);
				flowCounter++;
				// Add flow to list with first packet
				flows.put(flowId, new Flow(packet));
			} // Check if the flow finished due to idle timeout
			else if (flowIdleTimeout > 0 && packet.getTimestamp() - flow.getLastSeen() > flowIdleTimeout) {
				// Dump flow information to file
				dumpFlowToFile(flow);
				// Remove flow from list
				flows.remove(flowId);
				flowCounter++;
				// Add flow to list with first packet
				flows.put(flowId, new Flow(packet));
			} else {
				// Update flow information
				flow.addPacketSize(packet.getSize(), nFirstPackets);
				long packetIAT = packet.getTimestamp() - flow.getLastSeen();
				flow.addPacketIAT(packetIAT, nFirstPackets);
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
	 * @return
	 */
	public long dumpLastFlows() {
		for (Flow flow : flows.values()) {
			// Dump flow information to file
			dumpFlowToFile(flow);
			flowCounter++;
		}
		return flowCounter;
	}

	/**
	 * @param timestamp
	 */
	private void dumpTimedOutFlows(long timestamp) {
		// Go through every flow
		List<String> removeFlowId = new ArrayList<String>();
		for (String flowId : flows.keySet()) {
			Flow flow = flows.get(flowId);
			// Check if flow timed-out due to active timeout
			if (flowActiveTimeout > 0 && timestamp - flow.getStartTime() > flowActiveTimeout) {
				// Dump flow information to file
				dumpFlowToFile(flow);
				flowCounter++;
				// Add flow ID to the removing list
				removeFlowId.add(flowId);
			} else if (flowIdleTimeout > 0 && timestamp - flow.getLastSeen() > flowIdleTimeout) {
				// Dump flow information to file
				dumpFlowToFile(flow);
				flowCounter++;
				// Add flow ID to the removing list
				removeFlowId.add(flowId);
			}
		}
		// Remove dumped flows from list
		for (String flowId : removeFlowId) {
			flows.remove(flowId);
		}
	}

	/**
	 * @param flow
	 */
	private void dumpFlowToFile(Flow flow) {
		try {
			output.write(String.valueOf(flow.toCSV(nFirstPackets) + "\n").getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Generates the identifier of the flow using the source/destination addresses
	 * of either IP (IPv4/IPv6) or Ethernet, the IP protocol or the Ethernet type,
	 * the TCP/UDP source/destination ports, and the VLAN identifier. These fields
	 * were selected based on the hash function that Open vSwitch version >= 2.4
	 * applies for bucket selection
	 * 
	 * @param packet
	 *            the packet for generating the flow identifier
	 * @return the flow identifier
	 */
	public static String generateFlowId(Packet packet) {
		StringBuilder flowId = new StringBuilder();
		// Check if IPv4/IPv6 source/destination addresses exist
		if (packet.getIpSrc() != null && packet.getIpDst() != null) {
			flowId.append(packet.getIpSrcString());
			flowId.append("-");
			flowId.append(packet.getIpDstString());
			flowId.append("_");
			flowId.append(packet.getIpProto());
			flowId.append("_");
		} // Check if Ethernet source/destination addresses exist
		else if (packet.getEthSrc() != null && packet.getEthDst() != null) {
			flowId.append(packet.getEthSrcString());
			flowId.append("-");
			flowId.append(packet.getEthDstString());
			flowId.append("_");
			flowId.append(packet.getEthType());
			flowId.append("_");
		} else {
			flowId.append("noAddresses");
			flowId.append("_");
		}
		// Check if TCP/UDP source/destination ports exist
		if (packet.getPortSrc() != -1 && packet.getPortDst() != -1) {
			flowId.append(packet.getPortSrc());
			flowId.append("-");
			flowId.append(packet.getPortDst());
			flowId.append("_");
		}
		// Check if VLAN ID exists
		if (packet.getVlanId() != -1) {
			flowId.append(packet.getVlanId());
		}
		return flowId.toString();
	}

}
