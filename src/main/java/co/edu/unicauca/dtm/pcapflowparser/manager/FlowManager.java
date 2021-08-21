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
import java.util.Map;
import java.util.Set;

import co.edu.unicauca.dtm.pcapflowparser.model.Flow;
import co.edu.unicauca.dtm.pcapflowparser.model.FlowFeature;
import co.edu.unicauca.dtm.pcapflowparser.model.Packet;
import co.edu.unicauca.dtm.pcapflowparser.model.PacketIATFeature;

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
	private Set<Integer> features;

	/**
	 * 
	 */
	private int nFirstPackets;

	/**
	 * 
	 */
	private Map<String, Flow> flows;

	/**
	 * 
	 */
	private long flowCounter;

	/**
	 * 
	 */
	FileOutputStream output;

	/**
	 * 
	 */
	FileOutputStream iatOutput;

	/**
	 * @param outFile
	 * @param flowActiveTimeout
	 * @param flowIdleTimeout
	 * @param nFirstPackets
	 */
	public FlowManager(File outFile, int flowActiveTimeout, int flowIdleTimeout, Set<Integer> features,
			int nFirstPackets, File iatFile) {
		super();
		// Set input parameters
		long secToMicrosec = 1000000;
		this.flowActiveTimeout = (long) flowActiveTimeout * secToMicrosec;
		this.flowIdleTimeout = (long) flowIdleTimeout * secToMicrosec;
		this.features = features;
		this.nFirstPackets = nFirstPackets;
		// Initialize parameters
		flows = new HashMap<String, Flow>();
		flowCounter = 0;
		// Create CSV file writer
		try {
			output = new FileOutputStream(outFile);
			output.write(String.valueOf(FlowFeature.csvHeader(this.features, this.nFirstPackets) + "\n").getBytes());
			if (iatFile != null) {
				iatOutput = new FileOutputStream(iatFile);
				iatOutput.write(String.valueOf(PacketIATFeature.csvHeader() + "\n").getBytes());
			}
		} catch (FileNotFoundException e1) {
			System.err.println("Internal error. File '" + outFile.getAbsolutePath() + "' does not exist");
		} catch (IOException e) {
			System.err.println(
					"Internal error. Exception thrown when writing on the file '" + outFile.getAbsolutePath() + "'");
		}
	}

	/**
	 * @param packet
	 */
	public void addPacket(Packet packet) {
		// Check if packet belongs to an existing flow
		String flowId = FlowManager.generateFlowId(packet);
		if (flows.containsKey(flowId)) {
			Flow flow = flows.get(flowId);
			// Check if the flow finished due to active timeout
			if (flowActiveTimeout > 0 && packet.getTimestamp() - flow.getStartTime() > flowActiveTimeout) {
				// Compute time after last timeout
				long timeAfterLastTO = packet.getTimestamp() - flow.getStartTime() - flowActiveTimeout;
				// Dump timeout flow
				dumpTimeoutFlow(flowId, flow, new Flow(packet, flow.getPriorTOs() + 1, timeAfterLastTO));
			} // Check if the flow finished due to idle timeout
			else if (flowIdleTimeout > 0 && packet.getTimestamp() - flow.getLastSeen() > flowIdleTimeout) {
				// Compute time after last timeout
				long timeAfterLastTO = packet.getTimestamp() - flow.getLastSeen() - flowIdleTimeout;
				// Dump timeout flow
				dumpTimeoutFlow(flowId, flow, new Flow(packet, flow.getPriorTOs() + 1, timeAfterLastTO));
			} else {
				// Update flow information
				flow.addPacketSize(packet.getSize(), nFirstPackets);
				long packetIAT = packet.getTimestamp() - flow.getLastSeen();
				flow.addPacketIAT(packetIAT, nFirstPackets);
				// Update last seen
				flow.setLastSeen(packet.getTimestamp());
				// Check if writing packet IAT report
				if (iatOutput != null) {
					// Build packet IAT information
					StringBuilder iatInfo = new StringBuilder();
					iatInfo.append(flowId).append(",");
					iatInfo.append(flow.getPacketSizes().getN()).append(",");
					iatInfo.append(packetIAT).append("\n");
					// Write packet IAT report to file
					try {
						iatOutput.write(iatInfo.toString().getBytes());
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		} // First packet of a flow
		else {
			// Add flow to list with first packet
			flows.put(flowId, new Flow(packet));
		}
	}

	/**
	 * @param flowId
	 * @param timeoutFlow
	 * @param newFlow
	 */
	private void dumpTimeoutFlow(String flowId, Flow timeoutFlow, Flow newFlow) {
		// Dump flow information to file
		dumpFlowToFile(timeoutFlow);
		// Remove flow from list
		flows.remove(flowId);
		flowCounter++;
		// Add flow to list with first packet
		flows.put(flowId, newFlow);
	}

	/**
	 * @return number of processed flows
	 */
	public long dumpLastFlows() {
		// Dump remaining flows to file
		for (Flow flow : flows.values()) {
			dumpFlowToFile(flow);
			flowCounter++;
		}
		// Close file outputs
		try {
			output.close();
			if (iatOutput != null) {
				iatOutput.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return flowCounter;
	}

	/**
	 * @param flow
	 */
	private void dumpFlowToFile(Flow flow) {
		try {
			output.write(String.valueOf(flow.toCSV(features, nFirstPackets) + "\n").getBytes());
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
