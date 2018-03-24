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

package co.edu.unicauca.dtm.pcapflowparser.model;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

/**
 * 
 * 
 * Copyright 2018 Felipe Estrada-Solano <festradasolano at gmail>
 * 
 * Distributed under the Apache License, Version 2.0 (see LICENSE for details)
 * 
 * @author festradasolano
 */
public class Flow {

	/**
	 * First packet of the flow
	 */
	private Packet firstPacket;

	/**
	 * Start time in microseconds
	 */
	private long startTime;

	/**
	 * Last seen in microseconds
	 */
	private long lastSeen;

	/**
	 * Size in bytes of packets
	 */
	private SummaryStatistics packetSizes;
	
	/**
	 * Maximum idle time
	 */
	private SummaryStatistics packetIATs;

	/**
	 * Size in bytes of the first N packets
	 */
	private List<Integer> nFirstPacketSizes;

	/**
	 * Inter-arrival time in microseconds of the first N packets
	 */
	private List<Long> nFirstPacketIATs;

	/**
	 * 
	 */
	public Flow() {
		super();
	}

	/**
	 * @param firstPacket
	 */
	public Flow(Packet firstPacket) {
		super();
		this.firstPacket = firstPacket;
		startTime = firstPacket.getTimestamp();
		lastSeen = firstPacket.getTimestamp();
		packetSizes = new SummaryStatistics();
		packetSizes.addValue(firstPacket.getSize());
		packetIATs = new SummaryStatistics();
		nFirstPacketSizes = new ArrayList<Integer>();
		nFirstPacketSizes.add(firstPacket.getSize());
		nFirstPacketIATs = new ArrayList<Long>();
		nFirstPacketIATs.add(firstPacket.getTimestamp() - lastSeen);
	}

	/**
	 * @return the firstPacket
	 */
	public Packet getFirstPacket() {
		return firstPacket;
	}

	/**
	 * @param firstPacket
	 *            the firstPacket to set
	 */
	public void setFirstPacket(Packet firstPacket) {
		this.firstPacket = firstPacket;
	}

	/**
	 * @return the startTime
	 */
	public long getStartTime() {
		return startTime;
	}

	/**
	 * @param startTime
	 *            the startTime to set
	 */
	public void setStartTime(long startTime) {
		this.startTime = startTime;
	}

	/**
	 * @return the lastSeen
	 */
	public long getLastSeen() {
		return lastSeen;
	}

	/**
	 * @param lastSeen
	 *            the lastSeen to set
	 */
	public void setLastSeen(long lastSeen) {
		this.lastSeen = lastSeen;
	}

	/**
	 * @return the packetSizes
	 */
	public SummaryStatistics getPacketSizes() {
		return packetSizes;
	}

	/**
	 * @param packetSizes the packetSizes to set
	 */
	public void setPacketSizes(SummaryStatistics packetSizes) {
		this.packetSizes = packetSizes;
	}
	
	/**
	 * @param packetSize
	 * @param nFirstPackets
	 */
	public void addPacketSize(int packetSize, int nFirstPackets) {
		packetSizes.addValue(packetSize);
		if (nFirstPacketSizes.size() <= nFirstPackets) {
			nFirstPacketSizes.add(packetSize);
		}
	}

	/**
	 * @return the packetIATs
	 */
	public SummaryStatistics getPacketIATs() {
		return packetIATs;
	}

	/**
	 * @param packetIATs the packetIATs to set
	 */
	public void setPacketIATs(SummaryStatistics packetIATs) {
		this.packetIATs = packetIATs;
	}

	/**
	 * @param packetIAT
	 * @param nFirstPackets
	 */
	public void addPacketIAT(long packetIAT, int nFirstPackets) {
		packetIATs.addValue(packetIAT);
		if (nFirstPacketIATs.size() <= nFirstPackets) {
			nFirstPacketIATs.add(packetIAT);
		}
	}

	/**
	 * @return the nFirstPacketSizes
	 */
	public List<Integer> getNFirstPacketSizes() {
		return nFirstPacketSizes;
	}

	/**
	 * @param nFirstPacketSizes
	 *            the nFirstPacketSizes to set
	 */
	public void setNFirstPacketSizes(List<Integer> nFirstPacketSizes) {
		this.nFirstPacketSizes = nFirstPacketSizes;
	}

	/**
	 * @return the packetIATs
	 */
	public List<Long> getNFirstPacketIATs() {
		return nFirstPacketIATs;
	}

	/**
	 * @param packetIATs
	 *            the packetIATs to set
	 */
	public void setNFirstPacketIATs(List<Long> nFirstPacketIATs) {
		this.nFirstPacketIATs = nFirstPacketIATs;
	}

	/**
	 * @param nFirstPackets
	 * @return
	 */
	public String toCSV(int nFirstPackets) {
		StringBuilder csv = new StringBuilder();
		// Add time info: start and end time
		csv.append(startTime).append(",");
		csv.append(lastSeen).append(",");
		// Add first packet info
		csv.append(firstPacket.getIpSrcString()).append(",");
		csv.append(firstPacket.getIpDstString()).append(",");
		csv.append(firstPacket.getPortSrc()).append(",");
		csv.append(firstPacket.getPortDst()).append(",");
		csv.append(firstPacket.getIpProto()).append(",");
		csv.append(firstPacket.getEthSrcHex()).append(",");
		csv.append(firstPacket.getEthDstHex()).append(",");
		csv.append(firstPacket.getEthType()).append(",");
		csv.append(firstPacket.getVlanId()).append(",");
		// Add N first packet sizes
		for (int i = 0; i < nFirstPackets; i++) {
			if (i < nFirstPacketSizes.size()) {
				csv.append(nFirstPacketSizes.get(i)).append(",");
			} else {
				csv.append("NaN").append(",");
			}
		}
		// Add N first packet inter-arrival times
		for (int i = 0; i < nFirstPackets; i++) {
			if (i < nFirstPacketIATs.size()) {
				csv.append(nFirstPacketIATs.get(i)).append(",");
			} else {
				csv.append("NaN").append(",");
			}
		}
		// Add flow info: size, packets, duration, meanIAT, stdIAT, maxIAT, minIAT
		csv.append(packetSizes.getSum()).append(",");
		csv.append(packetSizes.getN()).append(",");
		csv.append(lastSeen - startTime).append(",");
		csv.append(packetIATs.getMean()).append(",");
		csv.append(packetIATs.getStandardDeviation()).append(",");
		csv.append(packetIATs.getMax()).append(",");
		csv.append(packetIATs.getMin()).append(",");
		return csv.toString();
	}

}
