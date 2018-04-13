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
import java.util.Set;

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
	 * Summary statistics of the size in bytes of packets
	 */
	private SummaryStatistics packetSizes;

	/**
	 * Summary statistics of the inter-arrival time in microseconds of packets
	 */
	private SummaryStatistics packetIATs;

	/**
	 * Number of prior timeouts
	 */
	private int priorTOs;

	/**
	 * Time in microseconds after the last timeout
	 */
	private long timeAfterLastTO;

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
		initialize(firstPacket);
	}

	/**
	 * @param firstPacket
	 * @param priotTOs
	 * @param timeAfterLastTO
	 */
	public Flow(Packet firstPacket, int priotTOs, long timeAfterLastTO) {
		super();
		initialize(firstPacket);
		this.priorTOs = priotTOs;
		this.timeAfterLastTO = timeAfterLastTO;
	}

	/**
	 * @param firstPacket
	 */
	private void initialize(Packet firstPacket) {
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
		priorTOs = 0;
		timeAfterLastTO = 0;
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
	 * @param packetSizes
	 *            the packetSizes to set
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
		if (nFirstPacketSizes.size() < nFirstPackets) {
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
	 * @param packetIATs
	 *            the packetIATs to set
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
		if (nFirstPacketIATs.size() < nFirstPackets) {
			nFirstPacketIATs.add(packetIAT);
		}
	}

	/**
	 * @return the priorTOs
	 */
	public int getPriorTOs() {
		return priorTOs;
	}

	/**
	 * @param priorTOs
	 *            the priorTOs to set
	 */
	public void setPriorTOs(int priorTOs) {
		this.priorTOs = priorTOs;
	}

	/**
	 * @return the timeAfterLastTO
	 */
	public long getTimeAfterLastTO() {
		return timeAfterLastTO;
	}

	/**
	 * @param timeAfterLastTO
	 *            the timeAfterLastTO to set
	 */
	public void setTimeAfterLastTO(long timeAfterLastTO) {
		this.timeAfterLastTO = timeAfterLastTO;
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
	public String toCSV(Set<Integer> features, int nFirstPackets) {
		StringBuilder csv = new StringBuilder();
		// Check if all features are included
		if (features.containsAll(FlowFeature.allFeatureIds())) {
			// Add time info: start and end time
			csv.append(startTime).append(",");
			csv.append(lastSeen).append(",");
			// Add first packet info
			csv.append(firstPacket.getEthSrcString()).append(",");
			csv.append(firstPacket.getEthDstString()).append(",");
			csv.append(firstPacket.getVlanId()).append(",");
			csv.append(firstPacket.getEthType()).append(",");
			csv.append(firstPacket.getIpSrcString()).append(",");
			csv.append(firstPacket.getIpDstString()).append(",");
			csv.append(firstPacket.getIpProto()).append(",");
			csv.append(firstPacket.getPortSrc()).append(",");
			csv.append(firstPacket.getPortDst()).append(",");
			// Add flow info: size, packets, duration, meanIAT, stdIAT, maxIAT, minIAT
			csv.append(packetSizes.getSum()).append(",");
			csv.append(packetSizes.getN()).append(",");
			csv.append(lastSeen - startTime).append(",");
			csv.append(packetIATs.getMean()).append(",");
			csv.append(packetIATs.getStandardDeviation()).append(",");
			csv.append(packetIATs.getMax()).append(",");
			csv.append(packetIATs.getMin()).append(",");
			// Add timeout info: prior timeouts and time after last timeout
			csv.append(priorTOs).append(",");
			csv.append(timeAfterLastTO).append(",");
			// Add N first packet sizes
			for (int i = 0; i < nFirstPackets; i++) {
				if (i < nFirstPacketSizes.size()) {
					csv.append(nFirstPacketSizes.get(i)).append(",");
				} else {
					csv.append(Double.NaN).append(",");
				}
			}
			// Add N first packet inter-arrival times
			for (int i = 0; i < nFirstPackets; i++) {
				if (i < nFirstPacketIATs.size()) {
					csv.append(nFirstPacketIATs.get(i)).append(",");
				} else {
					csv.append(Double.NaN).append(",");
				}
			}
			csv.deleteCharAt(csv.length() - 1);
			return csv.toString();
		}
		// Check included features
		// Add time info: start and end time
		if (features.contains(FlowFeature.START_TIME.getId())) {
			csv.append(startTime).append(",");
		}
		if (features.contains(FlowFeature.END_TIME.getId())) {
			csv.append(lastSeen).append(",");
		}
		// Add first packet info
		if (features.contains(FlowFeature.ETH_SRC.getId())) {
			csv.append(firstPacket.getEthSrcString()).append(",");
		}
		if (features.contains(FlowFeature.ETH_DST.getId())) {
			csv.append(firstPacket.getEthDstString()).append(",");
		}
		if (features.contains(FlowFeature.VLAN_ID.getId())) {
			csv.append(firstPacket.getVlanId()).append(",");
		}
		if (features.contains(FlowFeature.ETH_TYPE.getId())) {
			csv.append(firstPacket.getEthType()).append(",");
		}
		if (features.contains(FlowFeature.IP_SRC.getId())) {
			csv.append(firstPacket.getIpSrcString()).append(",");
		}
		if (features.contains(FlowFeature.IP_DST.getId())) {
			csv.append(firstPacket.getIpDstString()).append(",");
		}
		if (features.contains(FlowFeature.IP_PROTO.getId())) {
			csv.append(firstPacket.getIpProto()).append(",");
		}
		if (features.contains(FlowFeature.PORT_SRC.getId())) {
			csv.append(firstPacket.getPortSrc()).append(",");
		}
		if (features.contains(FlowFeature.PORT_DST.getId())) {
			csv.append(firstPacket.getPortDst()).append(",");
		}
		// Add flow info: size, packets, duration, meanIAT, stdIAT, maxIAT, minIAT
		if (features.contains(FlowFeature.TOTAL_SIZE.getId())) {
			csv.append(packetSizes.getSum()).append(",");
		}
		if (features.contains(FlowFeature.TOTAL_PACKETS.getId())) {
			csv.append(packetSizes.getN()).append(",");
		}
		if (features.contains(FlowFeature.DURATION.getId())) {
			csv.append(lastSeen - startTime).append(",");
		}
		if (features.contains(FlowFeature.IAT_MEAN.getId())) {
			csv.append(packetIATs.getMean()).append(",");
		}
		if (features.contains(FlowFeature.IAT_STD.getId())) {
			csv.append(packetIATs.getStandardDeviation()).append(",");
		}
		if (features.contains(FlowFeature.IAT_MAX.getId())) {
			csv.append(packetIATs.getMax()).append(",");
		}
		if (features.contains(FlowFeature.IAT_MIN.getId())) {
			csv.append(packetIATs.getMin()).append(",");
		}
		// Add timeout info: prior timeouts and time after last timeout
		if (features.contains(FlowFeature.PRIOR_TOS.getId())) {
			csv.append(priorTOs).append(",");
		}
		if (features.contains(FlowFeature.TIME_LAST_TO.getId())) {
			csv.append(timeAfterLastTO).append(",");
		}
		// Add N first packet sizes
		if (features.contains(FlowFeature.PACKET_SIZE.getId())) {
			for (int i = 0; i < nFirstPackets; i++) {
				if (i < nFirstPacketSizes.size()) {
					csv.append(nFirstPacketSizes.get(i)).append(",");
				} else {
					csv.append(Double.NaN).append(",");
				}
			}
		}
		// Add N first packet inter-arrival times
		if (features.contains(FlowFeature.PACKET_IAT.getId())) {
			for (int i = 0; i < nFirstPackets; i++) {
				if (i < nFirstPacketIATs.size()) {
					csv.append(nFirstPacketIATs.get(i)).append(",");
				} else {
					csv.append(Double.NaN).append(",");
				}
			}
		}
		csv.deleteCharAt(csv.length() - 1);
		return csv.toString();
	}

}
