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
	 * Total length in bytes
	 */
	private long totalLength;
	
	/**
	 * Maximum idle time
	 */
	private long maxIdleTime;
	
	/**
	 * Lengths in bytes of the first N packets
	 */
	private List<Integer> packetLengths;
	
	/**
	 * Inter-arrival times in microseconds of the first N packets
	 */
	private List<Long> packetIATs;
	
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
		totalLength = (long) firstPacket.getLength();
		maxIdleTime = firstPacket.getTimestamp() - lastSeen;
		packetLengths = new ArrayList<Integer>();
		packetLengths.add(firstPacket.getLength());
		packetIATs = new ArrayList<Long>();
		packetIATs.add(firstPacket.getTimestamp() - lastSeen);
	}

	/**
	 * @return the firstPacket
	 */
	public Packet getFirstPacket() {
		return firstPacket;
	}

	/**
	 * @param firstPacket the firstPacket to set
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
	 * @param startTime the startTime to set
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
	 * @param lastSeen the lastSeen to set
	 */
	public void setLastSeen(long lastSeen) {
		this.lastSeen = lastSeen;
	}

	/**
	 * @return the totalLength
	 */
	public long getTotalLength() {
		return totalLength;
	}

	/**
	 * @param totalLength the totalLength to set
	 */
	public void setTotalLength(long totalLength) {
		this.totalLength = totalLength;
	}
	
	/**
	 * @param packetLength
	 */
	public void sumUpPacketLength(int packetLength) {
		totalLength = totalLength + packetLength;
	}

	/**
	 * @return the maxIdleTime
	 */
	public long getMaxIdleTime() {
		return maxIdleTime;
	}

	/**
	 * @param maxIdleTime the maxIdleTime to set
	 */
	public void setMaxIdleTime(long maxIdleTime) {
		this.maxIdleTime = maxIdleTime;
	}
	
	/**
	 * @param packetIAT
	 */
	public void checkUpdateMaxIdleTime(long packetIAT) {
		if (packetIAT > maxIdleTime) {
			maxIdleTime = packetIAT;
		}
	}

	/**
	 * @return the packetLengths
	 */
	public List<Integer> getPacketLengths() {
		return packetLengths;
	}

	/**
	 * @param packetLengths the packetLengths to set
	 */
	public void setPacketLengths(List<Integer> packetLengths) {
		this.packetLengths = packetLengths;
	}
	
	/**
	 * @param packetLength
	 */
	public void addPacketLength(int packetLength) {
		packetLengths.add(packetLength);
	}

	/**
	 * @return the packetIATs
	 */
	public List<Long> getPacketIATs() {
		return packetIATs;
	}

	/**
	 * @param packetIATs the packetIATs to set
	 */
	public void setPacketIATs(List<Long> packetIATs) {
		this.packetIATs = packetIATs;
	}
	
	/**
	 * @param packetTimestamp
	 */
	public void addPacketIAT(long iat) {
		packetIATs.add(iat);
	}

}
