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
	 * Total size in bytes
	 */
	private long totalSize;
	
	/**
	 * Maximum idle time
	 */
	private long maxIdleTime;
	
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
		totalSize = (long) firstPacket.getSize();
		maxIdleTime = firstPacket.getTimestamp() - lastSeen;
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
	 * @return the totalSize
	 */
	public long getTotalSize() {
		return totalSize;
	}

	/**
	 * @param totalSize the totalSize to set
	 */
	public void setTotalSize(long totalSize) {
		this.totalSize = totalSize;
	}
	
	/**
	 * @param packetSize
	 */
	public void sumUpPacketSize(int packetSize) {
		totalSize = totalSize + packetSize;
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
	 * @return the nFirstPacketSizes
	 */
	public List<Integer> getNFirstPacketSizes() {
		return nFirstPacketSizes;
	}
	
	/**
	 * @param nFirstPacketSizes the nFirstPacketSizes to set
	 */
	public void setNFirstPacketSizes(List<Integer> nFirstPacketSizes) {
		this.nFirstPacketSizes = nFirstPacketSizes;
	}
	
	/**
	 * @param packetSize
	 */
	public void addPacketSize(int packetSize) {
		nFirstPacketSizes.add(packetSize);
	}

	/**
	 * @return the packetIATs
	 */
	public List<Long> getNFirstPacketIATs() {
		return nFirstPacketIATs;
	}

	/**
	 * @param packetIATs the packetIATs to set
	 */
	public void setNFirstPacketIATs(List<Long> nFirstPacketIATs) {
		this.nFirstPacketIATs = nFirstPacketIATs;
	}
	
	/**
	 * @param packetTimestamp
	 */
	public void addPacketIAT(long iat) {
		nFirstPacketIATs.add(iat);
	}
	
	/**
	 * @return
	 */
	public int getNFirstPacketsAdded() {
		if (nFirstPacketSizes.size() >= nFirstPacketIATs.size()) {
			return nFirstPacketSizes.size();
		} else {
			return nFirstPacketIATs.size();
		}
	}

}
