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
	 * Ethernet source address
	 */
	private byte[] ethSrc;
	
	/**
	 * Ethernet destination address
	 */
	private byte[] ethDst;
	
	/**
	 * Ethernet type
	 */
	private int ethType;
	
	/**
	 * VLAN identifier
	 */
	private int vlanId;
	
	/**
	 * IPv4/IPv6 source address
	 */
	private byte[] ipSrc;
	
	/**
	 * IPv4/IPv6 destination address
	 */
	private byte[] ipDst;
	
	/**
	 * IPv4 protocol
	 */
	private int ipProto;
	
	/**
	 * TCP/UDP source port
	 */
	private int portSrc;
	
	/**
	 * TCP/UDP destination port
	 */
	private int portDst;
	
	/**
	 * Start time in microseconds
	 */
	private long startTime;
	
	/**
	 * Last seen in microseconds
	 */
	private long lastSeen;

	/**
	 * Size in bytes
	 */
	private long size;
	
	/**
	 * Start of active time in microseconds
	 */
	private long startActiveTime;
	
	/**
	 * End of active time in microseconds
	 */
	private long endActiveTime;
	
	/**
	 * Lengths in bytes of the first N packets
	 */
	private List<Integer> packetLengths;
	
	/**
	 * Inter-arrival times in microseconds of the first N packets
	 */
	private List<Long> packetIATs;

}
