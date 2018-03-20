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

import org.jnetpcap.packet.format.FormatUtils;

/**
 * 
 * 
 * Copyright 2018 Felipe Estrada-Solano <festradasolano at gmail>
 * 
 * Distributed under the Apache License, Version 2.0 (see LICENSE for details)
 * 
 * @author festradasolano
 */
public class Packet {

	/**
	 * Arrival time in microseconds
	 */
	private long timestamp;
	
	/**
	 * Length on wire in bytes
	 */
	private int length;
	
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
	 * Constructor that generates the identifier of the packet
	 */
	public Packet() {
		super();
		timestamp = 0;
		length = 0;
		ethSrc = FormatUtils.toByteArray("000000000000");
		ethDst = FormatUtils.toByteArray("000000000000");
		ethType = 0;
		vlanId = 0;
		ipSrc = FormatUtils.toByteArray("00000000");
		ipDst = FormatUtils.toByteArray("00000000");
		ipProto = 0;
		portSrc = 0;
		portDst = 0;
	}

	/**
	 * @return the timestamp
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * @param timestamp the timestamp to set
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * @return the length
	 */
	public int getLength() {
		return length;
	}

	/**
	 * @param length the length to set
	 */
	public void setLength(int length) {
		this.length = length;
	}

	/**
	 * @return the ethSrc
	 */
	public byte[] getEthSrc() {
		return ethSrc;
	}
	
	/**
	 * @param ethSrc the ethSrc to set
	 */
	public void setEthSrc(byte[] ethSrc) {
		this.ethSrc = ethSrc;
	}

	/**
	 * @return the ethDst
	 */
	public byte[] getEthDst() {
		return ethDst;
	}

	/**
	 * @param ethDst the ethDst to set
	 */
	public void setEthDst(byte[] ethDst) {
		this.ethDst = ethDst;
	}

	/**
	 * @return the ethType
	 */
	public int getEthType() {
		return ethType;
	}

	/**
	 * @param ethType the ethType to set
	 */
	public void setEthType(int ethType) {
		this.ethType = ethType;
	}

	/**
	 * @return the vlanId
	 */
	public int getVlanId() {
		return vlanId;
	}

	/**
	 * @param vlanId the vlanId to set
	 */
	public void setVlanId(int vlanId) {
		this.vlanId = vlanId;
	}

	/**
	 * @return the ipSrc
	 */
	public byte[] getIpSrc() {
		return ipSrc;
	}

	/**
	 * @param ipSrc the ipSrc to set
	 */
	public void setIpSrc(byte[] ipSrc) {
		this.ipSrc = ipSrc;
	}

	/**
	 * @return the ipDst
	 */
	public byte[] getIpDst() {
		return ipDst;
	}

	/**
	 * @param ipDst the ipDst to set
	 */
	public void setIpDst(byte[] ipDst) {
		this.ipDst = ipDst;
	}

	/**
	 * @return the ipProto
	 */
	public int getIpProto() {
		return ipProto;
	}

	/**
	 * @param ipProto the ipProto to set
	 */
	public void setIpProto(int ipProto) {
		this.ipProto = ipProto;
	}

	/**
	 * @return the portSrc
	 */
	public int getPortSrc() {
		return portSrc;
	}

	/**
	 * @param portSrc the portSrc to set
	 */
	public void setPortSrc(int portSrc) {
		this.portSrc = portSrc;
	}

	/**
	 * @return the portDst
	 */
	public int getPortDst() {
		return portDst;
	}

	/**
	 * @param portDst the portDst to set
	 */
	public void setPortDst(int portDst) {
		this.portDst = portDst;
	}
	
}
