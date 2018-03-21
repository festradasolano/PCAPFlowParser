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
 * This class models a packet.
 * 
 * Copyright 2018 Felipe Estrada-Solano <festradasolano at gmail>
 * 
 * Distributed under the Apache License, Version 2.0 (see LICENSE for details)
 * 
 * @author festradasolano
 */
public class Packet {

	/**
	 * Unknown, invalid, or non-applicable Ethernet address: 00:00:00:00:00:00
	 */
	public static final byte[] ETH_UNKNOWN = FormatUtils.toByteArray("000000000000");

	/**
	 * Unknown, invalid, or non-applicable IPv4 address: 0.0.0.0
	 */
	public static final byte[] IP_UNKNOWN = FormatUtils.toByteArray("00000000");

	/**
	 * Arrival time in microseconds
	 */
	private long timestamp;

	/**
	 * Size in bytes
	 */
	private int size;

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
	 * Constructor that initializes the parameters to zeros
	 */
	public Packet() {
		super();
		timestamp = 0;
		size = 0;
		ethSrc = Packet.ETH_UNKNOWN;
		ethDst = Packet.ETH_UNKNOWN;
		ethType = 0;
		vlanId = 0;
		ipSrc = Packet.IP_UNKNOWN;
		ipDst = Packet.IP_UNKNOWN;
		ipProto = 0;
		portSrc = 0;
		portDst = 0;
	}

	/**
	 * @return the arrival time in microseconds
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * @param timestamp
	 *            the arrival time in microseconds to set
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * @return the size in bytes
	 */
	public int getSize() {
		return size;
	}

	/**
	 * @param size
	 *            the size in bytes to set
	 */
	public void setSize(int size) {
		this.size = size;
	}

	/**
	 * @return the Ethernet source address in bytes
	 */
	public byte[] getEthSrc() {
		return ethSrc;
	}

	/**
	 * @return the Ethernet source address in hexadecimal notation
	 */
	public String getEthSrcHex() {
		return FormatUtils.mac(ethSrc);
	}

	/**
	 * @param ethSrc
	 *            the Ethernet source address in bytes to set
	 */
	public void setEthSrc(byte[] ethSrc) {
		this.ethSrc = ethSrc;
	}

	/**
	 * @return the Ethernet destination address in bytes
	 */
	public byte[] getEthDst() {
		return ethDst;
	}

	/**
	 * @return the Ethernet destination address in hexadecimal notation
	 */
	public String getEthDstHex() {
		return FormatUtils.mac(ethDst);
	}

	/**
	 * @param ethDst
	 *            the Ethernet destination address in bytes to set
	 */
	public void setEthDst(byte[] ethDst) {
		this.ethDst = ethDst;
	}

	/**
	 * @return the Ethernet type
	 */
	public int getEthType() {
		return ethType;
	}

	/**
	 * @param ethType
	 *            the Ethernet type to set
	 */
	public void setEthType(int ethType) {
		this.ethType = ethType;
	}

	/**
	 * @return the VLAN identifier
	 */
	public int getVlanId() {
		return vlanId;
	}

	/**
	 * @param vlanId
	 *            the VLAN identifier to set
	 */
	public void setVlanId(int vlanId) {
		this.vlanId = vlanId;
	}

	/**
	 * @return the IPv4/IPv6 source address in bytes
	 */
	public byte[] getIpSrc() {
		return ipSrc;
	}

	/**
	 * @return the IPv4/IPv6 source address in dot-decimal notation for IPv4 and in
	 *         hexadecimal notation for IPv6
	 */
	public String getIpSrcString() {
		return FormatUtils.ip(ipSrc);
	}

	/**
	 * @param ipSrc
	 *            the IPv4/IPv6 source address in bytes
	 */
	public void setIpSrc(byte[] ipSrc) {
		this.ipSrc = ipSrc;
	}

	/**
	 * @return the IPv4/IPv6 destination address in bytes
	 */
	public byte[] getIpDst() {
		return ipDst;
	}

	/**
	 * @return the IPv4/IPv6 destination address in dot-decimal notation for IPv4
	 *         and in hexadecimal notation for IPv6
	 */
	public String getIpDstString() {
		return FormatUtils.ip(ipDst);
	}

	/**
	 * @param ipDst
	 *            the IPv4/IPv6 destination address in bytes
	 */
	public void setIpDst(byte[] ipDst) {
		this.ipDst = ipDst;
	}

	/**
	 * @return the IPv4 protocol
	 */
	public int getIpProto() {
		return ipProto;
	}

	/**
	 * @param ipProto
	 *            the IPv4 protocol to set
	 */
	public void setIpProto(int ipProto) {
		this.ipProto = ipProto;
	}

	/**
	 * @return the TCP/UDP source port
	 */
	public int getPortSrc() {
		return portSrc;
	}

	/**
	 * @param portSrc
	 *            the TCP/UDP source port to set
	 */
	public void setPortSrc(int portSrc) {
		this.portSrc = portSrc;
	}

	/**
	 * @return the TCP/UDP destination port
	 */
	public int getPortDst() {
		return portDst;
	}

	/**
	 * @param portDst
	 *            the TCP/UDP destination port to set
	 */
	public void setPortDst(int portDst) {
		this.portDst = portDst;
	}

}
