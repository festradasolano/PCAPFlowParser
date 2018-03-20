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

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import co.edu.unicauca.dtm.pcapflowparser.persistence.Packet;

/**
 * 
 * 
 * Copyright 2018 Felipe Estrada-Solano <festradasolano at gmail>
 * 
 * Distributed under the Apache License, Version 2.0 (see LICENSE for details)
 * 
 * @author festradasolano
 */
public class PacketManager {
	
	/**
	 * Reader of PCAP files
	 */
	private Pcap pcapReader;
	
	/**
	 * @param pcapFilePath
	 * @return
	 */
	public boolean config(String pcapFilePath) {
		// Read PCAP file
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		pcapReader = Pcap.openOffline(pcapFilePath, errbuf);
		if (pcapReader == null) {
			System.err.println("ERROR: " + errbuf);
			return false;
		}
		return true;
	}
	
	/**
	 * @return
	 */
	public Packet nextPacket() {
		PcapPacket readPacket = new PcapPacket(JMemory.POINTER);
		try {
			Packet packet = new Packet();
			// Read next available packet from libpcap
			if (pcapReader.nextEx(readPacket) == Pcap.NEXT_EX_OK) {
				PcapPacket pcapPacket = new PcapPacket(readPacket);
				// Timestamp and length
				packet.setTimestamp(pcapPacket.getCaptureHeader().timestampInMicros());
				packet.setLength(pcapPacket.getPacketWirelen());
				// Ethernet
				Ethernet eth = new Ethernet();
				if (pcapPacket.hasHeader(eth)) {
					packet.setEthSrc(eth.source());
					packet.setEthDst(eth.destination());
					packet.setEthType(eth.type());
				}
				// IEEE 802.1Q
				IEEE802dot1q dot1q = new IEEE802dot1q();
				if (pcapPacket.hasHeader(dot1q)) {
					packet.setVlanId(dot1q.id());
					packet.setEthType(dot1q.type());
				}
				// IPv4
				Ip4 ipv4 = new Ip4();
				if (pcapPacket.hasHeader(ipv4)) {
					packet.setIpSrc(ipv4.source());
					packet.setIpDst(ipv4.destination());
					packet.setIpProto(ipv4.type());
				}
				// IPv6
				Ip6 ipv6 = new Ip6();
				if (pcapPacket.hasHeader(ipv6)) {
					packet.setIpSrc(ipv6.source());
					packet.setIpDst(ipv6.destination());
				}
				// TCP
				Tcp tcp = new Tcp();
				if (pcapPacket.hasHeader(tcp)) {
					packet.setPortSrc(tcp.source());
					packet.setPortDst(tcp.destination());
				}
				// UDP
				Udp udp = new Udp();
				if (pcapPacket.hasHeader(udp)) {
					packet.setPortSrc(udp.source());
					packet.setPortDst(udp.destination());
				}
				return packet;
			} else {
				System.out.println("Read all packets from the current file!");
				return null;
			}
		} catch (PcapClosedException e) {
			System.out.println("Read all packets from the current file!");
			return null;
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

}
