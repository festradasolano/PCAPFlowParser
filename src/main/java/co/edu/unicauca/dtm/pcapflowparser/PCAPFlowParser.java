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

package co.edu.unicauca.dtm.pcapflowparser;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;

import co.edu.unicauca.dtm.pcapflowparser.manager.FlowManager;
import co.edu.unicauca.dtm.pcapflowparser.manager.PacketManager;
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
public class PCAPFlowParser {

	/**
	 * 
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// Define default paths
		String pcapPath = "/pcap/";
		String outPath = "/out/";
		// Define default timeouts in seconds
		String sFlowActiveTimeout = "0";
		String sFlowIdleTimeout = "0";
		// Define default number of first packets to collect info
		String sNFirstPackets = "10";
		// Get arguments
		switch (args.length) {
		case 1:
			pcapPath = args[0];
			break;
		case 2:
			pcapPath = args[0];
			outPath = args[1];
			break;
		case 3:
			pcapPath = args[0];
			outPath = args[1];
			sFlowActiveTimeout = args[2];
			break;
		case 4:
			pcapPath = args[0];
			outPath = args[1];
			sFlowActiveTimeout = args[2];
			sFlowIdleTimeout = args[3];
			break;
		case 5:
			pcapPath = args[0];
			outPath = args[1];
			sFlowActiveTimeout = args[2];
			sFlowIdleTimeout = args[3];
			sNFirstPackets = args[4];
			break;
		}
		// Check if PCAP path exists and is a directory
		File pcapDir = new File(pcapPath);
		if (!pcapDir.exists()) {
			System.err.println("PCAP path " + pcapPath + " does not exist");
			System.exit(-1);
		}
		if (!pcapDir.isDirectory()) {
			System.err.println("PCAP path " + pcapPath + " must point to a directory that contains the PCAP files");
			System.exit(-1);
		}
		// Check or create output directory
		File outDir = new File(outPath);
		if (outDir.exists()) {
			if (!outDir.isDirectory()) {
				System.err.println("Output path " + outPath + " must point to a directory for the output file");
				System.exit(-1);
			}
		} else {
			outDir.mkdirs();
		}
		// Parse flow active timeout to integer
		int flowActiveTimeout;
		try {
			flowActiveTimeout = Integer.parseInt(sFlowActiveTimeout);
		} catch (Exception e) {
			flowActiveTimeout = 60;
			System.err.println("Error parsing flow active timeout = " + sFlowActiveTimeout
					+ " to integer. Using default flow active timeout " + flowActiveTimeout + " seconds");
		}
		// Parse flow idle timeout to integer
		int flowIdleTimeout;
		try {
			flowIdleTimeout = Integer.parseInt(sFlowIdleTimeout);
		} catch (Exception e) {
			flowIdleTimeout = 60;
			System.err.println("Error parsing flow idle timeout = " + sFlowIdleTimeout
					+ " to integer. Using default flow idle timeout = " + flowIdleTimeout + " seconds");
		}
		// Parse initial packets to integer
		int nFirstPackets;
		try {
			nFirstPackets = Integer.parseInt(sNFirstPackets);
		} catch (Exception e) {
			nFirstPackets = 10;
			System.err.println("Error parsing number of initial packets = " + sNFirstPackets
					+ " to integer. Using default number of initial packets = " + nFirstPackets);
		}
		// Run PCAPFlowParser
		PCAPFlowParser parser = new PCAPFlowParser();
		parser.parsePCAP(pcapDir, outDir, flowActiveTimeout, flowIdleTimeout, nFirstPackets);
	}

	private void parsePCAP(File pcapDir, File outDir, int flowActiveTimeout, int flowIdleTimeout, int nFirstPackets) {
		long start = System.currentTimeMillis();
		// Get the list of files in the PCAP directory
		int nFiles = pcapDir.list().length;
		System.out.println("Found " + nFiles + " files in " + pcapDir.getAbsolutePath());
		// Flow manager
		FlowManager flowManager;
		try {
			flowManager = new FlowManager(pcapDir.getName(), outDir.getAbsolutePath(), flowActiveTimeout,
					flowIdleTimeout, nFirstPackets);
		} catch (FileNotFoundException e) {
			System.err.println("Error creating CSV file writer");
			return;
		}
		// Report parameters
		int nValidFiles = 0;
		int nErrorFiles = 0;
		long nPackets = 0;
		long nValidPackets = 0;
		long nErrorPackets = 0;
		// Sort PCAP files and read each one
		File[] pcapFiles = pcapDir.listFiles();
		Arrays.sort(pcapFiles);
		for (File pcapFile : pcapFiles) {
			System.out.println("Parsing file: " + pcapFile.getName() + " ...");
			// Read and check PCAP file
			PacketManager packetMgr = new PacketManager();
			if (!packetMgr.config(pcapFile.getAbsolutePath())) {
				nErrorFiles++;
				System.err.println("Error while opening file: " + pcapFile.getName());
			} else {
				nValidFiles++;
				while (true) {
					// Read next packet and check validity
					Packet packet = packetMgr.nextPacket();
					if (packet == null) {
						nErrorPackets++;
					} else {
						// Check end of file
						if (packet.getTimestamp() == -1) {
							System.out.println("\t... end of file: " + pcapFile.getName());
							break;
						}
						nValidPackets++;
						// Process packet in terms of flows
						flowManager.addPacket(packet);
					}
					nPackets++;
				}
			}
		}
		// Dump last flows
		long nFlows = flowManager.dumpLastFlows();
		// Report statistics
		long end = System.currentTimeMillis();
		System.out.println("======================");
		System.out.println("     FINAL REPORT     ");
		System.out.println("======================");
		System.out.println("Done! in " + ((end - start) / 1000.0) + " seconds");
		System.out.println("PCAP files");
		System.out.println(" - Total = " + nFiles);
		System.out.println(" - Valid = " + nValidFiles);
		System.out.println(" - Error = " + nErrorFiles);
		System.out.println("Packets");
		System.out.println(" - Total = " + nPackets);
		System.out.println(" - Valid = " + nValidPackets);
		System.out.println(" - Error = " + nErrorPackets);
		System.out.println("Flows");
		System.out.println(" - Total = " + nFlows);
	}

}
