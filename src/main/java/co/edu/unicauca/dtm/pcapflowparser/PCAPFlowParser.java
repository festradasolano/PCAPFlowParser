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
import java.util.HashMap;
import java.util.Map;

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

	private static final Map<String, Integer> options;
	static {
		options = new HashMap<String, Integer>();
		options.put("--help", 0);
		options.put("--pcap", 1);
		options.put("--out", 2);
		options.put("--activeTO", 3);
		options.put("--idleTO", 4);
		options.put("--nFirst", 5);
	}

	private static void printHelp() {
		System.out.println("==============");
		System.out.println("PCAPFlowParser");
		System.out.println("==============");
		System.out.println("Options:");
		System.out.println("--pcap\t\tFile or directory that contains the captured packets in PCAP format.");
		System.out.println("--out\t\tFile or directory to output the results. If file, add the extension (e.g., .csv).");
		System.out.println(
				"--activeTO\tTime in seconds after which an active flow is timed out anyway, even if there is still a continuous flow of packets.");
		System.out.println(
				"--idleTO\tTime in seconds after which an idle flow is timed out, i.e., if no packets belonging to the flow have been observed for the time specified.");
		System.out.println(
				"--nFirst\tNumber of first packets of a flow for generating the following features in the output file: packet size ('size_pkt') and packet IAT ('iat_pkt').");
		System.out.println("--help\t\tDisplay this help.");
		System.out.println("\t\t");
	}

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
		String sNFirstPackets = "0";
		// Get parameters from arguments
		for (int i = 0; i < args.length; i++) {
			// Check that given option exists
			int option = 0;
			if (options.containsKey(args[i])) {
				option = options.get(args[i]);
				i++;
			} else {
				System.out.println("Option " + args[i] + " does not exist");
				printHelp();
				System.exit(1);
			}
			// Set parameter corresponding to option
			switch (option) {
			case 0:
				printHelp();
				System.exit(1);
				break;
			case 1:
				pcapPath = args[i];
				break;
			case 2:
				outPath = args[i];
				break;
			case 3:
				sFlowActiveTimeout = args[i];
				break;
			case 4:
				sFlowIdleTimeout = args[i];
				break;
			case 5:
				sNFirstPackets = args[i];
				break;
			default:
				System.err.println("Internal error. Option " + option + " is not implemented");
				System.exit(1);
				break;
			}
		}
		// Check if PCAP path exists
		File pcapFile = new File(pcapPath);
		if (!pcapFile.exists()) {
			System.err.println("PCAP path " + pcapPath + " does not exist");
			System.exit(1);
		}
		// Check or create output directory
		File outFile = new File(outPath);
		if (outFile.exists()) {
			if (!outFile.isDirectory()) {
				System.err.println("Output path " + outPath + " must point to a directory for the output file");
				System.exit(-1);
			}
		} else {
			outFile.mkdirs();
		}

		// Parse flow active timeout to integer
		int flowActiveTimeout;
		try {
			flowActiveTimeout = Integer.parseInt(sFlowActiveTimeout);
		} catch (Exception e) {
			flowActiveTimeout = 0;
			System.err.println("Error parsing flow active timeout = " + sFlowActiveTimeout
					+ " to integer. Using default flow active timeout " + flowActiveTimeout + " seconds");
		}
		// Parse flow idle timeout to integer
		int flowIdleTimeout;
		try {
			flowIdleTimeout = Integer.parseInt(sFlowIdleTimeout);
		} catch (Exception e) {
			flowIdleTimeout = 0;
			System.err.println("Error parsing flow idle timeout = " + sFlowIdleTimeout
					+ " to integer. Using default flow idle timeout = " + flowIdleTimeout + " seconds");
		}
		// Parse initial packets to integer
		int nFirstPackets;
		try {
			nFirstPackets = Integer.parseInt(sNFirstPackets);
		} catch (Exception e) {
			nFirstPackets = 0;
			System.err.println("Error parsing number of initial packets = " + sNFirstPackets
					+ " to integer. Using default number of initial packets = " + nFirstPackets);
		}
		// Run PCAPFlowParser
		PCAPFlowParser parser = new PCAPFlowParser();
		// parser.parsePCAP(pcapDir, outDir, flowActiveTimeout, flowIdleTimeout,
		// nFirstPackets);
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
