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
import java.io.FileOutputStream;
import java.io.IOException;
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

	/**
	 * 
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// Define default paths
		String pcapPath = System.getProperty("user.home") + File.separator + "pcap";
		String outPath = System.getProperty("user.home") + File.separator + "pcapflowparser";
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
		String pcapName = "";
		if (pcapFile.exists()) {
			// Get PCAP file/folder name; remove extension if exists
			if (pcapFile.getName().lastIndexOf(".") > 0) {
				pcapName = pcapFile.getName().substring(0, pcapFile.getName().lastIndexOf("."));
			} else {
				pcapName = pcapFile.getName();
			}
			// Add CSV extension to PCAP name
			pcapName = pcapName + ".csv";
		} else {
			System.out.println("PCAP path '" + pcapPath + "' does not exist");
			System.exit(1);
		}
		// Check if output path exists
		File outFile = new File(outPath);
		if (outFile.exists()) {
			if (outFile.isDirectory()) {
				System.out.println("Output path '" + outPath + "' points to an existing folder");
				System.out.println("Creating output file '" + pcapName + "' in this folder path");
				outFile = new File(outFile.getAbsolutePath() + File.separator + pcapName);
				if (outFile.exists()) {
					System.out.println("Overriding existing output file '" + outFile.getName() + "'");
					outFile.delete();
				}
				createFile(outFile);
			} else {
				System.out.println("Output path '" + outPath + "' points to an existing file");
				System.out.println("Overriding existing output file '" + outFile.getName() + "'");
				outFile.delete();
				createFile(outFile);
			}
		} else {
			System.out.println("Output path '" + outPath + "' does not exist");
			// Check if output path refers to a file
			if (outFile.getName().matches(".+\\..+")) {
				System.out.println("Handling output path '" + outPath + "' as a file");
				// Check if parent folder exists
				if (!outFile.getParentFile().exists()) {
					System.out.println("Creating output parent folder path '" + outFile.getParent() + "'");
					outFile.getParentFile().mkdirs();
				}
				System.out.println("Creating output file '" + outFile.getName() + "'");
				createFile(outFile);
			} else {
				System.out.println("Handling output path '" + outPath + "' as a folder");
				System.out.println("Creating output folder path '" + outFile.getAbsolutePath() + "'");
				outFile.mkdirs();
				System.out.println("Creating output file '" + pcapName + "' in this folder path");
				outFile = new File(outFile.getAbsolutePath() + File.separator + pcapName);
				createFile(outFile);
			}
		}
		// Parse flow active timeout to integer
		int flowActiveTimeout;
		try {
			flowActiveTimeout = Integer.parseInt(sFlowActiveTimeout);
		} catch (Exception e) {
			flowActiveTimeout = 0;
			System.out.println("Error parsing flow active timeout = " + sFlowActiveTimeout
					+ " to integer. Using default flow active timeout " + flowActiveTimeout + " seconds");
		}
		// Parse flow idle timeout to integer
		int flowIdleTimeout;
		try {
			flowIdleTimeout = Integer.parseInt(sFlowIdleTimeout);
		} catch (Exception e) {
			flowIdleTimeout = 0;
			System.out.println("Error parsing flow idle timeout = " + sFlowIdleTimeout
					+ " to integer. Using default flow idle timeout = " + flowIdleTimeout + " seconds");
		}
		// Parse initial packets to integer
		int nFirstPackets;
		try {
			nFirstPackets = Integer.parseInt(sNFirstPackets);
		} catch (Exception e) {
			nFirstPackets = 0;
			System.out.println("Error parsing number of initial packets = " + sNFirstPackets
					+ " to integer. Using default number of initial packets = " + nFirstPackets);
		}
		System.out.println("");
		// Run PCAPFlowParser
		PCAPFlowParser parser = new PCAPFlowParser();
		parser.parsePCAP(pcapFile, outFile, flowActiveTimeout, flowIdleTimeout, nFirstPackets);
	}

	/**
	 * Prints help
	 */
	private static void printHelp() {
		System.out.println("==============");
		System.out.println("PCAPFlowParser");
		System.out.println("==============");
		System.out.println("Options:");
		System.out.println("--pcap\t\tFile or folder that contains the captured packets in PCAP format.");
		System.out.println("--out\t\tFile or folder to output the results. If file, add the extension (e.g., .csv).");
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
	 * Creates a file. Exits if the program throws an error while creating the file
	 * 
	 * @param file
	 *            to create
	 */
	private static void createFile(File file) {
		try {
			file.createNewFile();
		} catch (IOException e) {
			System.err.println("Error creating file " + file.getAbsolutePath());
			System.exit(1);
		}
	}

	/**
	 * @param pcapFile
	 * @param outFile
	 * @param flowActiveTimeout
	 * @param flowIdleTimeout
	 * @param nFirstPackets
	 */
	private void parsePCAP(File pcapFile, File outFile, int flowActiveTimeout, int flowIdleTimeout, int nFirstPackets) {
		long start = System.currentTimeMillis();
		// Flow manager
		FlowManager flowManager = new FlowManager(outFile, flowActiveTimeout, flowIdleTimeout, nFirstPackets);
		;
		// Report parameters
		int nValidFiles = 0;
		int nErrorFiles = 0;
		long nPackets = 0;
		long nValidPackets = 0;
		long nErrorPackets = 0;
		// Get the PCAP files
		File[] pcapFiles = { pcapFile };
		if (pcapFile.isDirectory()) {
			pcapFiles = pcapFile.listFiles();
			Arrays.sort(pcapFiles);
			System.out.println(
					"Processing " + pcapFiles.length + " files in folder '" + pcapFile.getAbsolutePath() + "'");
		} else {
			System.out.println("Processing file '" + pcapFile.getAbsolutePath() + "'");
		}
		int nFiles = pcapFiles.length;
		for (File pcap : pcapFiles) {
			System.out.println("Parsing file: " + pcap.getName() + " ...");
			// Read and check PCAP file
			PacketManager packetMgr = new PacketManager();
			if (!packetMgr.config(pcap.getAbsolutePath())) {
				nErrorFiles++;
				System.err.println("Error while opening file: " + pcap.getName());
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
							System.out.println("\t... end of file: " + pcap.getName());
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
		// Generate report statistics
		long end = System.currentTimeMillis();
		StringBuilder report = new StringBuilder();
		report.append("======================\n");
		report.append("     FINAL REPORT     \n");
		report.append("======================\n");
		report.append("Done! in ").append((end - start) / 1000.0).append(" seconds\n");
		report.append("PCAP files").append("\n");
		report.append(" - Total = ").append(nFiles).append("\n");
		report.append(" - Valid = ").append(nValidFiles).append("\n");
		report.append(" - Error = ").append(nErrorFiles).append("\n");
		report.append("Packets").append("\n");
		report.append(" - Total = ").append(nPackets).append("\n");
		report.append(" - Valid = ").append(nValidPackets).append("\n");
		report.append(" - Error = ").append(nErrorPackets).append("\n");
		report.append("Flows").append("\n");
		report.append(" - Total = ").append(nFlows).append("\n");
		// Print report in console
		System.out.println("");
		System.out.println(report.toString());
		// Write report file
		String reportPath = outFile.getParent() + File.separator;
		if (outFile.getName().lastIndexOf(".") > 0) {
			reportPath += outFile.getName().substring(0, outFile.getName().lastIndexOf("."));
		} else {
			reportPath += outFile.getName();
		}
		reportPath += "_report.txt";
		File reportFile = new File(reportPath);
		if (reportFile.exists()) {
			reportFile.delete();
		}
		System.out.println("Writing report to " + reportFile.getAbsolutePath());
		try {
			FileOutputStream output = new FileOutputStream(reportFile);
			output.write(report.toString().getBytes());
			output.close();
		} catch (FileNotFoundException e1) {
			System.err.println("Internal error. File '" + reportFile.getAbsolutePath() + "' does not exist");
		} catch (IOException e) {
			System.err.println(
					"Internal error. Exception thrown when writing on the file '" + reportFile.getAbsolutePath() + "'");
		}
		
	}

}
