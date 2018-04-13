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
import java.util.Set;

import co.edu.unicauca.dtm.pcapflowparser.manager.FlowManager;
import co.edu.unicauca.dtm.pcapflowparser.manager.PacketManager;
import co.edu.unicauca.dtm.pcapflowparser.model.FlowFeature;
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
	 */
	private static final Map<String, Integer> options;
	static {
		options = new HashMap<String, Integer>();
		options.put("--help", 0);
		options.put("--pcap", 1);
		options.put("--out", 2);
		options.put("--activeTO", 3);
		options.put("--idleTO", 4);
		options.put("--nFirst", 5);
		options.put("--include", 6);
		options.put("--exclude", 7);
	}

	/**
	 * 
	 */
	private static final String FEATURE_ALL = "all";

	/**
	 * 
	 */
	private static final String FEATURE_NONE = "none";

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
		// Define default features to include and exclude
		String featureInclude = FEATURE_ALL;
		String featureExclude = FEATURE_NONE;
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
			case 6:
				featureInclude = args[i];
				if (featureInclude.equalsIgnoreCase(FEATURE_NONE)) {
					System.out.println("Value 'none' is not applicable to the option '--include'");
					printHelp();
					System.exit(1);
				}
				break;
			case 7:
				featureExclude = args[i];
				if (featureExclude.equalsIgnoreCase(FEATURE_ALL)) {
					System.out.println("Value 'all' is not applicable to the option '--exclude'");
					printHelp();
					System.exit(1);
				}
				break;
			default:
				System.err.println("Internal error. Option " + option + " is not implemented");
				System.exit(1);
				break;
			}
		}
		// Get features to include
		Set<Integer> features = null;
		if (featureInclude.equalsIgnoreCase(FEATURE_ALL)) {
			features = FlowFeature.allFeatureIds();
		} else {
			features = FlowFeature.featureIdByName(featureInclude);
			if (features == null) {
				System.out.println("A problem occurred while trying to get one of the included features in '"
						+ featureInclude + "'");
				printHelp();
				System.exit(1);
			}
		}
		// Get the features to exclude
		if (!featureExclude.equalsIgnoreCase(FEATURE_NONE)) {
			Set<Integer> excludeIds = FlowFeature.featureIdByName(featureExclude);
			if (excludeIds == null) {
				System.out.println("A problem occurred while trying to get one of the excluded features in '"
						+ featureExclude + "'");
				printHelp();
				System.exit(1);
			}
			for (int excludeId : excludeIds) {
				features.remove(excludeId);
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
		// ---------------------
		// Start parsing process
		long start = System.currentTimeMillis();
		// Flow manager
		FlowManager flowManager = new FlowManager(outFile, flowActiveTimeout, flowIdleTimeout, features, nFirstPackets);
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
		// Print report in console
		System.out.println("");
		System.out.println(report.toString());
	}

	/**
	 * Prints help
	 */
	private static void printHelp() {
		System.out.println("");
		System.out.println("==============");
		System.out.println("PCAPFlowParser");
		System.out.println("==============");
		System.out.println("Options:");
		System.out.println("  --help\tDisplay this help");
		System.out.println("  --pcap\tFile or folder that contains the captured packets in PCAP format");
		System.out.println("  --out\t\tFile or folder to output the results. If file, add the extension (e.g., .csv)");
		System.out.println(
				"  --activeTO\tTime in seconds after which an active flow is timed out anyway, even if there is still a continuous flow of packets");
		System.out.println(
				"  --idleTO\tTime in seconds after which an idle flow is timed out, i.e., if no packets belonging to the flow have been observed for the time specified");
		System.out.println(
				"  --nFirst\tNumber of first packets of a flow for generating the following features in the output results: packet size ('size_pkt') and packet IAT ('iat_pkt')");
		System.out.println(
				"  --include\tList of features to include in the output results separated by commas (see values below). Value 'none' is not applicable to this option");
		System.out.println(
				"  --exclude\tList of features to exclude in the output results separated by commas (see values below). Value 'all' is not applicable to this option");
		System.out.println("");
		System.out.println("Feature values for the options --include and --exclude:");
		System.out.println("  all\t\tAll available features. Can not be combined with other feature values");
		System.out.println("  none\t\tNone feature. Can not be combined with other feature values");
		System.out.println("  start_time\tFlow start time");
		System.out.println("  end_time\tFlow end time");
		System.out.println("  eth_src\tEthernet source address");
		System.out.println("  eth_dst\tEthernet destination address");
		System.out.println("  vlan_id\tVLAN identifier");
		System.out.println("  eth_type\tEthernet type");
		System.out.println("  ip_src\tIPv4/IPv6 source address");
		System.out.println("  ip_dst\tIPv4/IPv6 destination address");
		System.out.println("  ip_proto\tIP protocol number");
		System.out.println("  port_src\tTCP/UDP source port");
		System.out.println("  port_dst\tTCP/UDP destination port");
		System.out.println("  tot_size\tFlow total size (in bytes)");
		System.out.println("  tot_pkts\tFlow total number of packets");
		System.out.println("  duration\tFlow duration (in microseconds)");
		System.out.println("  iat_mean\tMean of flow inter-arrival time (in microseconds)");
		System.out.println("  iat_std\tStandard deviation of flow inter-arrival time (in microseconds)");
		System.out.println("  iat_max\tMaximum of flow inter-arrival time (in microseconds)");
		System.out.println("  iat_min\tMinimum of flow inter-arrival time (in microseconds)");
		System.out.println("  prior_tos\tNumber of previous timeouts");
		System.out.println("  time_last_to\tTime after the last timeout");
		System.out.println("  size_pkt\tPacket size of the --nFirst packets");
		System.out.println("  iat_pkt\tPacket inter-arrival time of the --nFirst packets");
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

}
