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

import co.edu.unicauca.dtm.pcapflowparser.manager.PacketManager;

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
		String sFlowTimeout = "120";
		String sActivityTimeout = "10";
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
			sFlowTimeout = args[2];
			break;
		case 4:
			pcapPath = args[0];
			outPath = args[1];
			sFlowTimeout = args[2];
			sActivityTimeout = args[3];
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
				System.err.println("Output path " + outPath + " must point to a directory for the output files");
				System.exit(-1);
			}
		} else {
			outDir.mkdirs();
		}
		// Parse flow timeout to integer
		int flowTimeout;
		try {
			flowTimeout = Integer.parseInt(sFlowTimeout);
		} catch (Exception e) {
			flowTimeout = 120;
			System.err.println(
					"Error parsing flow timeout = " + sFlowTimeout + " to integer; using default value " + flowTimeout);
		}
		// Parse activity timeout to integer
		int activityTimeout;
		try {
			activityTimeout = Integer.parseInt(sActivityTimeout);
		} catch (Exception e) {
			activityTimeout = 10;
			System.err.println("Error parsing activity timeout = " + sActivityTimeout
					+ " to integer; using default value " + activityTimeout);
		}
		// Run PCAPFlowParser
		PCAPFlowParser parser = new PCAPFlowParser();
		parser.parsePCAP(pcapDir, outDir, flowTimeout, activityTimeout);
	}

	private void parsePCAP(File pcapDir, File outDir, int flowTimeout, int activityTimeout) {
		long start = System.currentTimeMillis();
		// Get the list of files in the PCAP directory
		int nFiles = pcapDir.list().length;
		System.out.println("Found " + nFiles + " files in " + pcapDir.getAbsolutePath());
		//
		int nParsedFiles = 0;
		int nErrorFiles = 0;
		for (File pcapFile : pcapDir.listFiles()) {
			System.out.println("Parsing file: " + pcapFile.getName());
			// Read and check PCAP file
			PacketManager packetMgr = new PacketManager();
			if (!packetMgr.config(pcapFile.getAbsolutePath())) {
				System.err.println("Error while opening file: " + pcapFile.getName());
				nErrorFiles++;
			} else {
				nParsedFiles++;
			}
		}
		long end = System.currentTimeMillis();
		// Report statistics
		System.out.println("Done! in " + ((end - start) / 1000.0) + " seconds.");
		System.out.println("PCAP files");
		System.out.println(" - Total = " + nFiles);
		System.out.println(" - Parse = " + nParsedFiles);
		System.out.println(" - Error = " + nErrorFiles);
	}

}
