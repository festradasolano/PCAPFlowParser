# PCAPFlowParser
A parser for generating flow characteristics from PCAP files

Based on the ISCXFlowMeter project.

Features
 - No bidirectional
 - Timeouts entry in seconds
 - Length of packet on wire from captured header for obtaining the actual size of packet (solves the problem of getting the payload size from anonymized data since the payload has been removed from the captured packet) 
