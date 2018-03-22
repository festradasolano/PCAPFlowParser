# PCAPFlowParser
A parser for generating flow characteristics from PCAP files

Based on the ISCXFlowMeter project.

Features
 - No bidirectional
 - Timeouts entry in seconds
 - Length of packet on wire from captured header for obtaining the actual size of packet (solves the problem of getting the payload size from anonymized data since the payload has been removed from the captured packet) 

Steps:
1. Install libpcap-dev (sudo apt-get install libpcap-dev)

2. //linux :at the pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425
//windows: at the pathtoproject/jnetpcap/win/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar

3. For terminal, add variable LD_LIBRARY_PATH=$JNETPCAP_HOME

4. For Eclipse, add JVM property -Djava.library.path=$JNETPCAP_HOME

5. For terminal, mvn package and java -jar JAR_FILE *arguments

6. For Eclipse, establish arguments and run as Java app

7. If error persists, try adding $JNETPCAP_HOME to /etc/ld.so.conf.d/libjnetpcap.conf and run sudo ldconfig. Check that libraries are installed using ldconfig -p | grep jnet