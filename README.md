# PCAPFlowParser
A parser for generating flow characteristics from PCAP files

Based on the ISCXFlowMeter project.

Features
 - No bidirectional
 - Timeouts entry in seconds
 - Length of packet on wire from captured header for obtaining the actual size of packet (solves the problem of getting the payload size from anonymized data since the payload has been removed from the captured packet)
 - PCAP files should be in alphabetical order. Add the leading zeros to the left depending on the number of files, e.g., pcap001 instead of pcap1 

## Installation and execution

### Prerequisites

1. [Apache Maven](https://maven.apache.org/download.cgi)

1. Packet Capture (PCAP) libraries:

 - For Linux, install **libpcap**

    $ sudo apt-get install libpcap-dev

 - For Windows, install [WinPcap](https://www.winpcap.org/install/default.htm)

### Installation

Let's assume that:
 - The project `PCAPFlowParser` has been downloaded in `$PROJECT_PATH`.
 - The variable `$LINUX_WIN` represents the name of the operating system, namely, `linux` or `win`. 

Therefore, hereinafter, the variable `$JNETPCAP_HOME` refers to `$PROJECT_PATH/lib/jnetpcap-1.4.r1425/$LINUX_WIN`.

Following, the installation steps:

1. Add `jnetpcap` dependency to the local Maven repository by running the following command in `$JNETPCAP_HOME`:

    $ mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar

2. Setup native `jnetpcap` dynamically loadable variable:

 - On Unix systems, add environment variable `LD_LIBRARY_PATH=$JNETPCAP_HOME`.
 
 - On Win32 systems, add `$JNETPCAP_HOME` to the system `PATH` variable.

 - On IDEs (*e.g.*, Eclipse IDE), add JVM property `-Djava.library.path=$JNETPCAP_HOME`.

3. Generate the JAR executable file by running `$ mvn package` in `$PROJECT_PATH` (this step is not required for running the application from an IDE such as Eclipse)

### Execution

5. For terminal, mvn package and java -jar JAR_FILE *arguments

6. For Eclipse, establish arguments and run as Java app

7. If error persists, try adding $JNETPCAP_HOME to /etc/ld.so.conf.d/libjnetpcap.conf and run sudo ldconfig. Check that libraries are installed using ldconfig -p | grep jnet