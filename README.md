# Packet-Analyzer-Hostman

This contains the source code of a simple TCP/IP packet analyzer. Its properties are:

1. Coded in C
2. Will work for only UNIX systems (due to using console color in followPacketStream.c. Removing console color will make it work in windows) 
3. GCC compiler works fine. MinGW will casue problem as the function fmemopen(), used in miscFunctions.c is not supported by it
4. It does not capture packets. It only analyzes packets from a captured PCAP file
5. Command line driven program
6. Source code contains 12 files (8 .c files, 4 .h files) included with Makefile. See Source file explanation below to see the details of what each of them files does
7. Has options to view packet file data in several formats. 

Compile the file using the provided make.

# Source file explanation:
1. main.c: Checks for valid pcap file and valid cmd argument. If both are valid passes it to a function in other src file.
2. printUsage.c: Prints the usage (which commands invoke which functions)
3. miscFunctions.c: Contains miscellaneous functions that are required by the other source files
4. packetBasicInfo.c: Prints source ip, destination ip, protocol, and size of each packet
5. packetDetails.c: Prints the details of each packets (all info of all the fields including payload)
6. packetDump.c: Prints the hexdump of the packets along with their corresponding printable ASCII characters
7. packetSearch.c: Can search the PCAP file for packets by their IP or a string in their payload
8. followStream.c: Prints the conversation between two particular hosts in two different colors
