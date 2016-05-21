# Packet-Analyzer-Hostman

Compile the file using make.

Description of source files:

1. main.c
Checks for valid pcap file and valid cmd argument. If both are valid passes it to a function in other src file.

2. printUsage.c
Prints the usage (which commands invoke which functions)

3. miscFunctions.c
Contains miscellaneous functions that are required by the other source files

4. packetBasicInfo.c
Prints source ip, destination ip, protocol, and size of each packet

5. packetDetails.c
Prints the details of each packets (all info of all the fields including payload)

6. packetDump.c
Prints the hexdump of the packets along with their corresponding printable ASCII characters

7. packetSearch.c
Can search the PCAP file for packets by their IP or a string in their payload

8. followStream.c
Prints the conversation between two particular hosts in two different colors
