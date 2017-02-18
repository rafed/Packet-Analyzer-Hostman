#ifndef OPTIONS_H_INCLUDED
#define OPTIONS_H_INCLUDED

#include <inttypes.h>
#include <stdio.h>

void printUsage();															/// ./Hostman

void packetBasicInfo(FILE *fp);												/// ./Hostman file.pcap -b

void allPacketDump(FILE *fp);												/// ./Hostman file.pcap -d
void selectedPacketDump(FILE *fp, uint32_t num);							/// ./Hostman file.pcap -d num
void selectedPacketRangeDump(FILE *fp, uint32_t num1, uint32_t num2);		///./Hostman file.pcap -v num1 num2

void allPacketDetails(FILE *fp);											/// ./Hostman file.pcap -v
void selectedPacketDetails(FILE *fp, uint32_t num);							/// ./Hostman file.pcap -v num
void selectedPacketRangeDetails(FILE *fp, uint32_t num1, uint32_t num2);	/// ./Hostman file.pcap -v num1 num2

void ipSearch(FILE *fp);													/// ./Hostman file.pcap -ip
void textSearch(FILE *fp);													/// ./Hostman file.pcap -t

void followStream(FILE *fp, uint32_t num);									/// ./Hostman file.pcap -f num

#endif // OPTIONS_H_INCLUDED
