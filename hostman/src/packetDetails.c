#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>

#include "cmdOptions.h"
#include "packetHeaders.h"
#include "miscFunctions.h"

#define PRINTINFO(str) printf("    |-%-25s: ", str)
#define PRINTFLAG(str) printf("    |-[Flag]-%-18s: ", str)

#define PRINTUINT8(num) printf("%" PRIu8 "\n", num)
#define PRINTUINT16(num) printf("%" PRIu16 "\n", num)
#define PRINTUINT32(num) printf("%" PRIu32 "\n", num),.

#define PRINTHEX8(num) printf("0x%02" PRIx8 "\n", num)
#define PRINTHEX16(num) printf("0x%04" PRIx16 "\n", num)
#define PRINTHEX32(num) printf("0x%08" PRIx32 "\n", num)

#define PRINTPORT(num) printf("%s (%" PRIu16 ")\n", determinePort(swap_uint16(num)), swap_uint16(num))

void packetDetails_ethernet(uint8_t *packetData);

void packetDetails_ip(uint8_t *packetData);
void packetDetails_arp(uint8_t *packetData);

void packetDetails_tcp(uint8_t *packetData);
void packetDetails_udp(uint8_t *packetData);

void packetDetails_data(uint8_t *packetData, int32_t length);

recHeaderStruct_t *recHeaderStruct;

// Packet header Variables
ethernetFrame_t *ethernetFrame;
ipHeader_t *ipHeader;
arpHeader_t *arpHeader;
tcpHeader_t *tcpHeader;
udpHeader_t *udpHeader;

/****************** ALL PACKET DETAILS ******************/
void allPacketDetails(FILE *fp)
{
	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	uint32_t counter = 0;

	while(fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(packetData, recHeaderStruct->inclLength, 1, fp);

		printf("-------------------[PACKET %" PRIu32 "]--------------------\n", ++counter);
		packetDetails_ethernet(packetData);
		putchar('\n');
	}

	free(packetData);
}

/****************** SELECTED PACKET DETAILS ******************/
void selectedPacketDetails(FILE *fp, uint32_t num)
{
	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	uint32_t i;

	for(i=0; i<num; i++){
		if(!fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){
			printf("No such packets exist\n");
			free(packetData);
			return;
		}

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		if(i != num-1) fseek(fp, recHeaderStruct->inclLength, SEEK_CUR);
	}
	fread(packetData, recHeaderStruct->inclLength, 1, fp);

	printf("-------------------[PACKET %" PRIu32 "]--------------------\n", num);
	packetDetails_ethernet(packetData);
	putchar('\n');

	free(packetData);
}

/****************** SELECTED PACKET DETAILS IN RANGE ******************/
void selectedPacketRangeDetails(FILE *fp, uint32_t num1, uint32_t num2)
{
	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	uint32_t i;

	for(i=0; i<num1-1; i++){
		if(!fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){
			printf("No such packets exist.\n");
			free(packetData);
			return;
		}

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fseek(fp, recHeaderStruct->inclLength, SEEK_CUR);
	}
	for(i=0; i<num2; i++){
		if(!fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){
			printf("No more packets to show.\n");
			free(packetData);
			return;
		}

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(packetData, recHeaderStruct->inclLength, 1, fp);

		printf("-------------------[PACKET %" PRIu32 "]--------------------\n", num1++);
		packetDetails_ethernet(packetData);
		putchar('\n');
	}

	free(packetData);
}

uint32_t i;	// loop variable

void packetDetails_ethernet(uint8_t *packetData)
{
	ethernetFrame = (ethernetFrame_t*) packetData;

	printf("Ethernet frame\n");

	PRINTINFO("Destination MAC");
	for(i=0; i<5; i++)
		printf("%02" PRIx8 ":", ethernetFrame->destinationMac[i]);
	printf("%02" PRIx8 "\n", ethernetFrame->destinationMac[5]);

	PRINTINFO("Source MAC");
	for(i=0; i<5; i++)
		printf("%02" PRIx8 ":", ethernetFrame->sourceMac[i]);
	printf("%02" PRIx8 "\n", ethernetFrame->sourceMac[5]);

	PRINTINFO("Type");
	printf("%s (0x%04" PRIx16 ")\n", determineEthernetProtocol(swap_uint16(ethernetFrame->type)), swap_uint16(ethernetFrame->type));

	switch(swap_uint16(ethernetFrame->type)){
		case 0x0800:	// IP protocol
			packetDetails_ip(packetData + ETHERNET_FRAME_LENGTH);
			break;
		case 0x0806:	// ARP protocol
			packetDetails_arp(packetData + ETHERNET_FRAME_LENGTH);
			break;
	}
}

/***************** Network Layer *****************/

void packetDetails_ip(uint8_t *packetData)
{
	printf("IP header \n");

	ipHeader = (ipHeader_t*)(packetData);

	PRINTINFO("Version");
	PRINTUINT8(ipHeader->version);

	PRINTINFO("Header length");
	PRINTUINT8(ipHeader->headerLength * 4);

	PRINTINFO("Type of service");
	PRINTHEX8(ipHeader->typeOfService);

	PRINTINFO("Total length");
	PRINTUINT16(swap_uint16(ipHeader->totalLength));

	PRINTINFO("Identification");
	printf("0x%04" PRIx16 " (%" PRIu16 ")\n", swap_uint16(ipHeader->identification), swap_uint16(ipHeader->identification));

	// Flags
	uint16_t flag = swap_uint16(ipHeader->flags);

	PRINTFLAG("Reserved bit");
	printf("%s\n", flagSetOrNot((flag & IP_reservedFlag) >> IP_reservedFlagPos));

	PRINTFLAG("Don't fragment");
	printf("%s\n", flagSetOrNot((flag & IP_dontFragment) >> IP_dontFragmentPos));

	PRINTFLAG("More fragments");
	printf("%s\n", flagSetOrNot((flag & IP_moreFragments) >> IP_moreFragmentsPos));

	PRINTFLAG("Fragment offset");
	PRINTHEX16(flag & IP_fragmentOffset);

	PRINTINFO("Time to live");
	PRINTUINT8(ipHeader->timeToLive);

	PRINTINFO("Protocol");
	printf("%s (%" PRIu8 ")\n", determineIpProtocol(ipHeader->protocol), ipHeader->protocol);

	PRINTINFO("Checksum");
	PRINTHEX16(swap_uint16(ipHeader->checksum));

	PRINTINFO("Source address");
	for(i=0; i<3; i++)
		printf("%" PRIu8 ".", ipHeader->sourceAddress[i]);
	printf("%" PRIu8 "\n", ipHeader->sourceAddress[3]);

	PRINTINFO("Destination address");
	for(i=0; i<3; i++)
		printf("%" PRIu8 ".", ipHeader->destinationAddress[i]);
	printf("%" PRIu8 "\n", ipHeader->destinationAddress[3]);

	uint8_t sizeOfIP = ipHeader->headerLength * 4;
	switch(ipHeader->protocol)
	{
		case 6:
			packetDetails_tcp(packetData + sizeOfIP);
			break;
		case 17:
			packetDetails_udp(packetData + sizeOfIP);
			break;
	}
}

void packetDetails_arp(uint8_t *packetData)
{
	arpHeader = (arpHeader_t*)(packetData);

	printf("ARP header \n");

	PRINTINFO("Hardware type");
	PRINTHEX16(swap_uint16(arpHeader->hardwareType));

	PRINTINFO("Protocol type");
	printf("%s (0x%04" PRIx16 ")\n", determineEthernetProtocol(swap_uint16(arpHeader->protocolType)), swap_uint16(arpHeader->protocolType));

	PRINTINFO("Hardware address length");
	PRINTUINT8(arpHeader->hwAddrLength);

	PRINTINFO("Protocol address length");
	PRINTUINT8(arpHeader->protoAddrLength);

	PRINTINFO("Opcode");
	PRINTUINT8(swap_uint16(arpHeader->opcode));

	PRINTINFO("Sender MAC");
	for(i=0; i<5; i++)
		printf("%02" PRIx8 ":", arpHeader->senderHwAddr[i]);
	printf("%02" PRIx8 "\n", arpHeader->senderHwAddr[5]);

	PRINTINFO("Sender IP");
	for(i=0; i<3; i++)
		printf("%" PRIu8 ".", arpHeader->senderIpAddr[i]);
	printf("%" PRIu8 "\n", arpHeader->senderIpAddr[3]);

	PRINTINFO("Target MAC");
	for(i=0; i<5; i++)
		printf("%02" PRIx8 ":", arpHeader->targetHwAddr[i]);
	printf("%02" PRIx8 "\n", arpHeader->targetHwAddr[5]);

	PRINTINFO("Target IP");
	for(i=0; i<3; i++)
		printf("%" PRIu8 ".", arpHeader->targetIpAddr[i]);
	printf("%" PRIu8 "\n", arpHeader->targetIpAddr[3]);
}

/************************ Transport Layer *************************/

void packetDetails_tcp(uint8_t *packetData)
{
	tcpHeader = (tcpHeader_t*)(packetData);

	printf("TCP header\n");

	PRINTINFO("Source port");
	PRINTPORT(tcpHeader->sourcePort);

	PRINTINFO("Destination port");
	PRINTPORT(tcpHeader->destinationPort);

	PRINTINFO("Sequence number");
	PRINTHEX32(swap_uint32(tcpHeader->sequenceNumber));

	PRINTINFO("Acknowledgement number");
	PRINTHEX32(swap_uint32(tcpHeader->acknowledgementNumber));

	// Flags
	uint16_t flag = swap_uint16(tcpHeader->flags);
	PRINTFLAG("Header length");
	PRINTUINT8(((flag & TCP_headerLength) >> TCP_headerLengthPos)*4);

	PRINTFLAG("Reserved");
	PRINTHEX16((flag & TCP_reserved) >> TCP_reservedPos);

	PRINTFLAG("URG");
	printf("%s\n", flagSetOrNot((flag & TCP_urg) >> TCP_urgPos));

	PRINTFLAG("ACK");
	printf("%s\n", flagSetOrNot((flag & TCP_ack) >> TCP_ackPos));

	PRINTFLAG("PSH");
	printf("%s\n", flagSetOrNot((flag & TCP_push) >> TCP_pushPos));

	PRINTFLAG("RST");
	printf("%s\n", flagSetOrNot((flag & TCP_reset) >> TCP_resetPos));

	PRINTFLAG("SYN");
	printf("%s\n", flagSetOrNot((flag & TCP_syn) >> TCP_synPos));

	PRINTFLAG("FIN");
	printf("%s\n", flagSetOrNot((flag & TCP_fin) >> TCP_synPos));

	PRINTINFO("Window size");
	PRINTUINT16(swap_uint16(tcpHeader->windowSize));

	PRINTINFO("Checksum");
	PRINTHEX16(swap_uint16(tcpHeader->checksum));

	PRINTINFO("Urgent pointer");
	PRINTUINT16(swap_uint16(tcpHeader->urgentPointer));

	packetDetails_data(packetData + TCP_LENGTH, (swap_uint16(ipHeader->totalLength) - (ipHeader->headerLength)*4 - TCP_LENGTH));
}

void packetDetails_udp(uint8_t *packetData)
{
	udpHeader = (udpHeader_t*)(packetData);

	printf("UDP header\n");

	PRINTINFO("Source port");
	PRINTPORT(udpHeader->sourcePort);

	PRINTINFO("Destination port");
	PRINTPORT(udpHeader->destinationPort);

	PRINTINFO("Length");
	PRINTUINT16(swap_uint16(udpHeader->length));

	PRINTINFO("Checksum");
	PRINTHEX16(swap_uint16(udpHeader->checksum));

	packetDetails_data(packetData + UDP_LENGTH, swap_uint16(udpHeader->length) - UDP_LENGTH);
}

/************************ Application layer *************************/
void packetDetails_data(uint8_t *packetData, int32_t length)
{
	if(length <= 0)
		return;

	printf("Packet data (Length: %d)\n    ", length);

	for(i=0; i<length; i++){
		if(i != 0 && i%64 == 0) printf("\n    ");
        printf("%c", isprint(*packetData) ? *packetData : '.');
        packetData++;
	}
	printf("\n");
}
