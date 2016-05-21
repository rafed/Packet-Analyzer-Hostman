#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

#include "cmdOptions.h"
#include "packetHeaders.h"
#include "miscFunctions.h"
#include "packetBasics.h"

char countArr[7];
char source[18];
char destination[18];
char protocol[8];
char length[5];

void packetBasicInfo(FILE *fp)
{
	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	recHeaderStruct_t *recHeaderStruct;

	uint32_t counter = 0;

	PRINTTOCONSOLE("No.", "Source", "Destination", "Protocol", "Length");
	while(fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(packetData, recHeaderStruct->inclLength, 1, fp);

		sprintf(countArr, "%d.", ++counter);
		basicInfo_ethernetFrame(packetData);
		sprintf(length, "%d", recHeaderStruct->inclLength);

		PRINTTOCONSOLE(countArr, source, destination, protocol, length);
	}

	free(packetData);
}

void basicInfo_ethernetFrame(uint8_t *packetData)
{
	ethernetFrame_t *ethernetFrame = (ethernetFrame_t*) packetData;

	switch(swap_uint16(ethernetFrame->type)){
		case 0x0806:	// ARP protocol
			basicInfo_arp(packetData);
			break;
		case 0x0800:	// IP protocol
			basicInfo_ip(packetData);
			break;
		case 0x86dd:
			sprintf(protocol, "IPv6");
			keepBlank();
			break;
		default:
			sprintf(protocol, "???");
			keepBlank();
			break;
	}
}

void basicInfo_arp(uint8_t *packetData)
{
	arpHeader_t *arpHeader = (arpHeader_t*) (packetData + ETHERNET_FRAME_LENGTH);

	PRINTMACTOARRAY(source, arpHeader->senderHwAddr);
	sprintf(destination, "Broadcast");

	sprintf(protocol, "ARP");
}

void basicInfo_ip(uint8_t *packetData)
{
	ipHeader_t *ipHeader = (ipHeader_t*) (packetData + ETHERNET_FRAME_LENGTH);

	PRINTIPTOARRAY(source, ipHeader->sourceAddress);
	PRINTIPTOARRAY(destination, ipHeader->destinationAddress);

	sprintf(protocol, "%s", determineIpProtocol(ipHeader->protocol));
}

void keepBlank()
{
	sprintf(destination, "--------------");
	sprintf(source, "--------------");
}
