#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "cmdOptions.h"
#include "packetHeaders.h"
#include "miscFunctions.h"
#include "packetBasics.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

ethernetFrame_t *ethernetFrame;
ipHeader_t *ipHeader;
tcpHeader_t *tcpHeader;
udpHeader_t *udpHeader;

uint8_t sizeOfIP;

char sourceIP[18], destIP[18];
uint16_t sourcePort, destPort;

char tempSourceIP[18], tempDestIP[18];
uint16_t tempSourcePort, tempDestPort;

uint32_t conversationLength;
int32_t payloadLength;

void printStream(uint8_t *packetData, int32_t length, char* color);

void followStream(FILE *fp, uint32_t num)
{
	int64_t fileLocation = ftell(fp);

	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	recHeaderStruct_t *recHeaderStruct;

	uint32_t i;		// loop variable

	for(i=0; i<num; i++){
		if(!fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){
			printf("No such packets exist.\n");
			return;
		}
		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(packetData, recHeaderStruct->inclLength, 1, fp);
	}

	/************************************************************/
	/** Found the reference packet, now save its ips and ports **/
	/************************************************************/

	ethernetFrame = (ethernetFrame_t*) packetData;
	if(swap_uint16(ethernetFrame->type) != 0x0800){
		printf("Cannot follow streams of such packets. Only TCP and UDP can be followed.\n");
		return;
	}

	ipHeader = (ipHeader_t*) (packetData + ETHERNET_FRAME_LENGTH);

	PRINTIPTOARRAY(sourceIP, ipHeader->sourceAddress);
	PRINTIPTOARRAY(destIP, ipHeader->destinationAddress);

	if(ipHeader->protocol == 6){
		tcpHeader = (tcpHeader_t*) (packetData + ETHERNET_FRAME_LENGTH + (ipHeader->headerLength)*4);

		sourcePort = tcpHeader->sourcePort;
		destPort = tcpHeader->destinationPort;
	}
	else if (ipHeader->protocol == 17){
		udpHeader = (udpHeader_t*) (packetData + ETHERNET_FRAME_LENGTH + (ipHeader->headerLength)*4);

		sourcePort = udpHeader->sourcePort;
		destPort = udpHeader->destinationPort;
	}
	else {
		printf("Cannot follow streams of such packets. Only TCP and UDP are followable.\n");
		return;
	}

	/******************************************************************/
	/** Search for the packets involved in the stream and print them **/
	/******************************************************************/
	fseek(fp, fileLocation, SEEK_SET);

	while(fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){
		uint8_t* tempPacketData = packetData;

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(tempPacketData, recHeaderStruct->inclLength, 1, fp);

		ethernetFrame = (ethernetFrame_t*) tempPacketData;

		if(swap_uint16(ethernetFrame->type) != 0x800){
			continue;
		}

		ipHeader = (ipHeader_t*) (tempPacketData + ETHERNET_FRAME_LENGTH);

		PRINTIPTOARRAY(tempSourceIP, ipHeader->sourceAddress);
		PRINTIPTOARRAY(tempDestIP, ipHeader->destinationAddress);

		if(ipHeader->protocol == 6){
			tcpHeader = (tcpHeader_t*) (tempPacketData + ETHERNET_FRAME_LENGTH + (ipHeader->headerLength)*4);

			tempSourcePort = tcpHeader->sourcePort;
			tempDestPort = tcpHeader->destinationPort;

			tempPacketData  = tempPacketData + ETHERNET_FRAME_LENGTH + (ipHeader->headerLength)*4 + TCP_LENGTH;
			payloadLength = (swap_uint16(ipHeader->totalLength) - (ipHeader->headerLength)*4 - TCP_LENGTH);
		}
		else if (ipHeader->protocol == 17){
			udpHeader = (udpHeader_t*) (tempPacketData + ETHERNET_FRAME_LENGTH + (ipHeader->headerLength)*4);

			tempSourcePort = udpHeader->sourcePort;
			tempDestPort = udpHeader->destinationPort;

			tempPacketData  = tempPacketData + ETHERNET_FRAME_LENGTH + (ipHeader->headerLength)*4 + UDP_LENGTH;
			payloadLength = swap_uint16(udpHeader->length) - UDP_LENGTH;
		}
		else {
			continue;
		}

		/** Condition if its a part of the stream **/
		if(!strcmp(sourceIP, tempSourceIP) && sourcePort == tempSourcePort){
			if(!strcmp(destIP, tempDestIP) && destPort == tempDestPort){
				printStream(tempPacketData, payloadLength, KBLU);
			}
		}
		else if(!strcmp(sourceIP, tempDestIP) && sourcePort == tempDestPort){
			if(!strcmp(destIP, tempSourceIP) && destPort == tempSourcePort){
				printStream(tempPacketData, payloadLength, KMAG);
			}
		}
	}

	free(packetData);

	printf("\nEntire conversation: %" PRIu32 " bytes.\n", conversationLength);
}

void printStream(uint8_t *packetData, int32_t length, char* color)
{
	if(length <= 0)
		return;

	conversationLength += length;

	uint32_t i;

	printf("%s\n", color);

	for(i=0; i<length; i++){
        printf("%c", isPrintNewline(*packetData) ? *packetData : '.');
        packetData++;
	}
	printf("%s\n", KNRM);
}
