#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdOptions.h"
#include "packetHeaders.h"
#include "miscFunctions.h"
#include "packetBasics.h"

void kmpSearch(uint8_t* data, int32_t dataLength, char* pattern);

char countArr[5];
char source[18];
char destination[18];
char protocol[8];
char length[5];

uint8_t found;

void ipSearch(FILE *fp)
{
	char ip[20];
	printf("Enter ip to search: ");
	scanf("%s", ip);

	if(!checkIP(ip)){
		printf("Wrong ip format.\n");
	}
	else{
		uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
		uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

		recHeaderStruct_t *recHeaderStruct;

		uint32_t counter = 0;
		found = 0;

		PRINTTOCONSOLE("No.", "Source", "Destination", "Protocol", "Length");
		while(fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){

			recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
			fread(packetData, recHeaderStruct->inclLength, 1, fp);

			sprintf(countArr, "%d.", ++counter);
			basicInfo_ethernetFrame(packetData);
			sprintf(length, "%d", recHeaderStruct->inclLength);

			if(!strcmp(ip, source) || !strcmp(ip, destination)){
				found = 1;
				PRINTTOCONSOLE(countArr, source, destination, protocol, length);
			}
		}

		if(!found){
			PRINTTOCONSOLE("--", "-------------", "-------------", "-------", "-------");
			printf("No such packets found.\n");
		}

		free(packetData);
	}
}

void textSearch(FILE *fp)
{
	char pattern[100];
	printf("Enter text to search: ");
	scanf("%s", pattern);

	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t* packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	recHeaderStruct_t *recHeaderStruct;

	PRINTTOCONSOLE("No.", "Source", "Destination", "Protocol", "Length");

	uint32_t counter = 0;
	found = 0;

	while(fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp)){
		counter++;

		uint8_t* tempPacketData = packetData;

		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(tempPacketData, recHeaderStruct->inclLength, 1, fp);

		ethernetFrame_t* ethernetFrame = (ethernetFrame_t*) tempPacketData;

		if(swap_uint16(ethernetFrame->type) == 0x0800 /*IP*/){
			tempPacketData += ETHERNET_FRAME_LENGTH;
			ipHeader_t* ipHeader = (ipHeader_t*)(tempPacketData);

			sprintf(countArr, "%d.", counter);
			PRINTIPTOARRAY(source, ipHeader->sourceAddress);
			PRINTIPTOARRAY(destination, ipHeader->destinationAddress);
			sprintf(protocol, "%s", determineIpProtocol(ipHeader->protocol));
			sprintf(length, "%d", recHeaderStruct->inclLength);

			uint16_t sizeOfIP = ipHeader->headerLength * 4;
			int32_t payloadLength;

			tempPacketData += sizeOfIP;
			if(ipHeader->protocol == 6){	// TCP
				//tcpHeader_t* tcpHeader = (tcpHeader_t*)(packetData);
				payloadLength = (swap_uint16(ipHeader->totalLength) - (ipHeader->headerLength)*4 - TCP_LENGTH);

				kmpSearch(tempPacketData + TCP_LENGTH, payloadLength, pattern);
			}
			else if(ipHeader->protocol == 17){	//UDP
				udpHeader_t* udpHeader = (udpHeader_t*)(tempPacketData);
				payloadLength = (swap_uint16(udpHeader->length) - UDP_LENGTH);

				kmpSearch(tempPacketData + UDP_LENGTH, payloadLength, pattern);
			}
		}
	}

	free(packetData);

	if(!found){
		PRINTTOCONSOLE("--", "-------------", "-------------", "-------", "-------");
		printf("No such packets found.\n");
	}
}

void kmpSearch(uint8_t *data, int32_t dataLength, char *pattern)
{
	if(dataLength <= 0) return;

	int32_t i, matched;

    uint32_t patternLength = strlen(pattern);

    /// Construct the lookup table
    uint32_t table[patternLength];

    table[0] = -1;
	matched = -1;

    for(i=1; i<patternLength; i++) {
        while(matched > -1 && pattern[matched+1] != pattern[i])
			matched = table[matched];
		if(table[matched+1] == table[i])
			matched++;
		table[i] = matched;
    }

    /// Perform the search
    matched = -1;
    for(i=0; i<dataLength; i++)
    {
    	while(matched>-1 && pattern[matched+1] != data[i])
			matched = table[matched];

		if(data[i] == pattern[matched+1])
			matched++;
		if(matched == patternLength-1){
			found = 1;
			PRINTTOCONSOLE(countArr, source, destination, protocol, length);
			break;
		}
    }
}
