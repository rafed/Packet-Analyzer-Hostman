#include <stdio.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>

#include "cmdOptions.h"
#include "packetHeaders.h"

void dump(uint8_t* packetData, uint32_t length);

uint32_t count = 0;

recHeaderStruct_t *recHeaderStruct;

/****************** All PACKET DUMP ******************/
void allPacketDump(FILE *fp)
{
	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	while(fread(recordHeaderArray, RECORD_HEADER_LENGTH, 1, fp))
	{
		recHeaderStruct = (recHeaderStruct_t*) recordHeaderArray;
		fread(packetData, recHeaderStruct->inclLength, 1, fp);

		printf("\nPacket %" PRIu8 ":\n", ++count);
		dump(packetData, recHeaderStruct->inclLength);
	}

	free(packetData);

	printf("\n");
}

/****************** SELECTED PACKET DUMP ******************/
void selectedPacketDump(FILE* fp, uint32_t num)
{
	uint8_t recordHeaderArray[RECORD_HEADER_LENGTH];
	uint8_t *packetData = (uint8_t*) malloc(MAX_PACKET_SIZE);

	uint32_t i;	// loop variable

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

	printf("\nPacket %" PRIu8 ":\n", num);
	dump(packetData, recHeaderStruct->inclLength);

	free(packetData);

	printf("\n");
}

/****************** DUMP IN RANGE ******************/
void selectedPacketRangeDump(FILE *fp, uint32_t num1, uint32_t num2)
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

		printf("\nPacket %" PRIu8 ":\n", num1++);
		dump(packetData, recHeaderStruct->inclLength);

		putchar('\n');
	}

	free(packetData);
}

uint32_t i, j, k;	// loop variables

void dump(uint8_t* packetData, uint32_t length)
{
	for(i=0; i<length; i+=16){
		for(j=i, k=0; j<length && k<16; j++, k++){
			if(k != 0 && k%8 == 0) printf(" ");
			printf("%02" PRIx8 " ", packetData[j]);
		}

		if(k%16 != 0){
			for(j=0; j< (16-k)*3; j++)
				putchar(' ');
		}
		putchar('\t');

		for(j=i, k=0; j<length && k<16; j++, k++){
			if(k != 0 && k%8 == 0) printf(" ");
			printf("%c", isprint(packetData[j]) ? packetData[j] : '.');
		}
		printf("\n");
	}
}
