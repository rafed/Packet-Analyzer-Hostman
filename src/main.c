#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdOptions.h"
#include "packetHeaders.h"
#include "miscFunctions.h"

uint8_t globalHeader[24];
//Testting for commit

int main(int argc, char **argv)
{
	FILE *fp;

	if(argc == 1){
		printUsage();
	}
	else if(!checkExtension(argv[1])){
		printf("Provide a valid pcap file. \n");
	}
	else if((fp = fopen(argv[1], "rb"))==NULL){
		printf("Cannot open pcap file.\n");
	}
	else{
		fread(globalHeader, 24, 1, fp);
		if(argc == 2)
		{
			packetBasicInfo(fp);
		}
		else if(argc == 3)
		{
			if(!strcmp(argv[2], "-b")){
				packetBasicInfo(fp);
			}
			else if(!strcmp(argv[2], "-d")){
				allPacketDump(fp);
			}
			else if(!strcmp(argv[2], "-v")){
				allPacketDetails(fp);
			}
			else if(!strcmp(argv[2], "-ip")){
				ipSearch(fp);
			}
			else if(!strcmp(argv[2], "-t")){
				textSearch(fp);
			}
			else{
				invalidArguments();
			}
		}
		else if(argc == 4)
		{
			if(!strcmp(argv[2], "-d")){
				if(checkIfNumber(argv[3])){
					selectedPacketDump(fp, atoi(argv[3]));
				}
				else{
					invalidArguments();
				}
			}
			else if(!strcmp(argv[2], "-v")){
				if(checkIfNumber(argv[3])){
					selectedPacketDetails(fp, atoi(argv[3]));
				}
				else{
					invalidArguments();
				}
			}
			else if(!strcmp(argv[2], "-f")){
				if(checkIfNumber(argv[3])){
					followStream(fp, atoi(argv[3]));
				}
				else{
					invalidArguments();
				}
			}
			else{
				invalidArguments();
			}
		}
		else if(argc == 5)
		{
			if(!strcmp(argv[2], "-d")){
				if(checkIfNumber(argv[3]) && checkIfNumber(argv[4])){
					selectedPacketRangeDump(fp, atoi(argv[3]), atoi(argv[4]));
				}
				else{
					invalidArguments();
				}
			}
			else if(!strcmp(argv[2], "-v")){
				if(checkIfNumber(argv[3]) && checkIfNumber(argv[4])){
					selectedPacketRangeDetails(fp, atoi(argv[3]), atoi(argv[4]));
				}
				else{
					invalidArguments();
				}
			}
			else{
				invalidArguments();
			}
		}

		fclose(fp);
	}

	return 0;
}
