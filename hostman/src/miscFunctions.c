#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>

#include "miscFunctions.h"

/************* Miscellaneous functions ***************/



/// Functions for swapping bytes due to small endianness
uint16_t swap_uint16(uint16_t val){
    return (val << 8) | (val >> 8);
}

uint32_t swap_uint32(uint32_t val){
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

/// Invalid arguments (from main)
void invalidArguments(){
	printf("Invalid arguments. See usage. [./Hostman]\n");
}

/// Check if a string is a number
uint8_t checkIfNumber(char* str)
{
	uint8_t flag = 1, i;
	for(i=0; i<strlen(str); i++){
		if(!isdigit(str[i])){
			flag = 0;
			break;
		}
	}
	return flag;
}

/// Check ip
uint8_t checkIP(char* ip)
{
	uint8_t i, dot = 0;
	uint16_t num;

	if(strlen(ip) > 15) return 0;

	char buff[20];
	strcpy(buff, ip);

	if(buff[0] == '0' || buff[0] == '.') return 0;
	for(i=0; i<strlen(buff); i++){
		if(buff[i] == '.'){
			dot++;
			buff[i] = ' ';
		}
		else if(buff[i] < '0' || buff[i] > '9'){
			return 0;
		}
	}
	if(dot != 3) return 0;

	FILE *stream = fmemopen(buff, strlen(buff), "r");

	while(fscanf(stream, "%"SCNu16, &num) == 1){
		if(num > 255){
			fclose(stream);
			return 0;
		}
	}

	fclose(stream);

	return 1;
}

/// Function to check file extension
uint8_t checkExtension(char *fileName)
{
	uint8_t length = strlen(fileName);
	if(length > 5){
		char *ext;
		ext = fileName + length - 5;

		if(!strcmp(ext, ".pcap"))
			return 1;
	}
	return 0;
}


char buffer[6];
/// Determine ethernet protocol
const char* determineEthernetProtocol(uint16_t num)
{
	switch(num){
		case 0x0800:
			return "IPv4";
		case 0x0806:
			return "ARP";
		case 0x8035:
			return "RARP";
		case 0x86DD:
			return "IPv6";
		default:
			return "???";
	}
}

/// Determine ip-protocol
const char *determineIpProtocol(uint8_t num)
{
	switch(num){
		case 1:		//ICMP Protocol
			return "ICMP";
        case 2:		//IGMP Protocol
        	return "IGMP";
		case 4:		// IPv4
			return "IPv4";
        case 6:		//TCP Protocol
			return "TCP";
        case 17: 	//UDP Protocol
			return "UDP";
		case 41:
			return "IPv6";
        default: 	//Other protocols
            return "???";
	}
}

/// Determine port description from number
const char *determinePort(uint16_t num)
{
	switch(num){
		case 20:
			return "FTP";
		case 22:
			return "SSH";
		case 23:
			return "Telnet";
		case 25:
			return "SMTP";
		case 53:
			return "DNS";
		case 80:
			return "HTTP";
		case 179:
			return "BGP";
		case 443:
			return "HTTPS";
		case 546:
			return "DHCP";
		default:
			sprintf(buffer, "%d", (int)num);
			return buffer;
	}
}

const char* flagSetOrNot(uint8_t num){
	if(num) return "Set";
	return "Not set";
}

uint8_t isPrintNewline(char c)
{
	if(c == 0x0a) return 1;
	if(c == 0x0d) return 1;
	if(c >= ' ' && c <= '~') return 1;
	return 0;
}
