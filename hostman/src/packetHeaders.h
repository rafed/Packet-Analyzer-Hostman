#ifndef PACKETHEADERS_H_INCLUDED
#define PACKETHEADERS_H_INCLUDED

#include <inttypes.h>

/****************** Macros *************************/
#define PCAP_HEADER_LENGTH 24
#define RECORD_HEADER_LENGTH 16

#define MAX_PACKET_SIZE 65535

#define ETHERNET_FRAME_LENGTH 14
#define IP_LENGTH 20
#define TCP_LENGTH 32
#define UDP_LENGTH 8

/*************** Global header ******************/
typedef struct pcapHeader_s {
	uint32_t magicNumber;    	/* magic number */
	uint16_t versionMajor;   	/* major version number */
	uint16_t versionMinor;   	/* minor version number */
	uint32_t thiszone;       	/* GMT to local correction */
	uint32_t sigfigs;       	/* accuracy of timestamps */
	uint32_t snapLength;     	/* max length of captured packets, in octets */
	uint32_t network;        	/* data link type */
} pcapHeader_t;

/************** Packet record header ***************/
typedef struct recHeaderStruct_s {
    uint32_t timestampSec;   	/* timestamp seconds */
    uint32_t timestampMisec;    /* timestamp microseconds */
    uint32_t inclLength;        /* number of octets of packet saved in file */
    uint32_t origLlength;       /* actual length of packet */
} recHeaderStruct_t;

/************************************************/
/*************** Packet headers *****************/
/************************************************/

/************* Data link layer headers ***************/

/// Ehternet header
typedef struct ethernetFrame_s {
	uint8_t destinationMac[6];
	uint8_t sourceMac[6];
	uint16_t type;
} ethernetFrame_t;

/************* Network layer headers *****************/

/// ARP header
typedef struct arpHeader_s {
    uint16_t hardwareType;			/* Hardware Type           */
    uint16_t protocolType;    		/* Protocol Type           */
    uint8_t hwAddrLength;       	/* Hardware Address Length */
    uint8_t protoAddrLength;       	/* Protocol Address Length */
    uint16_t opcode;    			/* Operation Code          */
    uint8_t senderHwAddr[6];      	/* Sender hardware address */
    uint8_t senderIpAddr[4];     	/* Sender IP address       */
    uint8_t targetHwAddr[6];    	/* Target hardware address */
	uint8_t targetIpAddr[4];     	/* Target IP address       */
} arpHeader_t;

/// IP header
typedef struct ipHeader_s {
	uint8_t headerLength: 4;			/* header length, multiply by 4 */
	uint8_t version: 4;					/* version */
	uint8_t typeOfService;     			/* type of service */
	uint16_t totalLength;               /* total length */
	uint16_t identification;            /* identification */
	uint16_t flags;                		/* fragment offset field */
/*
	uint16_t fragmentOffset: 13;
	uint8_t moreFragments: 1;
	uint8_t dontFragment: 1;
	uint8_t reservedFlag: 1;
*/
	#define IP_reservedFlag 0x8000		/* reserved flag */
	#define IP_reservedFlagPos 15

	#define IP_dontFragment 0x4000      /* dont fragment flag */
	#define IP_dontFragmentPos 14

	#define IP_moreFragments 0x2000     /* more fragments flag */
	#define IP_moreFragmentsPos 13

	#define IP_fragmentOffset 0x1fff    /* mask for fragmenting bits */

	uint8_t  timeToLive;                /* time to live */
	uint8_t  protocol;                  /* protocol */
	uint16_t checksum;                  /* checksum */
	uint8_t sourceAddress[4];		    /* source address */
	uint8_t destinationAddress[4];      /* destination address */
} ipHeader_t;

/************* Transport layer headers *************/

/// TCP header
typedef struct tcpHeader_s{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint32_t sequenceNumber;
	uint32_t acknowledgementNumber;
	uint16_t flags;

	#define TCP_headerLength 0xF000
	#define TCP_headerLengthPos 12

	#define TCP_reserved 0x0FC0
	#define TCP_reservedPos 6

	#define TCP_urg 0x0020
	#define TCP_urgPos 5

	#define TCP_ack 0x0010
	#define TCP_ackPos 4

	#define TCP_push 0x0008
	#define TCP_pushPos 3

	#define TCP_reset 0x0004
	#define TCP_resetPos 2

	#define TCP_syn 0x0002
	#define TCP_synPos 1

	#define TCP_fin 0x0001

	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urgentPointer;
} tcpHeader_t;

/// UDP header
typedef struct udpHeader_s{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint16_t checksum;
} udpHeader_t;

#endif // PACKETHEADERS_H_INCLUDED
