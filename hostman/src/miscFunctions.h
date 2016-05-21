#ifndef MISCFUNCTIONS_H_INCLUDED
#define MISCFUNCTIONS_H_INCLUDED

#include <inttypes.h>

uint16_t swap_uint16(uint16_t val);
uint32_t swap_uint32(uint32_t val);

void invalidArguments();
uint8_t checkIfNumber(char* str);
uint8_t checkIP(char *ip);

uint8_t checkExtension(char* fileName);

const char* determineEthernetProtocol(uint16_t num);
const char* determineIpProtocol(uint8_t num);
const char* determinePort(uint16_t num);

const char* flagSetOrNot(uint8_t num);

uint8_t isPrintNewline(char c);

#endif // MISCFUNCTIONS_H_INCLUDED
