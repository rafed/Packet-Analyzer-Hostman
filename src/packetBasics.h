#ifndef PACKETBASICS_H_INCLUDED
#define PACKETBASICS_H_INCLUDED

#include <inttypes.h>

#define PRINTIPTOARRAY(array, index) sprintf(array, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 , index[0], index[1], index[2], index[3])
#define PRINTMACTOARRAY(array, index) sprintf(array, "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8, index[0], index[1], index[2], index[3], index[4], index[5])
#define PRINTTOCONSOLE(a, b, c, d, e) printf("%-7s %-20s %-16s %-10s %-7s\n", a, b, c, d, e)

void basicInfo_ethernetFrame(uint8_t *packetData);
void basicInfo_arp(uint8_t *packetData);
void basicInfo_ip(uint8_t *packetData);

void keepBlank();

#endif // PACKETBASICS_H_INCLUDED
