#include <stdio.h>

#include "cmdOptions.h"

#define USAGE(str, cmd) printf("%-25s: %s\n", str, cmd)

void printUsage(){
	printf("%s\n%s\n%s\n%s\n%s\n",
	"    __  __                  __                             ",
	"   / / / /  ____    _____  / /_   ____ ___   ____ _   ____ ",
	"  / /_/ /  / __ \\  / ___/ / __/  / __ `__ \\ / __ `/  / __ \\",
	" / __  /  / /_/ / (__  ) / /_   / / / / / // /_/ /  / / / /",
	"/_/ /_/   \\____/ /____/  \\__/  /_/ /_/ /_/ \\__,_/  /_/ /_/ ");

	printf("\nUSAGE:\n");

	USAGE("See usage", "./Hostman");

	USAGE("Basic information", "./Hostman <filename> -b");
	putchar('\n');

	USAGE("Hexdump all packets", "./Hostman <filename> -d");
	USAGE("Hexdump selected packet", "./Hostman <filename> -d <packet no>");
	USAGE("Hexdump in range", "./Hostman <filename> -d <start packet no> <num of packets>");
	putchar('\n');

	USAGE("Detailed information", "./Hostman <filename> -v");
	USAGE("Selected packet detail", "./Hostman <filename> -v <packet no>");
	USAGE("Packet details in range", "./Hostman <filename> -v <start packet no> <num of packets>");
	putchar('\n');

	USAGE("Search by IP", "./Hostman <filename> -ip");
	USAGE("Search by text", "./Hostman <filename> -t");
	putchar('\n');

	USAGE("Follow packet stream", "./Hostman <filename> -f <packet no>");
}
