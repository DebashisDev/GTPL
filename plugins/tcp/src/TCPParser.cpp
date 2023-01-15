/*
 * TCPParser.cpp
 *
 *  Created on: 2 Nov 2022
 *      Author: debas
 */

#include <pthread.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <ctype.h>
#include <algorithm>
#include <string>

#include "TCPParser.h"

using namespace std;

TCPParser::TCPParser()
{

}

TCPParser::~TCPParser()
{

}

void TCPParser::parseTCPPacket(const BYTE packet, uint16_t totalLen, uint16_t ipHdrLen)
{
	tcphdr 		*tcpHeader;
	uint32_t	pLoad = 0;
	uint32_t	protoHLen = 0;
	uint16_t pos = 0;
	std::string data;
	char c;

	fstream		xdrFortiHandler; // For testing
	char filePath[] = "/opt/pinnacle/SpectaProbe/Mapping.csv"; // For testing
	xdrFortiHandler.open((char *)filePath, ios :: out | ios :: app);

	tcpHeader = (struct tcphdr *)(packet);
	protoHLen = ((tcpHeader->doff) << 2);

	pLoad = totalLen - (ipHdrLen + protoHLen);

	for(uint16_t i= 0; i < pLoad; i++, pos++)
	{
		c = packet[pos];
		data.append(1, (char) c);
	}

	xdrFortiHandler << data << endl;
	return;
}
