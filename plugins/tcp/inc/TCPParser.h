/*
 * TCPParser.h
 *
 *  Created on: 2 Nov 2022
 *      Author: debas
 */

#ifndef PLUGINS_TCP_SRC_TCPPARSER_H_
#define PLUGINS_TCP_SRC_TCPPARSER_H_

#include "SpectaTypedef.h"

#include <vector>
#include <string>
#include <sstream>

using namespace std;

class TCPParser
{
	public:
		TCPParser();
		~TCPParser();

		void parseTCPPacket(const BYTE packet, uint16_t totalLen, uint16_t tcpHdrLen);
};

#endif /* PLUGINS_TCP_SRC_TCPPARSER_H_ */
