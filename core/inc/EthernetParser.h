/*
 * EthernetProbe.h
 *
 *  Created on: 30-Jan-2016
 *      Author: Debashis
 */

#ifndef CORE_SRC_ETHERNETPARSER_H_
#define CORE_SRC_ETHERNETPARSER_H_

#include <string.h>
#include <algorithm>
#include <stdlib.h>    //malloc

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <pcap/vlan.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>

#include "UDPParser.h"
#include "TCPParser.h"
#include "Log.h"
#include "BaseConfig.h"
#include "IPGlobal.h"

class EthernetParser : public BaseConfig
{
	private:
		UDPParser		*udp;
		TCPParser		*tcp;
		dnsHdrIp		*dnsHdrIpInfo;


		int interfaceId = 0;
		int routerId = 0;

		struct iphdr*		ip4Header;
		struct udphdr*		udpHeader;

		void		parseIPV4Packet(const BYTE packet, headerInfo *hdrObj);
		uint16_t	extractIpv4Address(const BYTE packet);
		void    	hexDump(const void* pv, int len);

		void 		extractDnsIpv4Address(const BYTE packet, dnsHdrIp *info);

	public:
		EthernetParser(uint16_t intfid, uint16_t rId);
		~EthernetParser();

		void 	parsePacket(const BYTE packet, headerInfo *hdrObj);
};

#endif /* CORE_SRC_ETHERNETPARSER_H_ */
