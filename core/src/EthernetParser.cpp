/*
 * EthernetProbe.cpp
 *
 *  Created on: 30-Jan-2016
 *      Author: Debashis
 */

#include <sys/time.h>

#include "EthernetParser.h"

EthernetParser::EthernetParser(uint16_t intfid, uint16_t rId)
{
	this->_name = "EthernetParser";
	this->setLogLevel(Log::theLog().level());

	this->interfaceId = intfid;
	this->routerId = rId;

	this->udp 	= new UDPParser(this->interfaceId, this->routerId);
	this->tcp 	= new TCPParser();

	this->dnsHdrIpInfo	= new dnsHdrIp;

	ip4Header = NULL;
	udpHeader = NULL;

}

EthernetParser::~EthernetParser()
{
	delete (this->udp);
	delete (this->tcp);
	delete (this->dnsHdrIpInfo);
}

void EthernetParser::hexDump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  for( i = 0; i < len; ++i ) {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
}

void EthernetParser::parsePacket(const BYTE packet, headerInfo *hdrObj)
{
    uint16_t type = packet[12] * 256 + packet[13];		/* Ethernet Containing Protocol */

    hdrObj->ethLen = sizeof(struct ether_header);

    switch(type)
    {
    	case ETH_IP:
    			parseIPV4Packet(packet + hdrObj->ethLen, hdrObj);
    			break;
		default:
    		break;
    }
}


void EthernetParser::parseIPV4Packet(const BYTE packet, headerInfo *hdrObj)
{
	 	uint16_t ipVer, protocol = 0, headerLength = 0, protoLen;
	 	uint16_t tcpHdrLen = 0, totalLen = 0;
	 	uint16_t locator = 0;

	 	uint32_t routerIp = 0;

	 	ip4Header = (struct iphdr *)(packet);

		hdrObj->ipLen 		= ((unsigned int)ip4Header->ihl)*4;
		ipVer 				= ip4Header->version;

		/* Check if any Version 6 Packet inside ip Version 4 */
		if(ipVer != IPVersion4)
		{
			return;
		}

		protocol 		= ip4Header->protocol; // TCP or UDP

		switch(protocol)
		{
			case PACKET_IPPROTO_UDP:
						{
							headerLength 				= ((unsigned int)ip4Header->ihl)*4;
							udpHeader 					= (struct udphdr *)(packet + headerLength);
							protoLen					= ntohs((unsigned short int)udpHeader->len);
							uint16_t sPort 				= ntohs((unsigned short int)udpHeader->source);
							uint16_t dPort 				= ntohs((unsigned short int)udpHeader->dest);

							locator = initSection::ipMappingMap[dPort];

							if(dPort == Nokia && IPGlobal::PROCESS_CFLOW)
							{
								hdrObj->locationId = extractIpv4Address(packet);
								udp->parseUDPPacket(packet + hdrObj->ipLen, hdrObj);
							}
							else if(dPort == Forti && IPGlobal::PROCESS_FORTI)
							{
								udp->parseFortiPacket(packet + hdrObj->ipLen, hdrObj);
							}
							else if(((hdrObj->pckLen - protoLen) >= 12) && IPGlobal::PROCESS_DNS)
							{
								uint16_t dnsLen = protoLen - UDP_HDR_LEN ;
								dnsHdrIpInfo->reset();
								extractDnsIpv4Address(packet, dnsHdrIpInfo);

								udp->lockDnsMap();
								udp->parsePacketDNS(packet + hdrObj->ipLen + UDP_HDR_LEN, dnsLen, dnsHdrIpInfo);
								udp->unLockDnsMap();
							}
							else if(locator >= 1 && locator <= 26)
							{
								udp->parseMappingPacket(packet + hdrObj->ipLen, hdrObj, &locator);
							}
						}
						break;
			default:
									return;
									break;
		}
}

uint16_t EthernetParser::extractIpv4Address(const BYTE packet)
{
	uint16_t offset = 12;
	uint32_t sIp = 0;

	sIp = (sIp << 8) + (0xff & packet[offset]);
	sIp = (sIp << 8) + (0xff & packet[offset + 1]);
	sIp = (sIp << 8) + (0xff & packet[offset + 2]);
	sIp = (sIp << 8) + (0xff & packet[offset + 3]);

	return(initSection::routerIdMap[sIp]);
}

void EthernetParser::extractDnsIpv4Address(const BYTE packet, dnsHdrIp *info)
{
	uint16_t offset = 12;

	info->sourceIp = (info->sourceIp << 8) + (0xff & packet[offset]);
	info->sourceIp = (info->sourceIp << 8) + (0xff & packet[offset + 1]);
	info->sourceIp = (info->sourceIp << 8) + (0xff & packet[offset + 2]);
	info->sourceIp = (info->sourceIp << 8) + (0xff & packet[offset + 3]);

	offset = offset + 4;

	info->destIp = (info->destIp << 8) + (0xff & packet[offset]);
	info->destIp = (info->destIp << 8) + (0xff & packet[offset + 1]);
	info->destIp = (info->destIp << 8) + (0xff & packet[offset + 2]);
	info->destIp = (info->destIp << 8) + (0xff & packet[offset + 3]);
}
