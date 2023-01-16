/*
 * PUDP.cpp
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */


#include "UDPParser.h"

#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <algorithm>
#include <bits/stdc++.h>


UDPParser::UDPParser(uint16_t intfId, uint16_t routerId)
{
	this->iId 				= intfId;
	this->rId				= routerId;
	this->cFlowSm			= 0;
	this->fortiSm			= 0;
	this->timeStamp 		= 0;
	this->len 				= 0;
	this->lenToProcess		= 0;
	this->lenProcessed 		= 0;
	this->flowSetId 		= 0;
	this->buffer			= NULL;
	this->noOfFlowId 		= 0;
	this->flowSetLen		= 0;
	this->valueLoop			= 0;
	this->locationId		= 0;
	this->noOffGateFlows 	= 1;
}

UDPParser::~UDPParser()
{ }

void UDPParser::lockAAAMap()
{
	    pthread_mutex_lock(&mapAAALock::lockCount);
	    while (mapAAALock::count == 0)
	        pthread_cond_wait(&mapAAALock::nonzero, &mapAAALock::lockCount);
	    mapAAALock::count = mapAAALock::count - 1;
	    pthread_mutex_unlock(&mapAAALock::lockCount);
}

void UDPParser::unLockAAAMap()
{
    pthread_mutex_lock(&mapAAALock::lockCount);
    if (mapAAALock::count == 0)
        pthread_cond_signal(&mapAAALock::nonzero);
    mapAAALock::count = mapAAALock::count + 1;
    pthread_mutex_unlock(&mapAAALock::lockCount);
}

void UDPParser::lockDnsMap()
{
	    pthread_mutex_lock(&mapDnsLock::lockCount);
	    while (mapDnsLock::count == 0)
	        pthread_cond_wait(&mapDnsLock::nonzero, &mapDnsLock::lockCount);
	    mapDnsLock::count = mapDnsLock::count - 1;
	    pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void UDPParser::unLockDnsMap()
{
    pthread_mutex_lock(&mapDnsLock::lockCount);
    if (mapDnsLock::count == 0)
        pthread_cond_signal(&mapDnsLock::nonzero);
    mapDnsLock::count = mapDnsLock::count + 1;
    pthread_mutex_unlock(&mapDnsLock::lockCount);
}



void UDPParser::hexDump(const void* pv, uint16_t len)
{
  const unsigned char* p = (const unsigned char*) pv;
  uint16_t i;

  for( i = 0; i < len; ++i )
  {
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

void UDPParser::parseUDPPacket(const BYTE packet, headerInfo *hdrObj)
{ 
	hdrObj->udpLen = UDP_HDR_LEN;

	decodeNetFlow(packet + hdrObj->udpLen, hdrObj);
    return;
}

void UDPParser::decodeNetFlow(const BYTE packet, headerInfo *hdrObj)
{
	len 			= 0;
	lenToProcess	= 0;
	lenProcessed 	= 0;
	buffer			= NULL;
	timeStamp 		= 0;
	locationId		= 0;

//	hexDump(packet, 10);


//	timeStamp = VAL_ULONG(packet + 8);

	timeStamp = IPGlobal::CURRENT_EPOCH_SEC;
	locationId = hdrObj->locationId;

	lenToProcess = hdrObj->pckLen - (hdrObj->ethLen + hdrObj->ipLen + hdrObj->udpLen + NETFLOW_HDR_LEN);

	uint8_t version = VAL_USHORT(packet);


	if(version != 9) return;

	buffer = (packet + NETFLOW_HDR_LEN);

//	while(lenToProcess != 0)
//	{
//		len = decodeFlowSet(buffer + lenProcessed);
//		lenToProcess -= len;
//		lenProcessed += len;
//	}

	len = decodeFlowSet(buffer + lenProcessed);

}

uint16_t UDPParser::decodeFlowSet(const BYTE packet)
{
	uint16_t offset = 0;

	flowSetId = noOfFlowId = flowSetLen = 0;

	flowSetId = VAL_USHORT(packet + offset);
	offset += 2;

	flowSetLen = VAL_USHORT(packet + offset);
	offset += 2;

	switch(flowSetId)
	{
		case 1110:
				noOfFlowId = (flowSetLen - 4) / IPV4FLOWSIZE;
				decordFlowId(packet + offset, &noOfFlowId, IPVersion4);
				break;

		case 1210:
				noOfFlowId = (flowSetLen - 4) / IPV6FLOWSIZE;
				decordFlowId(packet + offset, &noOfFlowId, IPVersion6);
				break;

		default:
				break;
	}
	return flowSetLen;
}

void UDPParser::decordFlowId(const BYTE packet, uint16_t* noOfFlows, uint8_t version)
{
	uint16_t offset = 0;
	valueLoop = 0;

	cFlow **t_array = (cFlow **)malloc(*noOfFlows * sizeof(cFlow *));

	for(valueLoop = 0; valueLoop < *noOfFlows; valueLoop++)
		offset += extractValues(packet + offset, version, &valueLoop, t_array);

	t_array[0]->noOfFlows = valueLoop;
	t_array[0]->locationId = locationId;

	switch(t_array[0]->ipVersion)
	{
		case IPVersion4:
					pushToXdrAgentV4(t_array);
					break;

		case IPVersion6:
					break;
	}
}

//void UDPParser::display(cFlow** t_array)
//{
//	cFlow ***p = &t_array;
//
//	for (uint16_t i = 0; i < noOfFlowId; i++)
//	{
//	    printf("Source IP %s| Destination IP %s\n", (*p)[i]->srcIpv6, (*p)[i]->dstIpv6);
//	}
//}

uint16_t UDPParser::extractValues(const BYTE packet, uint8_t version, uint16_t *count, cFlow** t_array)
{
	uint16_t offset = 0;
	char lchar[20];

	t_array[*count] = (cFlow*) malloc(sizeof(cFlow));

	t_array[*count]->reset();
	t_array[*count]->sEpochSec = timeStamp;

	switch(version)
	{
		case IPVersion4:
			t_array[*count]->ipVersion = version;
			offset += ExtractIP4Address(packet, &t_array[*count]->srcIpv4,  &offset);
			offset += ExtractIP4Address(packet, &t_array[*count]->dstIpv4, &offset);
			break;

		case IPVersion6:
			t_array[*count]->ipVersion = version;
			offset += ExtractIP6Address(packet, t_array[*count]->srcIpv6, &offset);
			offset += ExtractIP6Address(packet, t_array[*count]->dstIpv6, &offset);
			offset += 16;	/* Next Hop */
			offset += 16;	/* BGP Next Hop */
			break;
	}

	offset += 4;	/* Next Hop */
	offset += 4;	/* BGP Next Hop */
	offset += 2;	/* InputInt */
	offset += 2;	/* OutputInt */
	offset += 8;	/* Packets */

//	offset += getOctets(packet, &cFlowObj->pLoad, &offset);

// -------------------------------------------------------------------

	lchar[0] = 0;

	sprintf(lchar, "%02x%02x%02x%02x%02x%02x%02x%02x",
			(unsigned)packet[offset], (unsigned)packet[offset+1], (unsigned)packet[offset+2], (unsigned)packet[offset+3], (unsigned)packet[offset+4], (unsigned)packet[offset+5], (unsigned)packet[offset+6], (unsigned)packet[offset+7]);

	t_array[*count]->pLoad = HextoDigits(lchar);
	offset += 8;

// ---------------------------------------------------------------------
	offset += 2;	/* Max Len */
	offset += 2;	/* Min Len */

//	offset += getDuration(packet, &t_array[*count]->duration, &offset);

	offset += 8;	/* Duration */

//	t_array[*count]->eEpochSec = timeStamp + t_array[*count]->duration;

	offset += getPort(packet, &t_array[*count]->srcPort, &offset);
	offset += getPort(packet, &t_array[*count]->dstPort, &offset);

	offset += 1;	/* Forwarding Status */
	offset += 1;	/* TCP Flag */
	offset += 1;	/* Min TTL */
	offset += 1;	/* Max TTL */
	offset += 1;	/* Protocol */

	if(version == IPVersion6)
	{
		offset += 4;	/* IPv6 Extension Header --*/
		offset += 4;	/* IPv6 Flow Level --*/
	}

	offset += 1;	/* IP ToS */
	offset += 1;	/* Ip Version */

	offset += getDirection(packet, &t_array[*count]->direction, &offset);

	offset += 2;	/* ICMP Type */

//	offset += getAS(packet, &t_array[*count]->srcAS, &offset);
//	offset += getAS(packet, &t_array[*count]->dstAS, &offset);

	offset += 4;
	offset += 4;

	offset += 1;	/* Source Mask */
	offset += 1;	/* Destination Mask */
	offset += 4;	/* Multicast */

	return offset;
}

void UDPParser::pushToXdrAgentV4(cFlow** t_array)
{
	uint16_t idx = PKT_WRITE_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

	cFlowSM::cFlowSMStore[cFlowSm][this->iId][rId][idx][cFlowSM::cFlowSMStoreCnt[cFlowSm][this->iId][rId][idx]] = t_array;

	cFlowSM::cFlowSMStoreCnt[cFlowSm][this->iId][rId][idx]++ ;
	cFlowSm++;

	if(cFlowSm >= IPGlobal::NO_OF_CFLOW_SM)
		cFlowSm = 0;
}

void UDPParser::copyMsgObj(uint32_t &cnt, std::unordered_map<uint32_t, cFlow> &ip_msg, cFlow *msgObj)
{
	if(msgObj == NULL)
		return;

	ip_msg[cnt].copy(msgObj);
	cnt++;
}

uint16_t UDPParser::ExtractIP4Address(const BYTE packet, uint32_t *ip,  uint16_t *offset)
{
	*ip	=(*ip << 8) + (0xff & packet[*offset]);
	*ip	=(*ip << 8) + (0xff & packet[*offset + 1]);
	*ip	=(*ip << 8) + (0xff & packet[*offset + 2]);
	*ip	=(*ip << 8) + (0xff & packet[*offset + 3]);

	return IPv4_LEN;
}

uint16_t UDPParser::ExtractIP6Address(const BYTE packet, char *ipBuffer, uint16_t *loc)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int domain = AF_INET6, ret;

	ipBuffer[0] = 0;
	ret = 0;

	sprintf(ipBuffer,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[*loc], packet[*loc+1], \
			packet[*loc+2], packet[*loc+3], packet[*loc+4], packet[*loc+5], packet[*loc+6], packet[*loc+7], packet[*loc+8], packet[*loc+9], \
			packet[*loc+10], packet[*loc+11], packet[*loc+12], packet[*loc+13], packet[*loc+14], packet[*loc+15], packet[*loc+16]);

	ret = inet_pton(domain, ipBuffer, buf);
	if (ret <= 0)
	{
		if (ret == 0) {
			fprintf(stderr, "Not in presentation format");
			ipBuffer[0] = 0;
		}
		else
			perror("inet_pton");
	}

	if (inet_ntop(domain, buf, ipBuffer, INET6_ADDRSTRLEN) == NULL) {
				   perror("inet_ntop");
				   ipBuffer[0] = 0;
	}
	return IPv6_LEN;
}

uint16_t UDPParser::getOctets(const BYTE packet, uint32_t *payLoad, uint16_t *offset)
{
	*payLoad	= VAL_ULONG(packet + (*offset + 4));
	return PLOAD_LEN;
}

uint16_t UDPParser::getDuration(const BYTE packet, double *duration, uint16_t *offset)
{
	uint32_t buffer = 0, firstByte = 0, secondByte = 0;
	double first = 0, decimal = 0, sTime = 0, eTime = 0;

	buffer 		= VAL_ULONG(packet + *offset);
	firstByte 	= buffer / 1000;
	secondByte  = buffer % 1000;

	first = (double) firstByte;
	decimal = (double)secondByte / 1000;

	sTime = first + decimal;

	buffer = firstByte = secondByte = first = decimal = 0;

	buffer 		= VAL_ULONG(packet + (*offset + 4));
	firstByte 	= buffer / 1000;
	secondByte 	= buffer % 1000;

	first= (double) firstByte;
	decimal = (double)secondByte / 1000;

	eTime = first + decimal;

	*duration = eTime - sTime;
	return DURATION_LEN;
}

uint16_t UDPParser::getPort(const BYTE packet, uint16_t *port, uint16_t *offset)
{
	*port = VAL_USHORT(packet + *offset);
	return PORT_LEN;
}

uint16_t UDPParser::getDirection(const BYTE packet, uint8_t *direction, uint16_t *offset)
{
	*direction = VAL_BYTE(packet + *offset);
	return DIRECTION_LEN;
}

uint16_t UDPParser::getAS(const BYTE packet, uint32_t *as, uint16_t *offset)
{
	*as = VAL_ULONG(packet + *offset);
	return AS_LEN;
}



uint32_t UDPParser::HextoDigits(char *hexadecimal)
{
	uint32_t decimalNumber=0;
	char hexDigits[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int i, j, power=0, digit;

	for(i=strlen(hexadecimal)-1; i >= 0; i--)
	{
		for(j=0; j<16; j++)
		{
			if(hexadecimal[i] == hexDigits[j])
			{
				decimalNumber += j*pow(16, power);
			}
		}
		 power++;
	}
	return decimalNumber;
}

/* DNS */

void UDPParser::parsePacketDNS(const BYTE packet, uint16_t dnsLen)
{
    uint32_t pos = 0, id_pos = 0;
    uint16_t qdcount = 0, ancount = 0, retPos = 0;

    char URL[50];
    URL[0] = 0;

    uint8_t dnsQRFlag 			= packet[pos+2] >> 7;					    // Query Response -> Question=0 and Answer=1

    /*
     * RCODE = 0 - No Error, 1- Format Error, 2- Server Error, 3- Name Error, 4- Not Implemented, 5- Refused.
     */

    if(dnsQRFlag == 1)
    {
				qdcount = (packet[pos+4] << 8) + packet[pos+5];			// Query Count
				ancount = (packet[pos+6] << 8) + packet[pos+7];			// Answer Count

				uint8_t dnsResponseCode = packet[pos + 3] & 0x0f;		// rcode will be there in case of Response (Answer = 1)

				if (dnsResponseCode != 0) // Earlier 26
					return;

				if(qdcount == 1 && (ancount > 0 && ancount <= 2))
				{
					if(parsePacketDNSQueries((pos + DNS_HDR_LEN), id_pos, (const BYTE)packet, &retPos, dnsLen, URL))
						if(dnsResponseCode == 0)
							parsePacketDNSAnswers(retPos, packet, ancount, URL);
					else
						return;
				}
    }
}

bool UDPParser::parsePacketDNSQueries(uint32_t pos, uint32_t id_pos, const BYTE packet, uint16_t *retPos, uint16_t dnsLen, char* URL)
{
    uint16_t type = 0;
    std::string url;

    url = read_rr_name(packet, &pos, id_pos, dnsLen);
    std::replace(url.begin(), url.end(), ',', '.');

    if (url.compare("NULL") == 0)
    { return false; }

    try
    {
    	if(url.length() >= URL_LEN)
    	{
    		url = url.substr(url.length() - (URL_LEN - 1));
    		strcpy(URL, url.c_str());
    	}
    	else
    	{ strcpy(URL, url.c_str()); }

    	url.clear();

    	type = VAL_USHORT(packet+pos);

    	if(type == 255) return false;	// 255 is for Any Ip Address

    	*retPos = pos + 4;
    	return true;
    }
    catch(...)
    {
    	return false;
    }
}

void UDPParser::parsePacketDNSAnswers(uint16_t pos, const BYTE packet, uint16_t ancount, char* URL)
{
	uint16_t type, dataLen, ttl;
	char ipv6ResolvedIp[INET6_ADDRSTRLEN];

	dataLen = ttl = 0;

	try
	{
		for(uint16_t ansCounter = 0; ansCounter < ancount; ansCounter++)
		{
			while(packet[pos] != 192) { // Reference Question Name Start with '0xc0' locate it
				pos += 1;
			}

			pos = pos + 2;												// Reference Question Name (2 Bytes)
			type = (packet[pos] << 8) + packet[pos + 1];

			pos = pos + 2;												// Type
			pos = pos + 2;												// Class

			pos = pos + 4;												// TTL

			dataLen = (packet[pos] << 8) + packet[pos + 1];
			pos = pos + 2;												// Data Length

			uint32_t longResolvedIp = 0;

			switch(type)
			{
				case A:	/* IP4 Address */
//					msgObj->dns.responseCode = 0;

					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos]);
					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos + 1]);
					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos + 2]);
					longResolvedIp=(longResolvedIp << 8) + (0xff & packet[pos + 3]);

					/* If Resolved Ip is 1.0.0.0 ~ 255.255.255.255 */
					if((longResolvedIp >= 16777216 && longResolvedIp <= 4294967295) && strlen(URL) > 0)
					{ updateDns(longResolvedIp, std::string(URL)); }

					pos = pos + dataLen;

					break;

				case AAAA: /* IP6 Address */
					{
//						msgObj->udp.responseCode = 0;
						uint16_t ipv6Len = ExtractIP6Address(packet, ipv6ResolvedIp, &pos);

						updateDnsV6(std::string(ipv6ResolvedIp), URL);

						pos = pos + dataLen;
						ipv6ResolvedIp[0] = 0;
					}
					break;

				default:
					pos = pos + dataLen;
					break;
			}
		}
	}
	catch(...)
	{
		std::cout << " a standard exception was caught, with message '"  << "'\n";
	}
}

string UDPParser::read_rr_name(const uint8_t * packet, uint32_t * packet_p, uint32_t id_pos, uint16_t len)
{
    uint32_t i, next, pos=*packet_p;
    uint32_t end_pos = 0;
    uint32_t name_len=0;
    uint32_t steps = 0;

    next = pos;

    while (pos < len && !(next == pos && packet[pos] == 0) && steps < len*2)
    {
        char c = packet[pos];
        steps++;
        if (next == pos)
        {
            if ((c & 0xc0) == 0xc0)
            {
                if (pos + 1 >= len)
                { return "NULL"; }

                if (end_pos == 0)
                	end_pos = pos + 1;

                pos = id_pos + ((c & 0x3f) << 8) + packet[pos+1];
                next = pos;
            }
            else
            {
                name_len++;
                pos++;
                next = next + c + 1;
            }
        }
        else
        {
            if (c >= '!' && c <= 'z' && c != '\\')
            	name_len++;
            else
            	name_len += 4;

            pos++;
        }
    }
    if (end_pos == 0)
    	end_pos = pos;

    if (steps >= 2*len || pos >= len)
    	return "NULL";

    name_len++;

    if(name_len > len *2)
    	return "NULL";

    string name;
    pos = *packet_p;

    next = pos;
    i = 0;

    while (next != pos || packet[pos] != 0)
    {
        if (pos == next)
        {
            if ((packet[pos] & 0xc0) == 0xc0)
            {
                pos = id_pos + ((packet[pos] & 0x3f) << 8) + packet[pos+1];
                next = pos;
            }
            else
            {
                if (i != 0) name.append(1,'.');i++;
                next = pos + packet[pos] + 1;
                pos++;
            }
        }
        else
        {
            char c = packet[pos];

            if (c >= '!' && c <= '~' && c != '\\')
            {
                name.append(1, (char) c);
                i++; pos++;
            }
            else
            { return "NULL"; }
        }
    }
    *packet_p = end_pos + 1;
    return name;
}

/* FotriGate */

void UDPParser::parseFortiPacket(const BYTE packet, headerInfo *hdrObj)
{
	hdrObj->udpLen = UDP_HDR_LEN;

	decodeForti(packet + hdrObj->udpLen, hdrObj);
    return;
}

void UDPParser::decodeForti(const BYTE packet, headerInfo *hdrObj)
{
	char c;
	uint16_t pos = 0;

	len = hdrObj->pckLen - (hdrObj->ethLen + hdrObj->ipLen + hdrObj->udpLen);

	for(uint16_t i= 0; i < len; i++, pos++)
	{
		c = packet[pos];
		data.append(1, (char) c);
	}
	pushToFortiGWAgent(data);
	data.clear();
}


void UDPParser::pushToFortiGWAgent(string xdr)
{
	uint16_t idx = PKT_WRITE_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

	fortiGwSM::fortiGwSMStore[fortiSm][this->iId][rId][idx][fortiGwSM::fortiGwSMStoreCnt[fortiSm][this->iId][rId][idx]] = xdr;

	fortiGwSM::fortiGwSMStoreCnt[fortiSm][this->iId][rId][idx]++ ;
	fortiSm++;

	if(fortiSm >= IPGlobal::NO_OF_FORTI_SM)
		fortiSm = 0;
}


void UDPParser::parseMappingPacket(const BYTE packet, headerInfo *hdrObj, uint16_t *locator)
{
	std::string data;

	parseMapping(packet + UDP_HDR_LEN + 64, hdrObj, locator);
    return;
}

void UDPParser::parseMapping(const BYTE packet, headerInfo *hdrObj, uint16_t *locator)
{
	uint16_t pos = 0;
	char c;
	bool found = false;

	vector<string> words{};
	size_t pos1 = 0;

	uint8_t index = 0, counter = 0;
	data.clear();

//	fstream		xdrFortiHandler; // For testing
//	char filePath[] = "/opt/pinnacle/SpectaProbe/mapping_test.csv"; // For testing
//	xdrFortiHandler.open((char *)filePath, ios :: out | ios :: app);

	len = hdrObj->pckLen - (hdrObj->ethLen + hdrObj->ipLen + hdrObj->udpLen);

	for(uint16_t i= 0; i < (len - 64); i++, pos++)
	{
		c = packet[pos];
		data.append(1, (char) c);
	}

//	xdrFortiHandler << data << endl;
//	xdrFortiHandler.close();

	try
	{
		while ((pos1 = data.find("|")) != string::npos)
		{
			if(data.length() <= 0)
				return;

			words.push_back(data.substr(0, pos1));
			data.erase(0, pos1 + 1);
		}

		data.clear();

		std::map<string, string>::iterator itr;

		for (const auto &w : words)
		{
			temp = string(w);

			while ((pos1 = temp.find(" ")) != string::npos)
			{
				if(temp.length() <= 0)
					return;

				first = temp.substr(0, pos1);

				if(first.find("10.", 0, 3) != string::npos)
				{
					privateIp = first;
					found = true;
				}

				if(found)
				{
					counter++;
					if(counter == 4)
					{
						if((first.find("45.", 0, 3) != string::npos) || (first.find("103.", 0, 4) != string::npos) || (first.find("15", 0, 2) != string::npos) || (first.find("16", 0, 2) != string::npos) || (first.find("43.", 0, 3) != string::npos))
						{
							found = false;
							counter = 0;
							publicIpLong = 0;
							privateIpLong = 0;

							ipToLong((char *)first.c_str(), &publicIpLong);
							ipToLong((char *)privateIp.c_str(), &privateIpLong);

//							if(aaaGlbMap::publicPrivateMap[this->iId][this->rId][*locator].find(publicIpLong) != aaaGlbMap::publicPrivateMap[this->iId][this->rId][*locator].end())
//							{
//
//								aaaGlbMap::publicPrivateMap[this->iId][this->rId][*locator][publicIpLong] = privateIpLong;
//							}
//							else
//								aaaGlbMap::publicPrivateMap[this->iId][this->rId][*locator].insert(std::pair<uint32_t, uint32_t>(publicIpLong, privateIpLong));

							if(aaaGlbMap::publicPrivateMap[this->iId][this->rId][publicIpLong % 100].find(publicIpLong) != aaaGlbMap::publicPrivateMap[this->iId][this->rId][publicIpLong % 100].end())
							{

								aaaGlbMap::publicPrivateMap[this->iId][this->rId][publicIpLong % 100][publicIpLong] = privateIpLong;
							}
							else
								aaaGlbMap::publicPrivateMap[this->iId][this->rId][publicIpLong % 100].insert(std::pair<uint32_t, uint32_t>(publicIpLong, privateIpLong));


							privateIp.clear();
						}
					}
				}
				temp.erase(0, pos1 + 1);
				first.clear();
			  }
		  }
	}
	catch(...)
	{
		std::cout << " a standard exception was caught, with message '" << "'\n";
		return;
	}
}

uint32_t UDPParser::ipToLong(char *ip, uint32_t *plong)
{
	char *next = NULL;
	const char *curr = ip;
	uint32_t tmp;
	int i, err = 0;

	*plong = 0;
	for (i = 0; i < NUM_OCTETTS; i++)
	{
		tmp = strtoul(curr, &next, 10);
		if (tmp >= 256 || (tmp == 0 && next == curr))
		{
			err++;
			break;
		}
		*plong = (*plong << 8) + tmp;
		curr = next + 1;
	}

	if (err)
		return 1;
	else
		return *plong;
}
