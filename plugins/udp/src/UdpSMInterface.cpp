/*
 * UdpSMInterface.cpp
 *
 *  Created on: 18 Mar 2021
 *      Author: Debashis
 */

#include "UdpSMInterface.h"

UdpSMInterface::UdpSMInterface(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "UdpSMInterface";
	this->setLogLevel(Log::theLog().level());
	this->instanceId = id;

	this->pFUtility = new FUtility();
	udpInitializeSessionPool();

	sessionCleanCnt = 0;
}

UdpSMInterface::~UdpSMInterface()
{ delete(this->pFUtility); }

uint32_t UdpSMInterface::udpGetFreeIndex()
{
	udpFreeBitPos++;
	if(udpFreeBitPos >= udpFreeBitPosMax) udpFreeBitPos = 0;
	int arrId = udpFreeBitPos / UDP_SESSION_POOL_ARRAY_ELEMENTS;
	int bitId = udpFreeBitPos % UDP_SESSION_POOL_ARRAY_ELEMENTS;

	while(udpBitFlagsSession[arrId].test(bitId)){
		udpFreeBitPos++;
		if(udpFreeBitPos >= udpFreeBitPosMax) udpFreeBitPos = 0;
		arrId = udpFreeBitPos / UDP_SESSION_POOL_ARRAY_ELEMENTS;
		bitId = udpFreeBitPos % UDP_SESSION_POOL_ARRAY_ELEMENTS;
	}
	if(udpFreeBitPos >= udpFreeBitPosMax){
		printf("[%d] getFreeIndexIp freeBitPosIp [%u] >= freeBitPosIpMax [%u]\n",instanceId, udpFreeBitPos, udpFreeBitPosMax);
	}
	udpBitFlagsSession[arrId].set(bitId);
	return udpFreeBitPos;
}

void UdpSMInterface::udpReleaseIndex(uint32_t idx)
{
	uint32_t arrId = idx / UDP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UDP_SESSION_POOL_ARRAY_ELEMENTS;

	udpSessionPoolMap[arrId][bitId]->reset();
	udpSessionPoolMap[arrId][bitId]->poolIndex = idx;
	udpBitFlagsSession[arrId].reset(bitId);
}

void UdpSMInterface::udpInitializeSessionPool()
{
	udpFreeBitPosMax = UDP_SESSION_POOL_ARRAY_ELEMENTS * UDP_SESSION_POOL_ARRAY_SIZE;

	printf("UdpSMInterface [%02d]	Initializing [%u]  UDP Session Pool... ", instanceId, udpFreeBitPosMax);
	TheLog_nc_v2(Log::Info, name(),"     [%02d] Initializing [%u] UDP Session Pool...", instanceId, udpFreeBitPosMax);

	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_SIZE; i++)
	{
		udpBitFlagsSession[i].reset();
		for(uint16_t j = 0; j < UDP_SESSION_POOL_ARRAY_ELEMENTS; j++)
		{
			udpSessionPoolMap[i][j] = new udpSession();
			udpSessionPoolMap[i][j]->poolIndex = (i*UDP_SESSION_POOL_ARRAY_ELEMENTS) + j;
		}
	}
	printf("Completed.\n");
	TheLog_nc_v2(Log::Info, name(),"     [%d] Initializing [%u] UDP Session Pool Completed.", instanceId, udpFreeBitPosMax);
}

udpSession* UdpSMInterface::udpGetSessionFromPool(uint32_t idx)
{
	uint32_t arrId = idx / UDP_SESSION_POOL_ARRAY_ELEMENTS;
	uint32_t bitId = idx % UDP_SESSION_POOL_ARRAY_ELEMENTS;
	return udpSessionPoolMap[arrId][bitId];
}

uint32_t UdpSMInterface::getMapIndexAndSessionKey(cFlow *pcFlow, uint64_t *sessionKey)
{
	uint32_t mapIndex = 0;
	*sessionKey = 0;
	ipV6Key = "";

    switch(pcFlow->ipVersion)
    {
    	case IPVersion4:
    			switch(pcFlow->direction)
    			{
    				case UP:
    					*sessionKey = (pcFlow->srcIpv4*59)^(pcFlow->dstIpv4)^(pcFlow->srcPort << 16)^(pcFlow->dstPort)^(17);
    					mapIndex = pcFlow->srcIpv4 % UDP_SESSION_POOL_ARRAY_ELEMENTS;
    					break;

    				case DOWN:
    					*sessionKey = (pcFlow->dstIpv4*59)^(pcFlow->srcIpv4)^(pcFlow->dstPort << 16)^(pcFlow->srcPort)^(17);
    					mapIndex = pcFlow->dstIpv4 % UDP_SESSION_POOL_ARRAY_ELEMENTS;
    					break;
    			}
    			break;

		case IPVersion6:
				switch(pcFlow->direction)
				{
					case UP:
							ipV6Key = std::to_string(17) +
									 (pcFlow->srcIpv6) + std::to_string(pcFlow->srcPort) +
									 (pcFlow->dstIpv6) + std::to_string(pcFlow->dstPort);
							mapIndex = pcFlow->srcIpv4 % TCP_SESSION_POOL_ARRAY_ELEMENTS;
							break;

					case DOWN:
							ipV6Key = std::to_string(17) +
									(pcFlow->dstIpv6) + std::to_string(pcFlow->dstPort) +
									(pcFlow->srcIpv6) + std::to_string(pcFlow->srcPort);
							mapIndex = pcFlow->dstPort % TCP_SESSION_POOL_ARRAY_ELEMENTS;
							break;
				}
				break;

    	default:
    			break;
	}
	return mapIndex;
}

void UdpSMInterface::UDPPacketEntry(cFlow **pcFlow)
{
	bool 			found = false, staticIp = false;
	uint32_t		temp = 0;

	location = 0;

	uint8_t flows = pcFlow[0]->noOfFlows;
	location = pcFlow[0]->locationId;

	for(uint8_t i = 0; i < flows; i++)
	{
		udpSession *pUdpSession = udpGetSession(pcFlow[i], &found, true);

		if(pUdpSession == NULL)
		{
			free(pcFlow[i]);
			continue;
		}

		timeStampArrivalPacket(pUdpSession, pcFlow[i]->sEpochSec);

		/* Create New Session */
		if(!found)
		{
			pUdpSession->routerLocationId = location;
			initializeUdpSession(pUdpSession, pcFlow[i]);
			updateUdpSession(pUdpSession, pcFlow[i]);
			free(pcFlow[i]);
		}
		else
		{
			updateUdpSession(pUdpSession, pcFlow[i]);
			free(pcFlow[i]);
		}
		pUdpSession = NULL;
	}
	free(pcFlow);
}

void UdpSMInterface::checkStaticIP(udpSession *pUdpSession)
{
	std::map<uint32_t, uint16_t>::iterator it = initSection::staticIpPoolMap.find(pUdpSession->sIpv4);
	if(it != initSection::staticIpPoolMap.end())
	{ pUdpSession->staticIp = true; }
}

uint16_t UdpSMInterface::checkSanityDestIp(udpSession *pUdpSession)
{
	uint16_t counter = 0;
	uint32_t temp = 0;

	switch(pUdpSession->routerLocationId)
	{
		case 100: /* GANDHINAGAR */
				for(counter = 0; counter < IPGlobal::GANDHINAGAR_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::GANDHINAGAR[counter][0], IPGlobal::GANDHINAGAR[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 101: /* JUNAGADH */
				for(counter = 0; counter < IPGlobal::JUNAGADH_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::JUNAGADH[counter][0], IPGlobal::JUNAGADH[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 102: /* NADIAD */
			for(counter = 0; counter < IPGlobal::NADIAD_COUNT; counter++)
			{
				if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::NADIAD[counter][0], IPGlobal::NADIAD[counter][1]))
				{
					temp = pUdpSession->sIpv4;

					pUdpSession->sIpv4 = pUdpSession->dIpv4;
					pUdpSession->dIpv4 = temp;

					temp = pUdpSession->upPLoadSize;
					pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
					pUdpSession->dnPLoadSize = temp;
					return 0;
				}
			}
			break;

		case 103: /* AHMEDABAD */
				for(counter = 0; counter < IPGlobal::AHMEDABAD_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::AHMEDABAD[counter][0], IPGlobal::AHMEDABAD[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 104: /* ANAND */
				for(counter = 0; counter < IPGlobal::ANAND_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::ANAND[counter][0], IPGlobal::ANAND[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 105: /* ANKLESHWAR */
				for(counter = 0; counter < IPGlobal::ANKLESHWAR_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::ANKLESHWAR[counter][0], IPGlobal::ANKLESHWAR[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 106: /* BARDOLI */
				for(counter = 0; counter < IPGlobal::BARDOLI_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::BARDOLI[counter][0], IPGlobal::BARDOLI[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 107: /* BARODA */
				for(counter = 0; counter < IPGlobal::BARODA_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::BARODA[counter][0], IPGlobal::BARODA[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 108: /* BHARUCH */
				for(counter = 0; counter < IPGlobal::BHARUCH_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::BHARUCH[counter][0], IPGlobal::BHARUCH[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 109: /* BHAVNAGAR */
				for(counter = 0; counter < IPGlobal::BHAVNAGAR_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::BHAVNAGAR[counter][0], IPGlobal::BHAVNAGAR[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 110: /* BILIMORA */
				for(counter = 0; counter < IPGlobal::BILIMORA_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::BILIMORA[counter][0], IPGlobal::BILIMORA[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 111: /* HALOL */
				for(counter = 0; counter < IPGlobal::HALOL_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::HALOL[counter][0], IPGlobal::HALOL[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 112: /* JAIPUR */
				for(counter = 0; counter < IPGlobal::JAIPUR_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::JAIPUR[counter][0], IPGlobal::JAIPUR[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 113: /* JAMNAGAR */
				for(counter = 0; counter < IPGlobal::JAMNAGAR_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::JAMNAGAR[counter][0], IPGlobal::JAMNAGAR[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 114: /* KIM */
				for(counter = 0; counter < IPGlobal::KIM_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::KIM[counter][0], IPGlobal::KIM[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 115: /* MEHSANA */
				for(counter = 0; counter < IPGlobal::MEHSANA_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::MEHSANA[counter][0], IPGlobal::MEHSANA[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 116: /* MODASA */
				for(counter = 0; counter < IPGlobal::MODASA_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::MODASA[counter][0], IPGlobal::MODASA[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 117: /* MORBI */
			for(counter = 0; counter < IPGlobal::MORBI_COUNT; counter++)
			{
				if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::MORBI[counter][0], IPGlobal::MORBI[counter][1]))
				{
					temp = pUdpSession->sIpv4;

					pUdpSession->sIpv4 = pUdpSession->dIpv4;
					pUdpSession->dIpv4 = temp;

					temp = pUdpSession->upPLoadSize;
					pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
					pUdpSession->dnPLoadSize = temp;
					return 0;
				}
			}
				break;

		case 118: /* NAVSARI */
				for(counter = 0; counter < IPGlobal::NAVSARI_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::NAVSARI[counter][0], IPGlobal::NAVSARI[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 119: /* PATNA */
				for(counter = 0; counter < IPGlobal::PATNA_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::PATNA[counter][0], IPGlobal::PATNA[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 120: /* PUNE */
				for(counter = 0; counter < IPGlobal::PUNE_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::PUNE[counter][0], IPGlobal::PUNE[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 121: /* RAJKOT */
				for(counter = 0; counter < IPGlobal::RAJKOT_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::RAJKOT[counter][0], IPGlobal::RAJKOT[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 122: /* SURAT */
				for(counter = 0; counter < IPGlobal::SURAT_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::SURAT[counter][0], IPGlobal::SURAT[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 123: /* UNJHA */
				for(counter = 0; counter < IPGlobal::UNJHA_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::UNJHA[counter][0], IPGlobal::UNJHA[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 124: /* VAPI */
				for(counter = 0; counter < IPGlobal::VAPI_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::VAPI[counter][0], IPGlobal::VAPI[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;

		case 125: /* VARANASI */
				for(counter = 0; counter < IPGlobal::VARANASI_COUNT; counter++)
				{
					if(IsIPInRange(pUdpSession->dIpv4, IPGlobal::VARANASI[counter][0], IPGlobal::VARANASI[counter][1]))
					{
						temp = pUdpSession->sIpv4;

						pUdpSession->sIpv4 = pUdpSession->dIpv4;
						pUdpSession->dIpv4 = temp;

						temp = pUdpSession->upPLoadSize;
						pUdpSession->upPLoadSize = pUdpSession->dnPLoadSize;
						pUdpSession->dnPLoadSize = temp;
						return 0;
					}
				}
				break;
		}
		return 0;
}

bool UdpSMInterface::IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask)
{
    uint32_t net_lower = (network & mask);
    uint32_t net_upper = (net_lower | (~mask));

    if(ip >= net_lower && ip <= net_upper)
        return true;
    return false;
}

udpSession* UdpSMInterface::udpGetSession(cFlow *pcFlow, bool *found, bool create)
{
	uint32_t sessionCnt = 0;
	udpSession *pUdpSession = NULL;
	uint32_t mapIndex, poolIndex;
	uint64_t ipV4Key = 0;

//	if(pcFlow->direction < 0)
//	{ return pUdpSession; }

	mapIndex = getMapIndexAndSessionKey(pcFlow, &ipV4Key);

	switch(pcFlow->ipVersion)
	{
		case IPVersion4:
		{
			std::map<uint64_t, uint32_t>::iterator it = udpV4SessionMap[mapIndex].find(ipV4Key);

			if(it != udpV4SessionMap[mapIndex].end())
			{
				pUdpSession = udpGetSessionFromPool(it->second);
				*found = true;
			}
			else
			{
				if(create) {
					for(int i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
						sessionCnt += (udpV4SessionMap[i].size() + udpV6SessionMap[i].size());

					if(sessionCnt < udpFreeBitPosMax) {
						poolIndex = udpGetFreeIndex();
						pUdpSession = udpGetSessionFromPool(poolIndex);
						pUdpSession->reset();

						pUdpSession->sessionIpV4Key = ipV4Key;
//						pUdpSession->smInstanceId = this->instanceId;
						pUdpSession->mapIndex = mapIndex;
						pUdpSession->poolIndex = poolIndex;
						udpV4SessionMap[pUdpSession->mapIndex][pUdpSession->sessionIpV4Key] = poolIndex;
					}
				}
				*found = false;
			}
		}
		break;

//		case IPVersion6:
//		{
//				std::map<string, uint32_t>::iterator it1 = udpV6SessionMap[mapIndex].find(ipV6Key);
//
//				if(it1 != udpV6SessionMap[mapIndex].end())
//				{
//					pUdpSession = udpGetSessionFromPool(it1->second);
//					*found = true;
//				}
//				else
//				{
//					if(create)
//					{
//						for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
//							sessionCnt += (udpV4SessionMap[i].size() + udpV6SessionMap[i].size());
//
//						if(sessionCnt < udpFreeBitPosMax)
//						{
//							poolIndex = udpGetFreeIndex();
//							pUdpSession = udpGetSessionFromPool(poolIndex);
//							pUdpSession->reset();
//
//							pUdpSession->ipV6sessionKey = ipV6Key;
//							pUdpSession->smInstanceId = this->instanceId;
//							pUdpSession->mapIndex = mapIndex;
//							pUdpSession->poolIndex = poolIndex;
//							udpV6SessionMap[pUdpSession->mapIndex][pUdpSession->ipV6sessionKey] = poolIndex;
//						}
//					}
//					*found = false;
//				}
//		}
//		break;

	}
	return pUdpSession;
}

void UdpSMInterface::initializeUdpSession(udpSession *pUdpSession, cFlow *pcFlow)
{
	pUdpSession->ipVer 			= pcFlow->ipVersion;
	pUdpSession->pType 			= PACKET_IPPROTO_UDP;

	pUdpSession->startTimeEpochSec 		= pUdpSession->pckArivalTimeEpochSec;

	switch(pcFlow->ipVersion)
	{
		case IPVersion4:
				switch(pcFlow->direction)
				{
						case UP: /* Egress = 1 GTPL IP --> Out Side */
								pUdpSession->sPort = pcFlow->srcPort;
								pUdpSession->dPort = pcFlow->dstPort;
								pUdpSession->sIpv4 = pcFlow->srcIpv4;
								pUdpSession->dIpv4 = pcFlow->dstIpv4;
								break;

						case DOWN: /* Ingress = 0 GTPL IP <-- Out Side */
								pUdpSession->sPort = pcFlow->dstPort;
								pUdpSession->dPort = pcFlow->srcPort;
								pUdpSession->sIpv4 = pcFlow->dstIpv4;
								pUdpSession->dIpv4 = pcFlow->srcIpv4;
								break;
				}
				break;

		case IPVersion6:
				switch(pcFlow->direction)
				{
						case UP:
								pUdpSession->sPort = pcFlow->srcPort;
								pUdpSession->dPort = pcFlow->dstPort;
								strcpy(pUdpSession->sIpv6, pcFlow->srcIpv6);
								strcpy(pUdpSession->dIpv6, pcFlow->dstIpv6);
								break;

						case DOWN:
								pUdpSession->sPort = pcFlow->dstPort;
								pUdpSession->dPort = pcFlow->srcPort;
								strcpy(pUdpSession->sIpv6, pcFlow->dstIpv6);
								strcpy(pUdpSession->dIpv6, pcFlow->srcIpv6);
								break;
				}
				break;
	}
}

void UdpSMInterface::updateUdpSession(udpSession *pUdpSession, cFlow *pcFlow)
{
	uint64_t timeDiff = 0;

	pUdpSession->totalFrCount ++;

	switch(pcFlow->direction)
	{
		case UP: /* Egress = 1 GTPL IP --> Out Side */
				if(pcFlow->pLoad > 0) {
					pUdpSession->upPLoadPkt += 1;
					pUdpSession->upPLoadSize += pcFlow->pLoad;
				}
				break;

		case DOWN: /* Ingress = 0 GTPL IP <-- Out Side */
				if(pcFlow->pLoad > 0) {
					pUdpSession->dnPLoadPkt += 1;
					pUdpSession->dnPLoadSize += pcFlow->pLoad;
				}
				break;
	}

	/** Check the Data Slicing **/
	if(pUdpSession->totalFrCount >= IPGlobal::SESSION_PKT_LIMIT)
	{
//		pUdpSession->causeCode = SYSTEM_PKTLIMIT_UDP_DATA;

		udpFlushSession(pUdpSession, true);
//		pUdpSession->reuse();
//		pUdpSession->startTimeEpochSec = pcFlow->sEpochSec;
	}
	else
	{
		if(pUdpSession->pckLastTimeEpochSec > pUdpSession->startTimeEpochSec)
		{
			timeDiff = pUdpSession->pckLastTimeEpochSec - pUdpSession->startTimeEpochSec;

			if (timeDiff >= IPGlobal::SESSION_TIME_LIMIT)
			{
//				pUdpSession->causeCode = SYSTEM_TIMEOUT_UDP_DATA;

				udpFlushSession(pUdpSession, true);
//				pUdpSession->reuse();
			}
		}
	}
}

void UdpSMInterface::timeStampArrivalPacket(udpSession *pUdpSession, uint64_t epochSec)
{
	pUdpSession->pckArivalTimeEpochSec 	= epochSec;
	pUdpSession->pckLastTimeEpochSec 	= epochSec;
}

void UdpSMInterface::udpFlushSession(udpSession *pUdpSession, bool erase)
{
	uint64_t epochSec = IPGlobal::CURRENT_EPOCH_SEC;

	checkSanityDestIp(pUdpSession);
	checkStaticIP(pUdpSession);

	uint16_t idx = PKT_WRITE_TIME_INDEX(epochSec, IPGlobal::TIME_INDEX);

	switch(pUdpSession->ipVer)
	{
	case IPVersion4:
				if(pUdpSession->routerLocationId != 0)
				{ udpStoreSession(idx, pUdpSession); }
				break;

	case IPVersion6:
				udpStoreSession(idx, pUdpSession);
				break;
	}

	if(erase)
		udpEraseSession(pUdpSession);
}

void UdpSMInterface::udpStoreSession(uint16_t idx, udpSession *pUdpSession)
{
//	uint16_t flusherNo = instanceId % IPGlobal::NO_OF_FLUSHER;

	if(FlusherStore::udpFlCnt[flusherNo][instanceId][idx + 2] == 0)
	{
		FlusherStore::udpFlStore[flusherNo][instanceId][idx][FlusherStore::udpFlCnt[flusherNo][instanceId][idx]].copy(pUdpSession);
		FlusherStore::udpFlCnt[flusherNo][instanceId][idx]++;
<<<<<<< HEAD
	}
=======
>>>>>>> e6bae557aa70c4b837204b5ce330c2a0ce1913b8

		flusherNo++;
	}
	else
		udpEraseSession(pUdpSession);

	if(flusherNo >= IPGlobal::NO_OF_FLUSHER)
	{	flusherNo = 0; }
}

void UdpSMInterface::udpTimeOutClean()
{
	sessionCleanCnt = 0;

	IPStats::udpV4SessionTotalCnt[instanceId] 	= 0;
	IPStats::udpV4SessionScanned[instanceId] 	= 0;
	IPStats::udpV4SessionCleaned[instanceId] 	= 0;

	IPStats::udpV6SessionTotalCnt[instanceId] 	= 0;
	IPStats::udpV6SessionScanned[instanceId] 	= 0;
	IPStats::udpV6SessionCleaned[instanceId] 	= 0;

//	TheLog_nc_v4(Log::Info, name()," [%02d] Going to Clean cFlow Sessions on Time : %02d:%02d:%02d",
//													instanceId, IPGlobal::CURRENT_HOUR, IPGlobal::CURRENT_MIN, IPGlobal::CURRENT_SEC);

	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		IPStats::udpV4SessionTotalCnt[instanceId] += udpV4SessionMap[i].size();

	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
	{
		for(auto elem = udpV4SessionMap[i].begin(), next_elem = elem; elem != udpV4SessionMap[i].end(); elem = next_elem)
		{
			++next_elem;
			udpCleanSession(udpGetSessionFromPool(elem->second));
			IPStats::udpV4SessionScanned[instanceId]++ ;
		}
	}

//	if(sessionCleanCnt > 0)
//		IPStats::udpV4SessionCleaned[instanceId] = sessionCleanCnt;

	TheLog_nc_v4(Log::Info, name()," [%02d] Ipv4 Cleaning Completed Sessions [%07lu]| Scanned [%07lu]| Cleaned [[%07lu]", instanceId,
						IPStats::udpV4SessionTotalCnt[instanceId], IPStats::udpV4SessionScanned[instanceId], sessionCleanCnt);

	sessionCleanCnt = 0;

#if 0
	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		IPStats::udpV6SessionTotalCnt[instanceId] += udpV6SessionMap[i].size();

	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
	{
		for(auto elem = udpV6SessionMap[i].begin(), next_elem = elem; elem != udpV6SessionMap[i].end(); elem = next_elem)
		{
			++next_elem;
			udpCleanSession(udpGetSessionFromPool(elem->second));
			IPStats::udpV6SessionScanned[instanceId]++ ;
		}
	}
	if(sessionCleanCnt > 0)
		IPStats::udpV6SessionCleaned[instanceId] = sessionCleanCnt;

//	TheLog_nc_v2(Log::Info, name()," Ipv6 Session Cleaning Completed for Session Id [%02d] with Session [%u]",
//			instanceId, IPStats::udpV6SessionCleaned[instanceId]);

	sessionCleanCnt = 0;
#endif

}

void UdpSMInterface::udpCleanSession(udpSession *pUdpSession)
{
	uint64_t curEpochSec = IPGlobal::CURRENT_EPOCH_SEC;

	uint16_t diffrence = curEpochSec - pUdpSession->pckLastTimeEpochSec;

	if(diffrence > IPGlobal::UDP_CLEAN_UP_TIMEOUT_SEC)
	{
//		if (pUdpSession->pType == PACKET_IPPROTO_UDP)
//			pUdpSession->causeCode = SYSTEM_CLEANUP_UDP_DATA;

		sessionCleanCnt++;
		IPStats::udpV4SessionCleaned[instanceId]++;
		udpFlushSession(pUdpSession, true);
	}
}

void UdpSMInterface::udpEraseSession(udpSession *pUdpSession)
{
	uint32_t idx, poolIndex;

	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
		{
			uint64_t sKey4 = pUdpSession->sessionIpV4Key;
			idx = pUdpSession->mapIndex;
			poolIndex = pUdpSession->poolIndex;
			udpReleaseIndex(poolIndex);
			udpV4SessionMap[idx].erase(sKey4);
		}
		break;

//		case IPVersion6:
//		{
//			string sKey6 = pUdpSession->ipV6sessionKey;
//			idx = pUdpSession->mapIndex;
//			poolIndex = pUdpSession->poolIndex;
//			udpReleaseIndex(poolIndex);
//			udpV6SessionMap[idx].erase(sKey6);
//		}
//		break;
	}
}

void UdpSMInterface::udpV4SessionCount()
{
	IPStats::tcpV4SessionTotalCnt[instanceId] = 0;
	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		IPStats::tcpV4SessionTotalCnt[instanceId] += udpV4SessionMap[i].size();
}

void UdpSMInterface::udpV6SessionCount()
{
	IPStats::tcpV6SessionTotalCnt[instanceId] = 0;
	for(uint16_t i = 0; i < UDP_SESSION_POOL_ARRAY_ELEMENTS; i++)
		IPStats::tcpV6SessionTotalCnt[instanceId] += udpV6SessionMap[i].size();
}

