/*
 * FlusherUtility.cpp
 *
 *  Created on: 18 Mar 2021
 *      Author: Debashis
 */

#include "FUtility.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <string.h>


FUtility::FUtility()
{ }

FUtility::~FUtility()
{ }

void FUtility::lockDnsMap()
{
	pthread_mutex_lock(&mapDnsLock::lockCount);
	while (mapDnsLock::count == 0)
		pthread_cond_wait(&mapDnsLock::nonzero, &mapDnsLock::lockCount);
	mapDnsLock::count = mapDnsLock::count - 1;
	pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void FUtility::unLockDnsMap()
{
    pthread_mutex_lock(&mapDnsLock::lockCount);
    if (mapDnsLock::count == 0)
        pthread_cond_signal(&mapDnsLock::nonzero);
    mapDnsLock::count = mapDnsLock::count + 1;
    pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void FUtility::buildUdpXdr(udpSession *pUdpSession, char *xdr)
{
	xdr[0] = 0;

	/* get URL */
	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
		{
			if(pUdpSession->upPLoadSize < 100 && pUdpSession->dnPLoadSize < 100)
				return;

			/* Get the Private IP in case of Dynanic IP */
			if(!pUdpSession->staticIp)
				getPrivateIP(pUdpSession);

			long2Ip(pUdpSession->sIpv4, pUdpSession->sIpv6);
			long2Ip(pUdpSession->dIpv4, pUdpSession->dIpv6);
		}
		break;

		case IPVersion6:
		{
//			sessionKey = pUdpSession->ipV6sessionKey;
		}
		break;
	}

	sprintf(xdr, "%d,"			// 01- Router LocationId
				 "%s,"			// 02- Source Ip
				 "%d,"			// 03- Source Port
				 "%s,"			// 04- Destination Ip
				 "%d,"			// 05- Destination Port
				 "%d,"			// 06- Up Payload Size
				 "%d,"		    // 07- Dn Payload Size
				 "%lu,"			// 08- Start Time,
				 "%d,"			// 09- Static = 1 / Dynamic = 0,
				 "%d",			// 10- Ip version

			pUdpSession->routerLocationId,
			pUdpSession->sIpv6,
			pUdpSession->sPort,
			pUdpSession->dIpv6,
			pUdpSession->dPort,
			pUdpSession->upPLoadSize,
			pUdpSession->dnPLoadSize,
			pUdpSession->startTimeEpochSec,
			pUdpSession->staticIp,
			pUdpSession->ipVer);
}


void FUtility::getPrivateIP(udpSession *pUdpSession)
{
	for(uint16_t interfaceId = 0; interfaceId < IPGlobal::NO_OF_INTERFACES; interfaceId++)
	{
		for(uint16_t routerId = 0; routerId < IPGlobal::ROUTER_PER_INTERFACE[interfaceId]; routerId++)
		{
			std::map<uint32_t, uint32_t>::iterator it = aaaGlbMap::publicPrivateMap[interfaceId][routerId][pUdpSession->sIpv4 % 100].find(pUdpSession->sIpv4);

			if(it != aaaGlbMap::publicPrivateMap[interfaceId][routerId][pUdpSession->sIpv4 % 100].end())
			{
				pUdpSession->sIpv4 = it->second;
				return;
			}
		}
	}
}

//void FUtility::getPrivateIP(udpSession *pUdpSession)
//{
//	for(uint16_t interfaceId = 0; interfaceId < IPGlobal::NO_OF_INTERFACES; interfaceId++)
//	{
//		for(uint16_t routerId = 0; routerId < IPGlobal::ROUTER_PER_INTERFACE[interfaceId]; routerId++)
//		{
//			for(uint16_t locationId = 1; locationId <= 26; locationId++)
//			{
//				std::map<uint32_t, uint32_t>::iterator it = aaaGlbMap::publicPrivateMap[interfaceId][routerId][locationId].find(pUdpSession->sIpv4);
//
//				if(it != aaaGlbMap::publicPrivateMap[interfaceId][routerId][locationId].end())
//				{
//					pUdpSession->sIpv4 = it->second;
//					return;
//				}
//			}
//		}
//	}
//}


void FUtility::swap3(uint64_t *a, uint64_t *b, uint64_t *c)
{
	uint64_t lr, mi, sm;

	if(*a > *b)
	{
		mi = *a;
		sm = *b;
	}
	else
	{
		mi = *b;
		sm = *a;
	}

	if(mi > *c)
	{
		lr = mi;
		if(sm > *c)
		{
			mi = sm;
			sm = *c;
		}
		else
		{
			mi = *c;
		}
	}
	else
		lr = *c;

	*a = sm;
	*b = mi;
	*c = lr;
}

void FUtility::swap4(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{
	uint64_t temp = 0;

	if(*a > *b)
	{
		temp = *a;
		*a = *b;
		*b = temp;
	}
	if(*c > *d)
	{
		temp = *c;
		*c = *d;
		*d = temp;
	}
	if(*a > *c)
	{
		temp = *a;
		*a = *c;
		*c = temp;
	}
	if(*b > *d)
	{
		temp = *b;
		*b = *d;
		*d = temp;
	}
	if(*b > *c)
	{
		temp = *b;
		*b = *c;
		*c = temp;
	}
}

void FUtility::buildDnsXdr(dnsSession *pDnsSession, char *csvXDR)
{
	char userId[IPV6_ADDR_LEN];

	uint32_t dnsResTimeMilliSec = 0;
	string sessionKey = "";

	userId[0] = 0;

	uint64_t sTime = pDnsSession->queryStartEpochNanoSec;
	uint64_t eTime = pDnsSession->queryEndEpochNanoSec;

	csvXDR[0] = 0;

	if(eTime > 0 && sTime > 0 && (eTime > sTime)) {
		if(sTime > 1000000) {
			sTime = sTime / (1000 * 1000);
			if(eTime > 1000000) {
				eTime = eTime / (1000 * 1000);
				dnsResTimeMilliSec = (uint32_t) (eTime - sTime);
			}
		}
	}

	switch(pDnsSession->ipVer)
	{
		case IPVersion4:
			sessionKey = to_string(pDnsSession->sessionV4Key);
			long2Ip(pDnsSession->sIpv4, pDnsSession->sIpv6);
			long2Ip(pDnsSession->dIpv4, pDnsSession->dIpv6);

			getV4UserId(pDnsSession->sIpv4, userId);

			if(strlen(userId) == 0)
				long2Ip(pDnsSession->sIpv4, userId);

			break;

		case IPVersion6:
			sessionKey = pDnsSession->sessionV6Key;
			break;
	}

	if(!checkNewLine(pDnsSession->url))
			return;

	if(strlen(pDnsSession->url) <= 5 || strlen(pDnsSession->url) > 50)
		return;

	if(strstr(pDnsSession->errorDesc, "No Error") != NULL)
		pDnsSession->errorCode = 0;

	sprintf(csvXDR, "%d,%d,17,DNS,"			// 1- Probe Id			2- XDR Id		3- UDP				4-  DNS
					"%s,%s,%d,%s,%d,"		// 5- User Id			6- Source Ip	7- Source Port		8-  Dest Ip		9- Dest Port
					"%s,%d,%s,"				// 10- URL				11- Error Code	12- Error Desc
					"%s,"					// 13- Address
					"%lu,%lu,%u,%s,"		// 14- Start time		15- End Time	16- Resolve Time    17- OLT
					"%s,%s,%s,%d,%s",		// 18- User Policy		19- User Plan	20- User Mac		21- Flush Type
					IPGlobal::PROBE_ID, XDR_ID_DNS,
					userId, pDnsSession->sIpv6, pDnsSession->sPort, pDnsSession->dIpv6, pDnsSession->dPort,
					pDnsSession->url, pDnsSession->errorCode, pDnsSession->errorDesc,
					"NA",
					pDnsSession->queryStartEpochNanoSec, pDnsSession->queryEndEpochNanoSec, dnsResTimeMilliSec, "NA",
					"NA", "NA", "NA", pDnsSession->flushType, sessionKey.c_str());
}

uint32_t FUtility::getV4UserId(uint32_t &sourceIP, char* userId)
{
	uint32_t userIp = 0;
	bool ipFound = false;

	/* Get User Name against User IP */
//	lockAAAMap();
//
//	std::map<uint32_t, userInfo>::iterator it = aaaGlbMap::aaaGlbUserIpMap.find(sourceIP);
//	if(it != aaaGlbMap::aaaGlbUserIpMap.end())
//	{
//		userIp 		= it->first;
//		strcpy(userId, it->second.userName);
//	}
//	unLockAAAMap();

	return userIp;
}

void FUtility::tcpGetV6UserId(
		char *sourceIP,
		char *destIP,
		char* userId,
		char* userPolicyPlan,
		char* userPlan,
		char* userMac,
		char* userOlt)
{
//	lockRadiusMap();
//
//	if(strlen(sourceIP) < 16)
//		return;
//
//	std::map<std::string, userInfo>::iterator it = radiusGlbMap::glbRadiusIpv6UserMap.find(std::string(sourceIP).substr(0, IPV6_PREFIX_LAN));
//
//	if(it != radiusGlbMap::glbRadiusIpv6UserMap.end())
//	{
//		 strcpy(userId, it->second.userId);
//		 strcpy(userPolicyPlan, it->second.userPolicyPlan);
//		 strcpy(userPlan, it->second.userPlan);
//		 strcpy(userMac, it->second.userMac);
//		 strcpy(userOlt, it->second.OLT);
//	}
//
//	unLockRadiusMap();
}


void FUtility::buildAaaXdr(aaaSession *pRadiusSession, char *xdr, bool *errorXdr)
{
	char terminationCause[25];
	char sourceIp[IPV6_ADDR_LEN], destIp[IPV6_ADDR_LEN];
	char ipvAddress[IPV6_ADDR_LEN];

	xdr[0] = terminationCause[0] = ipvAddress[0] = 0;

	if(pRadiusSession->ipVer == IPVersion4)
	{
		sourceIp[0] = destIp[0] = 0;
		long2Ip(pRadiusSession->sourceAddr, sourceIp);
		long2Ip(pRadiusSession->destAddr, destIp);
	}
	else
	{ return; }

	if(pRadiusSession->framedIpLong == 0)
		*errorXdr = true;

	if(pRadiusSession->StartTimeEpochMiliSec > pRadiusSession->EndTimeEpochMiliSec)
	{
		uint64_t temp = pRadiusSession->StartTimeEpochMiliSec;
		pRadiusSession->StartTimeEpochMiliSec = pRadiusSession->EndTimeEpochMiliSec;
		pRadiusSession->EndTimeEpochMiliSec = temp;
	}
	long2Ip(pRadiusSession->framedIpLong, ipvAddress);


	if(pRadiusSession->ipv6AddressPrefixFlag)
		strcpy(ipvAddress, pRadiusSession->userIpV6);

	pRadiusSession->appPort 				= pRadiusSession->dPort;

	/*
	 * 18 termination code are been defined in specification, apart form that all the Unknown
	 */

	if(pRadiusSession->accStatusType == 2 && (pRadiusSession->accTerminationCause == 0 || pRadiusSession->accTerminationCause > 18))
		strcpy(terminationCause, "Unknown");
	else
		strcpy(terminationCause, initSection::acctTeminateMap[pRadiusSession->accTerminationCause].c_str());

	if(pRadiusSession->accAuth > 3) pRadiusSession->accAuth = 0;

	checkNewLine(pRadiusSession->userName);

	sprintf(xdr, "%d,%d,%d,%s,"		// 01- Probe Id,       02- XDR Id, 		       03- App Port,      04- Protocol Desc,
				 "%d,%s,"			// 05- Protocol,       06- framed Protocol,
				 "%u,"				// 07- Session Key
				 "%s,%s,"			// 08- Source Mac,     09- Dest Mac,
			 	 "%s,%d,%s,%d,"		// 10- Source Ip,      11- Source Port,        12- Dest Ip,       13- Dest Port
				 "%llu,%llu,"		// 14- Start Time,     15- End Time,
				 "%d,%s,"			// 16- Req Code,       17- Req Code Desc,
				 "%s,%s,%s,%s,"		// 18- User Name,	   19- framed IP,      	   20- NAS IP,		  21- Calling Station Id
				 "%u,%s,%s,"		// 22- Service Type	   23- Service Type Desc   24- NAS Identifier
				 "%s,%s,"			// 25- User Plan, 	   26- User Policy Plan,
				 "%u,%s,"			// 27- Acc Status Type,28- Acc Status Type Desc,
				 "%u,%s,"			// 29- Termination C,  30- Termination C Desc,
				 "%d,%s,"			// 31- Resp Code,      32- Resp Code Desc,
				 "%d,%s,%u,"		// 33- NAS Port Type,  34- NAS Port Type Desc, 35- SessionTimeOut
				 "%u,%s,%s,"		// 36- Acc Auth,       37- Acc Auth Desc,	   38- Reply Msg
				 "%lu,%d,%s,%s,%s,"	// 39- Flush Time      40- Flush Type		   41- OLT    		  42- IPv6      43- User Mac
				 "%u,%u,%u,%u,%u,"	// 44- Input Octets	   45- Output Octets	   46- Session Time   47- InputPackets    48- Output Packets
				 "%u,%u",			// 49- Input Gigawords 50- Output Gigawords

				IPGlobal::PROBE_ID, XDR_ID_AAA, pRadiusSession->appPort, initSection::protocolName[pRadiusSession->dPort].c_str(),
				pRadiusSession->protocol, initSection::framedProtocolMap[pRadiusSession->protocol].c_str(),
				pRadiusSession->aaaKey,
				"NA", "NA",
				sourceIp, pRadiusSession->sPort, destIp, pRadiusSession->dPort,
				pRadiusSession->StartTimeEpochMiliSec, pRadiusSession->EndTimeEpochMiliSec,
				pRadiusSession->reqCode, initSection::radiusCodeMap[pRadiusSession->reqCode].c_str(),
				pRadiusSession->userName, ipvAddress, /*pRadiusSession->nasIP*/ "NA", pRadiusSession->callingStationId,
				pRadiusSession->serviceType, initSection::serviceTypeMap[pRadiusSession->serviceType].c_str(), pRadiusSession->nasIdentifier,
				"NA", "NA",
				pRadiusSession->accStatusType, initSection::acctStatusMap[pRadiusSession->accStatusType].c_str(),
				pRadiusSession->accTerminationCause, terminationCause,
				pRadiusSession->respCode, initSection::radiusCodeMap[pRadiusSession->respCode].c_str(),
				pRadiusSession->nasPortType, initSection::nasPortTypeMap[pRadiusSession->nasPortType].c_str(), 0,
				pRadiusSession->accAuth, initSection::acctAuthenticMap[pRadiusSession->accAuth].c_str(), pRadiusSession->replyMsg,
				pRadiusSession->flushTime, pRadiusSession->flushType, "NA", pRadiusSession->userIpV6, "NA",
				pRadiusSession->inputOctets, pRadiusSession->outputOctets, 0, 0, 0,
				pRadiusSession->inputGigaWords, pRadiusSession->outputGigaWords);

		return;
}

bool FUtility::checkNewLine(char *s)
{
	if(isalpha(*s))
    {
		while(*s && *s != '\n' && *s != '\r') s++;
		*s = 0;

		return true;
    }
	else
	{
		return false;
	}
}

string FUtility::getResolvedIp4(uint32_t dIp)
{
	lockDnsMap();
	std::string URL = findDns(dIp);
	unLockDnsMap();

//	if(!URL.length())
//		return("NULL");

	if(URL.length() <= 5)
			return("NULL");
	else
		return(URL);
}

string FUtility::findDns(uint32_t dIp)
{ return(getURLLookUp(dIp, DNSGlobal::dnsLookUpMap[dIp % 10])); }

string FUtility::getURLLookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap)
{
	std::map<uint32_t, std::string>::iterator itSp = dnsMap.find(ip);

	if(itSp != dnsMap.end())
		return(itSp->second);

	return "";
}


void FUtility::formateIPv6(char *buffer)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int domain = AF_INET6, ret;


	ret = inet_pton(domain, buffer, buf);
	if (ret <= 0)
	{
		if (ret == 0) {
			fprintf(stderr, "Not in presentation format");
		}
		else
			perror("inet_pton");
	}

	if (inet_ntop(domain, buf, buffer, INET6_ADDRSTRLEN) == NULL) {
	               perror("inet_ntop");
	}
}
