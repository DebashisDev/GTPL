/*
 * TCPGlobal.cpp
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#include "SmGlobal.h"

using namespace std;

SmGlobal::SmGlobal()
{};

SmGlobal::~SmGlobal()
{};

namespace initSection
{
	std::map<uint8_t, std::string> protocolName;
	std::map<uint16_t, std::string> dnsErrorCode;
	std::map<uint16_t, std::string> tcpPorts;
	std::map<uint32_t, std::string> radiusCodeMap;
	std::map<uint32_t, std::string> serviceTypeMap;
	std::map<uint32_t, std::string> framedProtocolMap;
	std::map<uint32_t, std::string> acctAuthenticMap;
	std::map<uint32_t, std::string> acctTeminateMap;
	std::map<uint32_t, std::string> acctStatusMap;
	std::map<uint32_t, std::string> nasPortTypeMap;
	std::map<uint32_t, std::string> ipSubNetMap;
	std::map<uint32_t, uint16_t> routerIdMap;
	std::map<uint16_t, uint16_t> ipMappingMap;
	std::map<uint32_t, uint16_t> staticIpPoolMap;
}

namespace IPStats
{
	uint64_t dnsLookupMapSize 			= 0;

	uint32_t tcpV4SessionScanned[MAX_TCP_SM_SUPPORT] = {0};
	uint32_t tcpV4SessionCleaned[MAX_TCP_SM_SUPPORT] = {0};
	uint32_t tcpV4SessionTotalCnt[MAX_TCP_SM_SUPPORT] = {0};

	uint32_t tcpV6SessionScanned[MAX_TCP_SM_SUPPORT] = {0};
	uint32_t tcpV6SessionCleaned[MAX_TCP_SM_SUPPORT] = {0};
	uint32_t tcpV6SessionTotalCnt[MAX_TCP_SM_SUPPORT] = {0};

	uint32_t udpV4SessionScanned[MAX_UDP_SM_SUPPORT] = {0};
	uint32_t udpV4SessionCleaned[MAX_UDP_SM_SUPPORT] = {0};
	uint32_t udpV4SessionTotalCnt[MAX_UDP_SM_SUPPORT] = {0};

	uint32_t udpV6SessionScanned[MAX_UDP_SM_SUPPORT] = {0};
	uint32_t udpV6SessionCleaned[MAX_UDP_SM_SUPPORT] = {0};
	uint32_t udpV6SessionTotalCnt[MAX_UDP_SM_SUPPORT] = {0};

	uint32_t dnsV4SessionScanned[MAX_DNS_SM_SUPPORT] = {0};
	uint32_t dnsV4SessionCleaned[MAX_DNS_SM_SUPPORT] = {0};
	uint32_t dnsV4SessionTotalCnt[MAX_DNS_SM_SUPPORT] = {0};

	uint32_t dnsV6SessionScanned[MAX_DNS_SM_SUPPORT] = {0};
	uint32_t dnsV6SessionCleaned[MAX_DNS_SM_SUPPORT] = {0};
	uint32_t dnsV6SessionTotalCnt[MAX_DNS_SM_SUPPORT] = {0};

	uint32_t unTcpSessionCnt[MAX_UNM_SM_SUPPORT] = {0};
	uint32_t unTcpSessionScanned[MAX_UNM_SM_SUPPORT] = {0};
	uint32_t unTcpSessionCleaned[MAX_UNM_SM_SUPPORT] = {0};

	uint32_t unUdpSessionCnt[MAX_UNM_SM_SUPPORT] = {0};
	uint32_t unUdpSessionScanned[MAX_UNM_SM_SUPPORT] = {0};
	uint32_t unUdpSessionCleaned[MAX_UNM_SM_SUPPORT] = {0};

	uint32_t aaaAccessSessionCnt[MAX_AAA_SM_SUPPORT] = {0};
	uint32_t aaaAccessSessionScanned[MAX_AAA_SM_SUPPORT] = {0};
	uint32_t aaaAccessSessionCleaned[MAX_AAA_SM_SUPPORT] = {0};

	uint32_t aaaAccounSessionCnt[MAX_AAA_SM_SUPPORT] = {0};
	uint32_t aaaAccounSessionScanned[MAX_AAA_SM_SUPPORT] = {0};
	uint32_t aaaAccounSessionCleaned[MAX_AAA_SM_SUPPORT] = {0};
}

namespace DNSGlobal
{
	std::map<uint32_t, std::string> dnsLookUpMap[10];
	std::map<std::string, std::string> dnsV6LookUpMap;
	std::map<uint32_t, uint32_t> dnsSubnetMap;
}

namespace aaaGlbMap
{
	std::map<uint32_t, userInfo> aaaGlbUserIpMap;	/* 01295072520@airtelbroadband.in */
	std::map<string, userInfo> aaaGlbUserIdMap;
	std::map<std::string, userInfo> aaaGlbIpv6UserMap;
//	std::map<uint32_t, uint32_t> publicPrivateMap[8][8][26];
	std::map<uint32_t, uint32_t> publicPrivateMap[8][8][100];
}

namespace mapDnsLock
{
	pthread_mutex_t lockCount = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t nonzero = PTHREAD_COND_INITIALIZER;
	unsigned count;
}

namespace mapAAALock
{
	pthread_mutex_t lockCount = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t nonzero = PTHREAD_COND_INITIALIZER;
	unsigned count;
}
