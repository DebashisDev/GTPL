/*
 * SMGlobal.h
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#ifndef INC_SMGLOBAL_H_
#define INC_SMGLOBAL_H_

#include <pthread.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <queue>
#include <array>
#include <stdlib.h>
#include <stdint.h>

#include "GConfig.h.bck"
#include "SpectaTypedef.h"

using namespace std;

#define FLUSH_REQ_RSP			30
#define FLUSH_RSP_REQ			31
#define FLUSH_DUPLICATE			32
#define FLUSH_CLEANUP			33

#define MAX_INTERFACE_SUPPORT		16
#define MAX_ROUTER_PER_INTERFACE	8

#define MAX_TCP_SM_SUPPORT 	25
#define MAX_UDP_SM_SUPPORT 	25
#define MAX_DNS_SM_SUPPORT 	15
#define MAX_AAA_SM_SUPPORT 	5
#define	MAX_UNM_SM_SUPPORT 	4

#define MAX_PEERING_IP	2000

/* 0.3 Million Sessions / Session Manager */
#define TCP_SESSION_POOL_ARRAY_ELEMENTS		100
#define TCP_SESSION_POOL_ARRAY_SIZE			1000

#define UDP_SESSION_POOL_ARRAY_ELEMENTS		100
#define UDP_SESSION_POOL_ARRAY_SIZE			35000

#define DNS_SESSION_POOL_ARRAY_ELEMENTS		100
#define DNS_SESSION_POOL_ARRAY_SIZE			1000

#define AAA_SESSION_POOL_ARRAY_ELEMENTS		100
#define AAA_SESSION_POOL_ARRAY_SIZE			1000

#define UNM_SESSION_POOL_ARRAY_ELEMENTS		100
#define UNM_SESSION_POOL_ARRAY_SIZE			1000

#define MAX_FLUSHER_SUPPORT					8
#define MAX_UNM_FLUSHER_SUPPORT				2

//#define IP_POOL_ARRAY_ELEMENTS				100		//Poosible values 10, 100, 1000, 10000, 100000....
//#define IP_FLUSH_POOL_ARRAY_ELEMENTS		100		//Poosible values 10, 100, 1000, 10000, 100000....
//#define IP_FLUSH_POOL_ARRAY_SIZE			5000
//#define DNS_FLUSH_POOL_ARRAY_ELEMENTS		100		//Poosible values 10, 100, 1000, 10000, 100000....
//#define DNS_FLUSH_POOL_ARRAY_SIZE			3000

// 10,00,000
#define AAA_ACCESS_REQUEST			1
#define AAA_ACCESS_ACCEPT			2
#define AAA_ACCESS_REJECT			3

#define AAA_ACCOUNTING_REQUEST		4
#define AAA_ACCOUNTING_RESPONSE		5

#define	AAA_ACCOUNTING_START		1
#define	AAA_ACCOUNTING_STOP			2
#define AAA_ACCOUNTING_UPDATE		3

#define DNS_HDR_LEN			12

//#define XDR_MAX_LEN					32000
#define VPS_MAX_LEN					14000
#define VPS_SINGLE_ELEMENT_SIZE		30
#define XDR_RECORDS_BATCH_SIZE		1000

#define SESSION_ID_LEN  	40		//sip_sp_dip_dp_appid
#define APN_LEN		 		50
#define URL_LEN		 		50
#define HTTP_AGENT_LEN		100
#define DESC_LEN			100

#define MAC_ADDR_LEN		18
#define IPV6_ADDR_LEN 		46
#define SESSION_KEY_LEN		100
#define DNS_RESOLVED_IP		100

#define AAA_USER_NAME_LEN	33
#define AAA_USER_ID_LEN		50
#define AAA_USER_OLT_LEN	100
#define AAA_USER_POLICY_LEN	50
#define AAA_USER_PLAN_LEN	50

#define XDR_ID_IP 			10
#define XDR_ID_DNS			12
#define XDR_ID_AAA 			30

#define FLUSH_TYPE_CLEANUP 			40

enum dnsResponse
{
	QUERY 		= 0,
	RESPONSE 	= 1,
	STATUS 		= 2,
	UNASSIGNED 	= 3,
	NOTIFY 		= 4,
	UPDATE 		= 5,
	SUCCESS		= 6
};

typedef enum
{
	SYSTEM_CLEANUP_TCP_CONN_DATA		= 10,
	SYSTEM_CLEANUP_TCP_CONN_NODATA		= 11,
	SYSTEM_CLEANUP_TCP_NOCONN_DATA		= 12,
	SYSTEM_CLEANUP_TCP_NOCONN_NODATA	= 13,
	SYSTEM_CLEANUP_UDP_DATA				= 14,
	SYSTEM_CLEANUP_LONG_SESSION			= 16,
	SYSTEM_CLEANUP_TCP_DATA				= 17,
	SYSTEM_CLEANUP_END_OF_DAY_TCP_DATA	= 18,
	SYSTEM_CLEANUP_END_OF_DAY_UDP_DATA	= 19,

	SESSION_TERM_TCP_FIN_RECEIVED		= 20,
	SESSION_TERM_TCP_CONN_NODATA		= 21,
	SESSION_TERM_TCP_NOCONN_DATA		= 22,
	SESSION_TERM_TCP_NOCONN_NODATA		= 23,
	SESSION_TERM_TCP_OVERWRITE			= 24,
	SESSION_TERM_DNS_QUERY_SUCCESS		= 25,


	SYSTEM_PKTLIMIT_TCP_CONN_DATA		= 30,
	SYSTEM_PKTLIMIT_TCP_NOCONN_DATA		= 31,
	SYSTEM_PKTLIMIT_UDP_DATA			= 32,

	SYSTEM_TIMEOUT_TCP_CONN_DATA		= 33,
	SYSTEM_TIMEOUT_TCP_NOCONN_DATA		= 34,
	SYSTEM_TIMEOUT_UDP_DATA				= 35,

	DUPLICATE_SYN						= 40,
	FIN_NO_SESSION						= 50,

	SYSTEM_CLEANUP_DNS_QUERY			= 99,

}causeCode;

typedef enum
{
	TCP_FIN	= 1,
	TCP_LIMIT = 2,
	TCP_CLEAN = 3
}flushType;

typedef enum
{
	UD_SYN_TSVAL = 1,
	UD_SYSACK_TSVAL,
	UD_SYN_LATENCY,
	UD_TCP_DATA,
	UD_TCP_DISCONN,
	UD_UDP_DATA,
	CR_TCP_SESSION,
	CR_UDP_SESSION,
	UD_HTTP_DATA_REQ,
	UD_HTTP_DATA_RSP,
	UP_TCP_DATA_SLICE,
	TCP_UNKNOWN_PACKET_TYPE
}tcp_udp_commands;

typedef enum
{
	SYN_RCV = 1,
	SYN_ACK_RCV,
	ACK_RCV,
	CONNECTED,
	DATA_RCV,
	FIN_RCV,
}TcpState;

typedef enum {
	DNS_PORT 		= 53,
	HTTP_PORT 		= 80,
	SYSLOG_PORT		= 514,
	HTTPS_PORT 		= 443,
	GTPU_PORT 		= 2152,
	GTPC_PORT 		= 2123,
	GTPC_PORT1 		= 3386,
	HTTP_PORT1 		= 8080,
	GX_PORT			= 3868,
	RADIUS_AUTH		= 1812,
	RADIUS_ACCO 	= 1813,
	RADIUS_AUTH1	= 31812,
	RADIUS_ACCO1 	= 31813
};

typedef struct _dnsSession
{
	uint8_t		ipVer;
	uint8_t		errorCode;
	uint16_t	sPort;
	uint16_t	dPort;
	uint16_t	state;
	uint16_t	flushType;
	uint32_t	transactionId;
	uint32_t 	sIpv4;
	uint32_t 	dIpv4;
	uint32_t	causeCode;
	uint32_t	poolIndex;
	uint64_t 	queryStartEpochSec;
	uint64_t	queryEndEpochSec;
	uint64_t 	queryStartEpochNanoSec;
	uint64_t	queryEndEpochNanoSec;
	uint64_t	sessionV4Key;
	char		sIpv6[IPV6_ADDR_LEN];
	char		dIpv6[IPV6_ADDR_LEN];
	char 		url[URL_LEN];
	char 		errorDesc[DESC_LEN];
	string		sessionV6Key;

	_dnsSession()
	{ reset(); }

	void set(const _dnsSession *obj)
	{
		this->ipVer 		= obj->ipVer;
		this->errorCode 	= obj->errorCode;
		this->sPort 		= obj->sPort;
		this->dPort 		= obj->dPort;
		this->state			= obj->state;
		this->flushType 	= obj->flushType;
		this->transactionId = obj->transactionId;
		this->sIpv4 		= obj->sIpv4;
		this->dIpv4 		= obj->dIpv4;
		this->causeCode 	= obj->causeCode;
		this->poolIndex 	= obj->poolIndex;
		this->queryStartEpochSec 	= obj->queryStartEpochSec;
		this->queryEndEpochSec 		= obj->queryEndEpochSec;
		this->queryStartEpochNanoSec= obj->queryStartEpochNanoSec;
		this->queryEndEpochNanoSec 	= obj->queryEndEpochNanoSec;
		this->sessionV4Key 	= obj->sessionV4Key;
		strcpy(this->sIpv6, obj->sIpv6);
		strcpy(this->dIpv6, obj->dIpv6);
		strcpy(this->url, obj->url);
		strcpy(this->errorDesc, obj->errorDesc);
		this->sessionV6Key 	= obj->sessionV6Key;
	}

	void copy(const _dnsSession* obj)
	{
		this->ipVer 		= obj->ipVer;
		this->errorCode 	= obj->errorCode;
		this->sPort 		= obj->sPort;
		this->dPort 		= obj->dPort;
		this->state			= obj->state;
		this->flushType 	= obj->flushType;
		this->transactionId = obj->transactionId;
		this->sIpv4 		= obj->sIpv4;
		this->dIpv4 		= obj->dIpv4;
		this->causeCode 	= obj->causeCode;
		this->poolIndex 	= obj->poolIndex;
		this->queryStartEpochSec 	= obj->queryStartEpochSec;
		this->queryEndEpochSec 		= obj->queryEndEpochSec;
		this->queryStartEpochNanoSec= obj->queryStartEpochNanoSec;
		this->queryEndEpochNanoSec 	= obj->queryEndEpochNanoSec;
		this->sessionV4Key 	= obj->sessionV4Key;
		strcpy(this->sIpv6, obj->sIpv6);
		strcpy(this->dIpv6, obj->dIpv6);
		strcpy(this->url, obj->url);
		strcpy(this->errorDesc, obj->errorDesc);
		this->sessionV6Key 	= obj->sessionV6Key;
	}
	void reset()
	{
		this->ipVer 		= 0;
		this->errorCode 	= 0;
		this->sPort 		= 0;
		this->dPort 		= 0;
		this->state			= 0;
		this->flushType 	= 0;
		this->transactionId = 0;
		this->sIpv4 		= 0;
		this->dIpv4 		= 0;
		this->causeCode 	= 0;
		this->poolIndex 	= 0;
		this->queryStartEpochSec 	= 0;
		this->queryEndEpochSec 		= 0;
		this->queryStartEpochNanoSec= 0;
		this->queryEndEpochNanoSec 	= 0;
		this->sessionV4Key 	= 0;
		this->sIpv6[0]		= 0;
		this->dIpv6[0]		= 0;
		this->url[0]		= 0;
		this->errorDesc[0]	= 0;
		this->sessionV6Key.clear();
	}
}dnsSession;


typedef struct _udpSession
{
    uint8_t		ipVer;
	uint8_t		causeCode;
	uint8_t		pType;
    bool	 	staticIp;
    uint16_t 	sPort;
    uint16_t 	dPort;
    uint16_t 	upPLoadPkt;
    uint16_t 	dnPLoadPkt;
    uint16_t 	totalFrCount;
	uint16_t	smInstanceId;
	uint16_t	flushOrgId;
	uint16_t	routerLocationId;
    uint32_t	sIpv4;
    uint32_t	dIpv4;
    uint32_t	upPLoadSize;
    uint32_t	dnPLoadSize;
	uint32_t	mapIndex;
	uint32_t	poolIndex;

    uint64_t 	pckArivalTimeEpochSec;
    uint64_t 	pckLastTimeEpochSec;

    uint64_t	startTimeEpochSec;
    uint64_t	endTimeEpochSec;

    uint64_t	sessionIpV4Key;
    std::string ipV6sessionKey;
	uint64_t 	flushTime;
    char 		userId[IPV6_ADDR_LEN];
    char		sIpv6[IPV6_ADDR_LEN];
    char		dIpv6[IPV6_ADDR_LEN];

	~_udpSession(){}

	_udpSession()
	{ reset(); }

	void reset()
	{
		this->ipVer 		= 0;
		this->causeCode		= 0;
		this->pType			= 0;
		this->staticIp		= false;
		this->sPort			= 0;
		this->dPort			= 0;
		this->upPLoadPkt	= 0;
		this->dnPLoadPkt	= 0;
		this->totalFrCount	= 0;
		this->smInstanceId	= 0;
		this->flushOrgId	= 0;
		this->routerLocationId	= 0;
		this->sIpv4			= 0;
		this->dIpv4			= 0;
		this->upPLoadSize	= 0;
		this->dnPLoadSize	= 0;
	    this->mapIndex		= 0;
	    this->poolIndex		= 0;

	    this->pckArivalTimeEpochSec		= 0;
	    this->pckLastTimeEpochSec		= 0;
	    this->startTimeEpochSec			= 0;
	    this->endTimeEpochSec			= 0;

	    this->sessionIpV4Key			= 0;
	    ipV6sessionKey.clear();
	    this->flushTime					= 0;
	    userId[0] = 0;
	    sIpv6[0] = 0;
	    dIpv6[0] = 0;
	}

	void reuse()
	{
		this->totalFrCount 	= 0;

		this->upPLoadPkt	= 0;
		this->dnPLoadPkt	= 0;

		this->upPLoadSize 	= 0;
		this->dnPLoadSize 	= 0;

		this->pckArivalTimeEpochSec		= 0;
		this->startTimeEpochSec			= pckLastTimeEpochSec;
		this->pckLastTimeEpochSec		= 0;
		this->endTimeEpochSec		= 0;
		this->pckLastTimeEpochSec 		= 0;
	}

	_udpSession(const _udpSession& obj)
	{
		this->ipVer 		= obj.ipVer;
		this->causeCode		= obj.causeCode;
		this->pType			= obj.pType;
		this->staticIp		= obj.staticIp;
		this->sPort			= obj.sPort;
		this->dPort			= obj.dPort;
		this->upPLoadPkt	= obj.upPLoadPkt;
		this->dnPLoadPkt	= obj.dnPLoadPkt;
		this->totalFrCount	= obj.totalFrCount;
		this->smInstanceId	= obj.smInstanceId;
		this->flushOrgId	= obj.flushOrgId;
		this->routerLocationId	= obj.routerLocationId;
		this->sIpv4			= obj.sIpv4;
		this->dIpv4			= obj.dIpv4;
		this->upPLoadSize	= obj.upPLoadSize;
		this->dnPLoadSize	= obj.dnPLoadSize;
	    this->mapIndex		= obj.mapIndex;
	    this->poolIndex		= obj.poolIndex;

	    this->pckArivalTimeEpochSec		= obj.pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec		= obj.pckLastTimeEpochSec;
	    this->startTimeEpochSec			= obj.startTimeEpochSec;
	    this->endTimeEpochSec			= obj.endTimeEpochSec;

	    this->sessionIpV4Key			= obj.sessionIpV4Key;
	    this->ipV6sessionKey 			= obj.ipV6sessionKey;
	    this->flushTime					= obj.flushTime;
	    strcpy(this->userId, obj.userId);
	    strcpy(this->sIpv6, obj.sIpv6);
	    strcpy(this->dIpv6, obj.dIpv6);
	}

	void copy(const _udpSession* obj)
	{
		this->ipVer 		= obj->ipVer;
		this->causeCode		= obj->causeCode;
		this->pType			= obj->pType;
		this->staticIp		= obj->staticIp;
		this->sPort			= obj->sPort;
		this->dPort			= obj->dPort;
		this->upPLoadPkt	= obj->upPLoadPkt;
		this->dnPLoadPkt	= obj->dnPLoadPkt;
		this->totalFrCount	= obj->totalFrCount;
		this->smInstanceId	= obj->smInstanceId;
		this->flushOrgId	= obj->flushOrgId;
		this->routerLocationId	= obj->routerLocationId;
		this->sIpv4			= obj->sIpv4;
		this->dIpv4			= obj->dIpv4;
		this->upPLoadSize	= obj->upPLoadSize;
		this->dnPLoadSize	= obj->dnPLoadSize;
	    this->mapIndex		= obj->mapIndex;
	    this->poolIndex		= obj->poolIndex;

	    this->pckArivalTimeEpochSec		= obj->pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec		= obj->pckLastTimeEpochSec;
	    this->startTimeEpochSec			= obj->startTimeEpochSec;
	    this->endTimeEpochSec			= obj->endTimeEpochSec;

	    this->sessionIpV4Key			= obj->sessionIpV4Key;
	    this->ipV6sessionKey 			= obj->ipV6sessionKey;
	    this->flushTime					= obj->flushTime;
	    strcpy(this->userId, obj->userId);
	    strcpy(this->sIpv6, obj->sIpv6);
	    strcpy(this->dIpv6, obj->dIpv6);
	}
}udpSession;

typedef struct _aaaSession
{
	uint8_t 	ipVer;
	int16_t		nasPortType;
	uint16_t	appPort;
	uint16_t 	sPort;
	uint16_t 	dPort;
	uint16_t 	reqCode;
	uint16_t 	respCode;
	uint16_t	packetIdentifier;
	uint16_t	mapIndex;
	uint16_t	flushType;
	uint32_t	accStatusType;
	uint32_t	serviceType;
	uint32_t	protocol;
	uint32_t 	sourceAddr;
	uint32_t	accTerminationCause;
	uint32_t 	destAddr;
	uint32_t	accAuth;
	uint32_t	framedIpLong;
	uint32_t	inputOctets;
	uint32_t	outputOctets;
	uint32_t	inputPackets;
	uint32_t	outputPackets;
	uint32_t	inputGigaWords;
	uint32_t	outputGigaWords;
	uint64_t 	StartTimeEpochMiliSec;
	uint64_t 	EndTimeEpochMiliSec;
	uint64_t	StartTimeEpochSec;
	uint64_t	EndTimeEpochSec;
	uint64_t	aaaKey;
	uint64_t 	flushTime;
	char 		sourceMacAddr[MAC_ADDR_LEN];
	char 		destMacAddr[MAC_ADDR_LEN];
	char		userName[AAA_USER_NAME_LEN];
	char		nasIP[16];
	char 		callingStationId[50];
	char		nasIdentifier[35];
	char		replyMsg[35];
	char		userMac[MAC_ADDR_LEN];
	char		userIpV6[IPV6_ADDR_LEN];
	bool		ipv6AddressPrefixFlag;

	~_aaaSession(){}

	_aaaSession()
	{ reset(); }

	void reset()
	{
		StartTimeEpochMiliSec = 0;
		EndTimeEpochMiliSec = 0;
		StartTimeEpochSec	= 0;
		EndTimeEpochSec		= 0;
		sourceMacAddr[0] = 0;
		destMacAddr[0] = 0;
		appPort = 0;
		sourceAddr = 0;
		destAddr = 0;
		sPort = 0;
		dPort = 0;
		ipVer = 0;
		reqCode = 0;
		respCode = 0;
		packetIdentifier = 0;

		protocol = 0;
		nasPortType = -1;
		serviceType = 0;
		accStatusType = 0;
		accTerminationCause = 0;
		aaaKey = 0;
		accAuth = 0;
		mapIndex = 0;
		flushTime = 0;
		flushType = 0;

		userName[0] = 0;
		framedIpLong = 0;
		strcpy(nasIP, "NA");

		strcpy(callingStationId, "NA");
		strcpy(nasIdentifier, "NA");
		replyMsg[0] = 0;
		userMac[0] = 0;
		strcpy(userIpV6, "NA");
		ipv6AddressPrefixFlag = false;
		inputOctets	= 0;
		outputOctets	= 0;
		inputPackets	= 0;
		outputPackets	= 0;
		inputGigaWords = 0;
		outputGigaWords = 0;
	}

	_aaaSession(const _aaaSession& obj)
	{
		this->StartTimeEpochMiliSec 	= obj.StartTimeEpochMiliSec;
		this->EndTimeEpochMiliSec 		= obj.EndTimeEpochMiliSec;
		this->StartTimeEpochSec			= obj.StartTimeEpochSec;
		this->EndTimeEpochSec			= obj.EndTimeEpochSec;
		strcpy(this->sourceMacAddr, obj.sourceMacAddr);
		strcpy(this->destMacAddr, obj.destMacAddr);
		this->appPort					= obj.appPort;
		this->sourceAddr 				= obj.sourceAddr;
		this->destAddr 					= obj.destAddr;
		this->sPort 				= obj.sPort;
		this->dPort 					= obj.dPort;
		this->ipVer						= obj.ipVer;
		this->reqCode					= obj.reqCode;
		this->respCode					= obj.respCode;

		this->packetIdentifier 			= obj.packetIdentifier;

		this->protocol 					= obj.protocol;
		this->nasPortType 				= obj.nasPortType;
		this->serviceType 				= obj.serviceType;
		this->accStatusType 			= obj.accStatusType;
		this->accTerminationCause 		= obj.accTerminationCause;
		this->aaaKey 			= obj.aaaKey;
		this->accAuth 					= obj.accAuth;
		this->mapIndex 					= obj.mapIndex;
		this->flushTime					= obj.flushTime;
		this->flushType					= obj.flushType;
		strcpy(this->userName, obj.userName);
		this->framedIpLong				= obj.framedIpLong;

		strcpy(this->nasIP, obj.nasIP);
		strcpy(this->callingStationId, obj.callingStationId);
		strcpy(this->nasIdentifier, obj.nasIdentifier);
		strcpy(this->replyMsg, obj.replyMsg);
		strcpy(this->userMac, obj.userMac);
		strcpy(this->userIpV6, obj.userIpV6);
		this->ipv6AddressPrefixFlag = obj.ipv6AddressPrefixFlag;
		this->inputOctets 	= obj.inputOctets;
		this->outputOctets	= obj.outputOctets;
		this->inputPackets  = obj.inputPackets;
		this->outputPackets = obj.outputPackets;
		this->inputGigaWords 	= obj.inputGigaWords;
		this->outputGigaWords	= obj.outputGigaWords;
	}

	void copy(const _aaaSession* obj)
	{
		this->StartTimeEpochMiliSec 	= obj->StartTimeEpochMiliSec;
		this->EndTimeEpochMiliSec 		= obj->EndTimeEpochMiliSec;
		this->StartTimeEpochSec			= obj->StartTimeEpochSec;
		this->EndTimeEpochSec			= obj->EndTimeEpochSec;

		strcpy(this->sourceMacAddr, obj->sourceMacAddr);
		strcpy(this->destMacAddr, obj->destMacAddr);
		this->appPort					= obj->appPort;
		this->sourceAddr 				= obj->sourceAddr;
		this->destAddr 					= obj->destAddr;
		this->sPort 				= obj->sPort;
		this->dPort 					= obj->dPort;
		this->ipVer						= obj->ipVer;
		this->reqCode					= obj->reqCode;
		this->respCode					= obj->respCode;

		this->packetIdentifier 			= obj->packetIdentifier;

		this->protocol 					= obj->protocol;
		this->nasPortType 				= obj->nasPortType;
		this->serviceType 				= obj->serviceType;
		this->accStatusType 			= obj->accStatusType;
		this->accTerminationCause 		= obj->accTerminationCause;
		this->aaaKey 			= obj->aaaKey;
		this->accAuth 					= obj->accAuth;
		this->mapIndex 					= obj->mapIndex;
		this->flushTime					= obj->flushTime;
		this->flushType					= obj->flushType;
		strcpy(this->userName, obj->userName);
		this->framedIpLong				= obj->framedIpLong;
		strcpy(this->nasIP, obj->nasIP);
		strcpy(this->callingStationId, obj->callingStationId);
		strcpy(this->nasIdentifier, obj->nasIdentifier);
		strcpy(this->replyMsg, obj->replyMsg);
		strcpy(this->userMac, obj->userMac);
		strcpy(this->userIpV6, obj->userIpV6);
		this->ipv6AddressPrefixFlag = obj->ipv6AddressPrefixFlag;
		this->inputOctets 	= obj->inputOctets;
		this->outputOctets	= obj->outputOctets;
		this->inputPackets  = obj->inputPackets;
		this->outputPackets = obj->outputPackets;
		this->inputGigaWords 	= obj->inputGigaWords;
		this->outputGigaWords	= obj->outputGigaWords;
	}
}aaaSession;

namespace initSection
{
	extern std::map<uint8_t, std::string> protocolName;
	extern std::map<uint16_t, std::string> dnsErrorCode;
	extern std::map<uint16_t, std::string> tcpPorts;
	extern std::map<uint32_t, std::string> radiusCodeMap;
	extern std::map<uint32_t, std::string> serviceTypeMap;
	extern std::map<uint32_t, std::string> framedProtocolMap;
	extern std::map<uint32_t, std::string> acctAuthenticMap;
	extern std::map<uint32_t, std::string> acctTeminateMap;
	extern std::map<uint32_t, std::string> acctStatusMap;
	extern std::map<uint32_t, std::string> nasPortTypeMap;
	extern std::map<uint32_t, std::string> ipSubNetMap;
	extern std::map<uint32_t, uint16_t> routerIdMap;
	extern std::map<uint16_t, uint16_t> ipMappingMap;
	extern std::map<uint32_t, uint16_t> staticIpPoolMap;
}

namespace IPStats
{
	extern uint64_t dnsLookupMapSize;

	extern uint32_t tcpV4SessionScanned[MAX_TCP_SM_SUPPORT];
	extern uint32_t tcpV4SessionCleaned[MAX_TCP_SM_SUPPORT];
	extern uint32_t tcpV4SessionTotalCnt[MAX_TCP_SM_SUPPORT];

	extern uint32_t tcpV6SessionScanned[MAX_TCP_SM_SUPPORT];
	extern uint32_t tcpV6SessionCleaned[MAX_TCP_SM_SUPPORT];
	extern uint32_t tcpV6SessionTotalCnt[MAX_TCP_SM_SUPPORT];

	extern uint32_t udpV4SessionScanned[MAX_UDP_SM_SUPPORT];
	extern uint32_t udpV4SessionCleaned[MAX_UDP_SM_SUPPORT];
	extern uint32_t udpV4SessionTotalCnt[MAX_UDP_SM_SUPPORT];

	extern uint32_t udpV6SessionScanned[MAX_UDP_SM_SUPPORT];
	extern uint32_t udpV6SessionCleaned[MAX_UDP_SM_SUPPORT];
	extern uint32_t udpV6SessionTotalCnt[MAX_UDP_SM_SUPPORT];

	extern uint32_t dnsV4SessionScanned[MAX_DNS_SM_SUPPORT];
	extern uint32_t dnsV4SessionCleaned[MAX_DNS_SM_SUPPORT];
	extern uint32_t dnsV4SessionTotalCnt[MAX_DNS_SM_SUPPORT];

	extern uint32_t dnsV6SessionScanned[MAX_DNS_SM_SUPPORT];
	extern uint32_t dnsV6SessionCleaned[MAX_DNS_SM_SUPPORT];
	extern uint32_t dnsV6SessionTotalCnt[MAX_DNS_SM_SUPPORT];

	extern uint32_t unTcpSessionCnt[MAX_UNM_SM_SUPPORT];
	extern uint32_t unTcpSessionScanned[MAX_UNM_SM_SUPPORT];
	extern uint32_t unTcpSessionCleaned[MAX_UNM_SM_SUPPORT];

	extern uint32_t unUdpSessionCnt[MAX_UNM_SM_SUPPORT];
	extern uint32_t unUdpSessionScanned[MAX_UNM_SM_SUPPORT];
	extern uint32_t unUdpSessionCleaned[MAX_UNM_SM_SUPPORT];

	extern uint32_t aaaAccessSessionCnt[MAX_AAA_SM_SUPPORT];
	extern uint32_t aaaAccessSessionScanned[MAX_AAA_SM_SUPPORT];
	extern uint32_t aaaAccessSessionCleaned[MAX_AAA_SM_SUPPORT];

	extern uint32_t aaaAccounSessionCnt[MAX_AAA_SM_SUPPORT];
	extern uint32_t aaaAccounSessionScanned[MAX_AAA_SM_SUPPORT];
	extern uint32_t aaaAccounSessionCleaned[MAX_AAA_SM_SUPPORT];
}

namespace DNSGlobal
{
	extern std::map<uint32_t, std::string> dnsLookUpMap[10];
	extern std::map<std::string, std::string> dnsV6LookUpMap;
	extern std::map<uint32_t, uint32_t> dnsSubnetMap;
}

typedef struct _userInfo
{
	char 		userName[IPV6_ADDR_LEN];					/* User Name */
	uint32_t	allocatedIpLong;						/* User Ip Long */
	uint32_t	oldAllocatedIpLong;						/* User Ip Long */

	~_userInfo(){};

	_userInfo()
	{ reset(); }

	void reset()
	{
		userName[0]  = 0;
		allocatedIpLong = 0;
		oldAllocatedIpLong = 0;
    }
}userInfo;

namespace aaaGlbMap
{
	extern std::map<uint32_t, userInfo> aaaGlbUserIpMap;	/* 01295072520@airtelbroadband.in */
	extern std::map<string, userInfo> aaaGlbUserIdMap;
	extern std::map<std::string, userInfo> aaaGlbIpv6UserMap;
//	extern std::map<uint32_t, uint32_t> publicPrivateMap[8][8][26];
	extern std::map<uint32_t, uint32_t> publicPrivateMap[8][8][100];
}

namespace mapDnsLock
{
	extern pthread_mutex_t lockCount;
	extern pthread_cond_t nonzero;
	extern unsigned count;
}

namespace mapAAALock
{
	extern pthread_mutex_t lockCount;
	extern pthread_cond_t nonzero;
	extern unsigned count;
}

class SmGlobal
{
	public:
		SmGlobal();
		~SmGlobal();
};

#endif /* INC_IPGLOBAL_H_ */
