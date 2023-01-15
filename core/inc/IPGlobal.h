/*
 * TCPGlobal.h
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#ifndef INC_IPGLOBAL_H_
#define INC_IPGLOBAL_H_

#include <pthread.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <list>
#include <queue>
#include <array>
#include <bitset>
#include <sstream>
#include <unordered_set>

#include "GConfig.h.bck"
#include "SpectaTypedef.h"
#include "SmGlobal.h"

using namespace std;

#define UDP_HDR_LEN		8
#define DNS_HDR_LEN		12
#define URL_LEN		 	50
#define NETFLOW_HDR_LEN	20

#define IPV4FLOWSIZE	76
#define IPV6FLOWSIZE	140

#define ETH_IP        	0x0800          /* Internet Protocol packet     */
#define ETH_8021Q     	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_IPV6    	0x86DD          /* IPv6 over bluebook           */
#define ETH_MPLS_UC   	0x8847          /* MPLS Unicast traffic         */
#define ETH_PPP_SES   	0x8864          /* PPPoE session messages       */

#define MAX_INTERFACE_SUPPORT				8
#define MAX_ROUTER_PER_INTERFACE_SUPPORT 	8
#define MAX_AGENT_SUPPORT					40
#define MAX_FLUSHER_SUPPORT					12

#define XDR_MAX_LEN							2000

#define PKT_WRITE_TIME_INDEX(epochsec,ti) ( ((epochsec % ti) + 1) >= ti ? 0 : ((epochsec % ti) + 1) )
#define PKT_READ_TIME_INDEX(epochsec,ti) ( epochsec % ti )
#define PKT_READ_NEXT_TIME_INDEX(idx,ti) ( (idx+1) >= ti ? 0 : (idx+1) )

#define NEXT_TIME_INDEX(idx) ( (idx+1) >= 10 ? 0 : (idx+1) )


//Every 5 secs packets are stored in one single time index and there are 5 time index for SM
#define SM_READ_TIME_INDEX(epochsec,tim) ( (epochsec % (tim)) / 5 )
#define SM_NEXT_TIME_INDEX(idx,ti) ( (idx+1) >= ti ? 0 : (idx+1) )


namespace GContainer
{ extern GConfig *config; }


typedef enum
{
	PACKET_IPPROTO_IP 		= 0,	/** Dummy protocol for TCP		*/
	PACKET_IPPROTO_HOPOPTS 	= 0,	/** IPv6 Hop-by-Hop options		*/
	PACKET_IPPROTO_ICMP 	= 1,	/** Internet Control Message Protocol */
	PACKET_IPPROTO_IGMP 	= 2,	/** Internet Group management Protocol */
	PACKET_IPPROTO_IPIP 	= 4,	/** IPIP tunnels (older KA9Q tunnels use 94) */
	PACKET_IPPROTO_TCP		= 6,	/** Transmission Control Protocol	*/
	PACLET_IPPROTO_EGP 		= 8,	/** Exterior Gateway Protocol */
	PACKET_IPPROTO_PUP 		= 12,	/** PUP Protocol */
	PACKET_IPPROTO_UDP 		= 17,	/** User Datagram Protocol		*/
	PACKET_IPPROTO_DNS 		= 18,	/** DNS		*/
	PACKET_IPPROTO_IDP 		= 22,	/** XNS IDP protocol */
	PACKET_IPPROTO_TP 		= 29,	/** SO Transport Protocol Class 4. */
	PACKET_IPPROTO_DCCP 	= 33,	/** Datagram Congestion Control Protocol. */
	PACKET_IPPROTO_IPV6 	= 41,	/** IPv6 header */
	PACKET_IPPROTO_ROUTING 	= 43,	/** IPv6 Routing header */
	PACKET_IPPROTO_FRAGMENT = 44,	/** IPv6 fragmentation header */
	PACKET_IPPROTO_RSVP 	= 46,	/** Reservation Protocol */
	PACKET_IPPROTO_GRE 		= 47,	/** General Routing Encapsulation */
	PACKET_IPPROTO_GTPU 	= 48,	/** GTPU Protocol		*/
	PACKET_IPPROTO_GTPC 	= 49,	/** GTPC Protocol		*/
	PACKET_IPPROTO_ESP 		= 50,	/** encapsulating security Payload */
	PACKET_IPPROTO_AH 		= 51,	/** Authentication header */
	PACKET_IPPROTO_GX 		= 52,	/** GTPU Protocol		*/
	PACKET_IPPROTO_RADIUS 	= 53,	/** RADIUS Protocol		*/
	PACKET_IPPROTO_ICMPV6 	= 58,	/** ICMPV6 */
	PACKET_IPPROTO_NONE 	= 59,	/** IPv6 no next header */
	PACKET_IPPROTO_DSTOPTS 	= 60,	/** IPv6 destination options */
	PACKET_IPPROTO_MTP 		= 92,	/** Multicast Transport Protocol */
	PACKET_IPPROTO_ENCAP 	= 98,	/** Encapsulation Header */
	PACKET_IPPROTO_PIM 		= 103,	/** Protocol Independent Multicast */
	PACKET_IPPROTO_COMP 	= 108,	/** Compression Header Protocol */
	PACKET_IPPROTO_SCTP 	= 132,	/** SCTP Protocol		*/
	PACKET_IPPROTO_UDPLITE 	= 136,	/** UDP-Lite protocol */
	PACKET_IPPROTO_RAW 		= 255	/** Raw IP Packets */
}IPProtocolTypes;

typedef struct _xdrStore
{
	stringstream xdr;

	_xdrStore()
	{
		reset();
	}
	_xdrStore(const _xdrStore& obj)
	{
		this->xdr << obj.xdr.rdbuf();
	}
	void copy(const _xdrStore* obj)
	{
		this->xdr << obj->xdr.rdbuf();
	}
	void reset()
	{
		this->xdr << "";
	}
}xdrStore;

typedef struct _RawPkt
{
	uint16_t	len;
	uint32_t 	tv_sec;
	BYTE		pkt;

	_RawPkt(int rawPckSize) {
		reset();
		pkt = (BYTE) malloc(rawPckSize);
	}

	_RawPkt(const _RawPkt& rpkt) {
		len 	= rpkt.len;
		tv_sec 	= rpkt.tv_sec;
		pkt 	= rpkt.pkt;
	}

	void copy(const _RawPkt* rpkt) {
		len 	= rpkt->len;
		tv_sec 	= rpkt->tv_sec;
		pkt 	= rpkt->pkt;
	}

	void operator=(const _RawPkt& rpkt) {
		len 	= rpkt.len;
		tv_sec 	= rpkt.tv_sec;
		pkt 	= rpkt.pkt;
	}

	void reset() {
		len = 0;
		tv_sec = 0;
	}

}RawPkt;

typedef struct _cFlow
{
	uint8_t		noOfFlows;
	uint8_t		ipVersion;
	uint8_t		direction;
	uint16_t 	srcPort;
	uint16_t 	dstPort;
	uint32_t	pLoad;
	uint16_t	locationId;
	uint32_t 	srcIpv4;
	uint32_t	dstIpv4;
	uint32_t	sEpochSec;
	char		srcIpv6[40];
	char		dstIpv6[40];

	_cFlow()
	{ reset(); }

	void reset()
	{
		this->noOfFlows		= 0;
		this->ipVersion		= 0;
		this->direction		= 0;
		this->srcPort		= 0;
		this->dstPort		= 0;
		this->pLoad			= 0;
		this->locationId	= 0;
		this->srcIpv4		= 0;
		this->dstIpv4		= 0;
		this->sEpochSec		= 0;
		this->srcIpv6[0]	= 0;
		this->dstIpv6[0]	= 0;
	}

	_cFlow(const _cFlow& cFlowPkt)
	{
		this->noOfFlows		= cFlowPkt.noOfFlows;
		this->ipVersion		= cFlowPkt.ipVersion;
		this->direction		= cFlowPkt.direction;
		this->srcPort		= cFlowPkt.srcPort;
		this->dstPort		= cFlowPkt.dstPort;
		this->pLoad			= cFlowPkt.pLoad;
		this->locationId	= cFlowPkt.locationId;
		this->srcIpv4		= cFlowPkt.srcIpv4;
		this->dstIpv4		= cFlowPkt.dstIpv4;
		this->sEpochSec		= cFlowPkt.sEpochSec;
		strcpy(this->srcIpv6, cFlowPkt.srcIpv6);
		strcpy(this->dstIpv6, cFlowPkt.dstIpv6);
	}

	void copy(const _cFlow* cFlowPkt)
	{
		this->noOfFlows		= cFlowPkt->noOfFlows;
		this->ipVersion		= cFlowPkt->ipVersion;
		this->direction		= cFlowPkt->direction;
		this->srcPort		= cFlowPkt->srcPort;
		this->dstPort		= cFlowPkt->dstPort;
		this->pLoad			= cFlowPkt->pLoad;
		this->locationId	= cFlowPkt->locationId;
		this->srcIpv4		= cFlowPkt->srcIpv4;
		this->dstIpv4		= cFlowPkt->dstIpv4;
		strcpy(this->srcIpv6, cFlowPkt->srcIpv6);
		strcpy(this->dstIpv6, cFlowPkt->dstIpv6);
	}

}cFlow;


typedef struct _fortiGate
{
	string	subType;
	string 	srcPort;
	string 	dstPort;
	string	protocol;
	string	transIp;
	string	recByte;
	string	sendByte;
	string	sEpochSec;
	string	location;
	string	srcIpv6;
	string	dstIpv6;
	string	duration;
	string  sessionId;
	string	srcintf;
	string	dstintf;

	_fortiGate()
	{ reset(); }

	void reset()
	{
		subType.clear();
		srcPort.clear();
		dstPort.clear();
		protocol.clear();
		transIp.clear();
		recByte.clear();
		sendByte.clear();
		sEpochSec.clear();
		location.clear();
		srcIpv6.clear();
		dstIpv6.clear();
		duration.clear();
		sessionId.clear();
		srcintf.clear();
		dstintf.clear();
	}
}fortiGate;


typedef struct _headerInfo
{
	uint16_t 	pckLen;
	uint16_t 	ethLen;
	uint16_t	ipLen;
	uint16_t	udpLen;
	uint32_t 	netFlowLen;
	uint16_t	locationId;

	_headerInfo()
	{ reset(); }

	_headerInfo(const _headerInfo& hdr)
	{
		this->pckLen 	= hdr.pckLen;
		this->ethLen	= hdr.ethLen;
		this->ipLen		= hdr.ipLen;
		this->udpLen	= hdr.udpLen;
		this->netFlowLen= hdr.netFlowLen;
		this->locationId= hdr.locationId;
	}

	void copy(const _headerInfo* hdr)
	{
		this->pckLen 	= hdr->pckLen;
		this->ethLen	= hdr->ethLen;
		this->ipLen		= hdr->ipLen;
		this->udpLen	= hdr->udpLen;
		this->netFlowLen= hdr->netFlowLen;
		this->locationId= hdr->locationId;
	}

	void reset()
	{
		this->pckLen 	= 0;
		this->ethLen	= 0;
		this->ipLen		= 0;
		this->udpLen	= 0;
		this->netFlowLen= 0;
		this->locationId= 0;
	}
}headerInfo;


typedef struct _bwData
{
	uint64_t Bw;
	uint64_t upBw;
	uint64_t dnBw;

	uint64_t totalVol;
	uint64_t upTotalVol;
	uint64_t dnTotalVol;
	uint64_t avgTotalBw;
	uint64_t avgUpBw;
	uint64_t avgDnBw;
	uint64_t peakTotalVol;
	uint64_t peakUpTotalVol;
	uint64_t peakDnTotalVol;

	_bwData()
	{
		Bw = 0;
		upBw = 0;
		dnBw = 0;
		totalVol = 0;
		upTotalVol = 0;
		dnTotalVol = 0;
		avgTotalBw = 0;
		avgUpBw = 0;
		avgDnBw = 0;
		peakTotalVol = 0;
		peakUpTotalVol = 0;
		peakDnTotalVol = 0;
	}
}bwData;

namespace IPGlobal
{
	extern uint64_t	CURRENT_EPOCH_SEC;
	extern uint16_t	CURRENT_SEC;
	extern uint16_t	CURRENT_HOUR;
	extern uint16_t	CURRENT_MIN;
	extern uint16_t	CURRENT_DAY;
	extern uint16_t	CURRENT_MONTH;
	extern uint16_t	CURRENT_YEAR;
	extern uint16_t	THREAD_SLEEP_TIME;
	extern uint16_t	SESSION_SCAN_FREQ_SEC;
	extern uint16_t	SESSION_PKT_LIMIT;
	extern uint16_t	SESSION_TIME_LIMIT;
	extern uint16_t	UDP_CLEAN_UP_TIMEOUT_SEC;

	extern unordered_set<uint32_t> UniqueSourceIp;

	extern bool		PROBE_RUNNING_STATUS;
	extern bool		PROBE_STATS_RUNNING_STATUS;
	extern bool		PROBE_LOG_RUNNING_STATUS;

	extern bool		PKT_LISTENER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT];
	extern bool		PKT_LISTENER_DAYCHANGE_INDICATION[MAX_INTERFACE_SUPPORT];
	extern bool		PKT_LISTENER_INTF_MON_RUNNING_STATUS[MAX_INTERFACE_SUPPORT];
	extern uint16_t PKT_LISTENER_CPU_CORE[MAX_INTERFACE_SUPPORT];
	extern uint16_t TIMER_CPU_CORE;

	/* ---- */
	extern bool		ROUTER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
	extern uint16_t ROUTER_PER_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern uint16_t ROUTER_CPU_CORE[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

	/* ---- */
	extern bool		CFLOW_SM_RUNNING_STATUS[MAX_AGENT_SUPPORT];
	extern uint16_t	NO_OF_CFLOW_SM;
	extern uint16_t	CFLOW_SM_CPU_CORE[MAX_AGENT_SUPPORT];

	extern bool		FORTI_SM_RUNNING_STATUS[MAX_AGENT_SUPPORT];
	extern uint16_t	NO_OF_FORTI_SM;
	extern uint16_t	FORTI_SM_CPU_CORE[MAX_AGENT_SUPPORT];

	/* ---- */
	extern bool		FLUSHER_RUNNING_STATUS[MAX_FLUSHER_SUPPORT];
	extern uint16_t	NO_OF_FLUSHER;
	extern uint16_t	FLUSHER_CPU_CORE[MAX_AGENT_SUPPORT];

	extern uint16_t PROBE_ID;
	extern uint16_t LOG_LEVEL;
	extern std::string LOG_DIR;
	extern std::string XDR_DIR;
	extern std::string IP_DIR;
	extern std::string DATA_DIR;

	extern bool 	PRINT_STATS;
	extern bool 	PROCESS_CFLOW;
	extern bool 	PROCESS_FORTI;
	extern bool 	PROCESS_DNS;

	extern uint16_t PRINT_STATS_FREQ_SEC;
	extern uint16_t	LOG_STATS_FREQ_SEC;

	extern uint16_t	NO_OF_NIC_INTERFACE;
	extern uint16_t	NO_OF_SOLAR_INTERFACE;
	extern uint16_t NO_OF_INTERFACES;

	extern bool		TIMER_PROCESSING;

	extern	string 	ETHERNET_INTERFACES[MAX_INTERFACE_SUPPORT];
	extern	string 	SOLAR_INTERFACES[MAX_INTERFACE_SUPPORT];
	extern	string	PNAME[MAX_INTERFACE_SUPPORT];

	extern uint16_t	TIME_INDEX;
	extern uint32_t PPS_PER_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern uint16_t	PPS_CAP_PERCENTAGE[MAX_INTERFACE_SUPPORT];
	extern uint16_t	MAX_BW_INTERFACE[MAX_INTERFACE_SUPPORT];

	extern uint16_t	SOLARFLARE_HW_TIMESTAMP;
	extern bool		PACKET_PROCESSING[MAX_INTERFACE_SUPPORT];

	extern uint32_t		DISCARD_PKT_CNT[MAX_INTERFACE_SUPPORT];
	extern uint32_t 	PKT_RATE_INTF[MAX_INTERFACE_SUPPORT];
	extern uint64_t 	PKTS_TOTAL_INTF[MAX_INTERFACE_SUPPORT];
	extern uint64_t 	BW_MBPS_INTF[MAX_INTERFACE_SUPPORT];

    extern uint64_t discarded_packets_i_0;
    extern uint64_t discarded_packets_i_1;
    extern uint64_t discarded_packets_i_2;
    extern uint64_t discarded_packets_i_3;
    extern uint64_t discarded_packets_i_4;
    extern uint64_t discarded_packets_i_5;
    extern uint64_t discarded_packets_i_6;
    extern uint64_t discarded_packets_i_7;

    extern uint64_t discarded_packets_i_0;
    extern uint64_t discarded_packets_i_1;
    extern uint64_t discarded_packets_i_2;
    extern uint64_t discarded_packets_i_3;
    extern uint64_t discarded_packets_i_4;
    extern uint64_t discarded_packets_i_5;
    extern uint64_t discarded_packets_i_6;
    extern uint64_t discarded_packets_i_7;

	extern string	ADMIN_PORT;
	extern bool		ADMIN_FLAG;

	extern uint16_t	MAX_PKT_LEN_PER_INTERFACE[MAX_INTERFACE_SUPPORT];
	extern uint64_t	AGENT_PACKET_RECEIVED[MAX_AGENT_SUPPORT];

	extern uint32_t	GANDHINAGAR[MAX_PEERING_IP][2];
	extern uint16_t	GANDHINAGAR_COUNT;

	extern uint32_t	JUNAGADH[MAX_PEERING_IP][2];
	extern uint16_t	JUNAGADH_COUNT;

	extern uint32_t	NADIAD[MAX_PEERING_IP][2];
	extern uint16_t	NADIAD_COUNT;

	extern uint32_t	AHMEDABAD[MAX_PEERING_IP][2];
	extern uint16_t	AHMEDABAD_COUNT;

	extern uint32_t	ANAND[MAX_PEERING_IP][2];
	extern uint16_t	ANAND_COUNT;

	extern uint32_t	ANKLESHWAR[MAX_PEERING_IP][2];
	extern uint16_t	ANKLESHWAR_COUNT;

	extern uint32_t	BARDOLI[MAX_PEERING_IP][2];
	extern uint16_t	BARDOLI_COUNT;

	extern uint32_t	BARODA[MAX_PEERING_IP][2];
	extern uint16_t	BARODA_COUNT;

	extern uint32_t	BHARUCH[MAX_PEERING_IP][2];
	extern uint16_t	BHARUCH_COUNT;

	extern uint32_t	BHAVNAGAR[MAX_PEERING_IP][2];
	extern uint16_t	BHAVNAGAR_COUNT;

	extern uint32_t	BILIMORA[MAX_PEERING_IP][2];
	extern uint16_t	BILIMORA_COUNT;

	extern uint32_t	HALOL[MAX_PEERING_IP][2];
	extern uint16_t	HALOL_COUNT;

	extern uint32_t	JAIPUR[MAX_PEERING_IP][2];
	extern uint16_t	JAIPUR_COUNT;

	extern uint32_t	JAMNAGAR[MAX_PEERING_IP][2];
	extern uint16_t	JAMNAGAR_COUNT;

	extern uint32_t	KIM[MAX_PEERING_IP][2];
	extern uint16_t	KIM_COUNT;

	extern uint32_t	MEHSANA[MAX_PEERING_IP][2];
	extern uint16_t	MEHSANA_COUNT;

	extern uint32_t	MODASA[MAX_PEERING_IP][2];
	extern uint16_t	MODASA_COUNT;

	extern uint32_t	MORBI[MAX_PEERING_IP][2];
	extern uint16_t	MORBI_COUNT;

	extern uint32_t	NAVSARI[MAX_PEERING_IP][2];
	extern uint16_t	NAVSARI_COUNT;

	extern uint32_t	PATNA[MAX_PEERING_IP][2];
	extern uint16_t	PATNA_COUNT;

	extern uint32_t	PUNE[MAX_PEERING_IP][2];
	extern uint16_t	PUNE_COUNT;

	extern uint32_t	RAJKOT[MAX_PEERING_IP][2];
	extern uint16_t	RAJKOT_COUNT;

	extern uint32_t	SURAT[MAX_PEERING_IP][2];
	extern uint16_t	SURAT_COUNT;

	extern uint32_t	UNJHA[MAX_PEERING_IP][2];
	extern uint16_t	UNJHA_COUNT;

	extern uint32_t	VAPI[MAX_PEERING_IP][2];
	extern uint16_t	VAPI_COUNT;

	extern uint32_t	VARANASI[MAX_PEERING_IP][2];
	extern uint16_t	VARANASI_COUNT;

//	extern uint32_t	ABU[MAX_PEERING_IP][2];
//	extern uint16_t	ABU_COUNT;
//
//	extern uint32_t	ADIPUR[MAX_PEERING_IP][2];
//	extern uint16_t	ADIPUR_COUNT;
//
//	extern uint32_t	AMRELI[MAX_PEERING_IP][2];
//	extern uint16_t	AMRELI_COUNT;
//
//	extern uint32_t	ANJAR[MAX_PEERING_IP][2];
//	extern uint16_t	ANJAR_COUNT;
//
//	extern uint32_t	BHACHAU[MAX_PEERING_IP][2];
//	extern uint16_t	BHACHAU_COUNT;
//
//	extern uint32_t	BHUJ[MAX_PEERING_IP][2];
//	extern uint16_t	BHUJ_COUNT;
//
//	extern uint32_t	BODELI[MAX_PEERING_IP][2];
//	extern uint16_t	BODELI_COUNT;
//
//	extern uint32_t	CHANDRAPUR[MAX_PEERING_IP][2];
//	extern uint16_t	CHANDRAPUR_COUNT;
//
//	extern uint32_t	CHIKHALI[MAX_PEERING_IP][2];
//	extern uint16_t	CHIKHALI_COUNT;
//
//	extern uint32_t	DABHOI[MAX_PEERING_IP][2];
//	extern uint16_t	DABHOI_COUNT;
//
//	extern uint32_t	DAHOD[MAX_PEERING_IP][2];
//	extern uint16_t	DAHOD_COUNT;
//
//	extern uint32_t	DEESA[MAX_PEERING_IP][2];
//	extern uint16_t	DEESA_COUNT;
//
//	extern uint32_t	DEHGAM[MAX_PEERING_IP][2];
//	extern uint16_t	DEHGAM_COUNT;
//
//	extern uint32_t	DHANBAD[MAX_PEERING_IP][2];
//	extern uint16_t	DHANBAD_COUNT;
//
//	extern uint32_t	DWARKA[MAX_PEERING_IP][2];
//	extern uint16_t	DWARKA_COUNT;
//
//	extern uint32_t	GANDHIDHAM[MAX_PEERING_IP][2];
//	extern uint16_t	GANDHIDHAM_COUNT;
//
//	extern uint32_t	GODHARA[MAX_PEERING_IP][2];
//	extern uint16_t	GODHARA_COUNT;
//
//	extern uint32_t	GUWAHATI[MAX_PEERING_IP][2];
//	extern uint16_t	GUWAHATI_COUNT;
//
//	extern uint32_t	HIMATNAGAR[MAX_PEERING_IP][2];
//	extern uint16_t	HIMATNAGAR_COUNT;
//
//	extern uint32_t	IDAR[MAX_PEERING_IP][2];
//	extern uint16_t	IDAR_COUNT;
//
//	extern uint32_t	JAMSHEDPUR[MAX_PEERING_IP][2];
//	extern uint16_t	JAMSHEDPUR_COUNT;
//
//	extern uint32_t	JODHPUR[MAX_PEERING_IP][2];
//	extern uint16_t	JODHPUR_COUNT;
//
//	extern uint32_t	KAALOL[MAX_PEERING_IP][2];
//	extern uint16_t	KAALOL_COUNT;
//
//	extern uint32_t	KADI[MAX_PEERING_IP][2];
//	extern uint16_t	KADI_COUNT;
//
//	extern uint32_t	KALOL[MAX_PEERING_IP][2];
//	extern uint16_t	KALOL_COUNT;
//
//	extern uint32_t	KARJAN[MAX_PEERING_IP][2];
//	extern uint16_t	KARJAN_COUNT;
//
//	extern uint32_t	KESHOD[MAX_PEERING_IP][2];
//	extern uint16_t	KESHOD_COUNT;
//
//	extern uint32_t	KHAMBAT[MAX_PEERING_IP][2];
//	extern uint16_t	KHAMBAT_COUNT;
//
//	extern uint32_t	KHAMBHALIA[MAX_PEERING_IP][2];
//	extern uint16_t	KHAMBHALIA_COUNT;
//
//	extern uint32_t	KHEDA[MAX_PEERING_IP][2];
//	extern uint16_t	KHEDA_COUNT;
//
//	extern uint32_t	KHERALU[MAX_PEERING_IP][2];
//	extern uint16_t	KHERALU_COUNT;
//
//	extern uint32_t	KOLHAPUR[MAX_PEERING_IP][2];
//	extern uint16_t	KOLHAPUR_COUNT;
//
//	extern uint32_t	MANGROL_SURAT[MAX_PEERING_IP][2];
//	extern uint16_t	MANGROL_SURAT_COUNT;
//
//	extern uint32_t	MANSA[MAX_PEERING_IP][2];
//	extern uint16_t	MANSA_COUNT;
//
//	extern uint32_t	MUNDRA[MAX_PEERING_IP][2];
//	extern uint16_t	MUNDRA_COUNT;
//
//	extern uint32_t	NAGPUR[MAX_PEERING_IP][2];
//	extern uint16_t	NAGPUR_COUNT;
//
//	extern uint32_t	OLPAD[MAX_PEERING_IP][2];
//	extern uint16_t	OLPAD_COUNT;
//
//	extern uint32_t	PALANPUR[MAX_PEERING_IP][2];
//	extern uint16_t	PALANPUR_COUNT;
//
//	extern uint32_t	PATAN[MAX_PEERING_IP][2];
//	extern uint16_t	PATAN_COUNT;
//
//	extern uint32_t	PETLAD[MAX_PEERING_IP][2];
//	extern uint16_t	PETLAD_COUNT;
//
//	extern uint32_t	PONDICHERRY[MAX_PEERING_IP][2];
//	extern uint16_t	PONDICHERRY_COUNT;
//
//	extern uint32_t	PORBANDAR[MAX_PEERING_IP][2];
//	extern uint16_t	PORBANDAR_COUNT;
//
//	extern uint32_t	RAJPIPLA[MAX_PEERING_IP][2];
//	extern uint16_t	RAJPIPLA_COUNT;
//
//	extern uint32_t	SANAND[MAX_PEERING_IP][2];
//	extern uint16_t	SANAND_COUNT;
//
//	extern uint32_t	SATARA[MAX_PEERING_IP][2];
//	extern uint16_t	SATARA_COUNT;
//
//	extern uint32_t	SIDHPUR[MAX_PEERING_IP][2];
//	extern uint16_t	SIDHPUR_COUNT;
//
//	extern uint32_t	SURENDRANAGAR1[MAX_PEERING_IP][2];
//	extern uint16_t	SURENDRANAGAR1_COUNT;
//
//	extern uint32_t	SURENDRANAGAR2[MAX_PEERING_IP][2];
//	extern uint16_t	SURENDRANAGAR2_COUNT;
//
//	extern uint32_t	TALAJA[MAX_PEERING_IP][2];
//	extern uint16_t	TALAJA_COUNT;
//
//	extern uint32_t	TIRUPATI[MAX_PEERING_IP][2];
//	extern uint16_t	TIRUPATI_COUNT;
//
//	extern uint32_t	UDAIPUR[MAX_PEERING_IP][2];
//	extern uint16_t	UDAIPUR_COUNT;
//
//	extern uint32_t	UMRETH[MAX_PEERING_IP][2];
//	extern uint16_t	UMRETH_COUNT;
//
//	extern uint32_t	UNA[MAX_PEERING_IP][2];
//	extern uint16_t	UNA_COUNT;
//
//	extern uint32_t	VALSAD[MAX_PEERING_IP][2];
//	extern uint16_t	VALSAD_COUNT;
//
//	extern uint32_t	VERAVAL[MAX_PEERING_IP][2];
//	extern uint16_t	VERAVAL_COUNT;
//
//	extern uint32_t	VIJAPUR[MAX_PEERING_IP][2];
//	extern uint16_t	VIJAPUR_COUNT;
//
//	extern uint32_t	VIRAMGAM[MAX_PEERING_IP][2];
//	extern uint16_t	VIRAMGAM_COUNT;
//
//	extern uint32_t	VISNAGAR[MAX_PEERING_IP][2];
//	extern uint16_t	VISNAGAR_COUNT;

}

namespace PKTStore
{
	extern std::unordered_map<uint32_t, RawPkt*> pktRepository[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t pktRepoCnt[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool pktRepoBusy[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace cFlowSM
{
	extern std::unordered_map<uint32_t, cFlow**> cFlowSMStore[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t cFlowSMStoreCnt[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool cFlowSMBusy[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace fortiGwSM
{
	extern std::unordered_map<uint32_t, std::string> fortiGwSMStore[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern uint32_t fortiGwSMStoreCnt[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	extern bool fortiGwSMSMBusy[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace FlusherStore
{
	extern std::unordered_map<uint32_t, udpSession> udpFlStore[MAX_FLUSHER_SUPPORT][MAX_AGENT_SUPPORT][10];
	extern uint32_t udpFlCnt[MAX_FLUSHER_SUPPORT][MAX_AGENT_SUPPORT][10];
}
#endif /* INC_IPGLOBAL_H_ */
