/*
 * TCPGlobal.cpp
 *
 *  Created on: Nov 14, 2015
 *      Author: Debashis
 */

#include "IPGlobal.h"

using namespace std;

namespace GContainer
{ GConfig *config; }

namespace IPGlobal
{
	uint64_t	CURRENT_EPOCH_SEC 		= 0;
	uint16_t	CURRENT_SEC 			= 0;
	uint16_t	CURRENT_HOUR 			= 0;
	uint16_t	CURRENT_MIN 			= 0;
	uint16_t	CURRENT_DAY 			= 0;
	uint16_t	CURRENT_MONTH 			= 0;
	uint16_t	CURRENT_YEAR			= 0;
	uint16_t	THREAD_SLEEP_TIME		= 25000;
	uint16_t	SESSION_SCAN_FREQ_SEC 	= 15;
	uint16_t	SESSION_PKT_LIMIT		= 5000;
	uint16_t	SESSION_TIME_LIMIT		= 900;
	uint16_t	UDP_CLEAN_UP_TIMEOUT_SEC = 120;

	unordered_set<uint32_t> UniqueSourceIp;

	bool		PROBE_RUNNING_STATUS		 = true;
	bool		PROBE_LOG_RUNNING_STATUS	= false;
	bool		PROBE_STATS_RUNNING_STATUS 	= false;

	bool		PKT_LISTENER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT] = {0};
	bool		PKT_LISTENER_DAYCHANGE_INDICATION[MAX_INTERFACE_SUPPORT] = {0};
	bool		PKT_LISTENER_INTF_MON_RUNNING_STATUS[MAX_INTERFACE_SUPPORT] = {0};
	uint16_t 	PKT_LISTENER_CPU_CORE[MAX_INTERFACE_SUPPORT] = {0};
	uint16_t	TIMER_CPU_CORE = 0;

	/* ---- */
	bool		ROUTER_RUNNING_STATUS[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT] = {0};
	uint16_t 	ROUTER_PER_INTERFACE[MAX_INTERFACE_SUPPORT] 	= {0,0,0,0,0,0,0,0};
	uint16_t 	ROUTER_CPU_CORE[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT] = {0};

	/* ---- */
	bool		CFLOW_SM_RUNNING_STATUS[MAX_AGENT_SUPPORT] = {false};
	uint16_t	NO_OF_CFLOW_SM = 0;
	uint16_t	CFLOW_SM_CPU_CORE[MAX_AGENT_SUPPORT] = {0};


	bool		FORTI_SM_RUNNING_STATUS[MAX_AGENT_SUPPORT] = {false};
	uint16_t	NO_OF_FORTI_SM = 0;
	uint16_t	FORTI_SM_CPU_CORE[MAX_AGENT_SUPPORT] = {0};


	/* ---- */
	bool		FLUSHER_RUNNING_STATUS[MAX_FLUSHER_SUPPORT] = {0};
	uint16_t	NO_OF_FLUSHER = 0;
	uint16_t	FLUSHER_CPU_CORE[MAX_AGENT_SUPPORT] = {0};

	uint16_t 	PROBE_ID;
	uint16_t 	LOG_LEVEL;
	std::string LOG_DIR;
	std::string XDR_DIR;
	std::string IP_DIR;
	std::string DATA_DIR;

	bool 		PRINT_STATS 			= false;
	bool 		PROCESS_CFLOW 			= false;
	bool 		PROCESS_FORTI 			= false;
	bool 		PROCESS_DNS 			= false;

	uint16_t 	PRINT_STATS_FREQ_SEC 	= 1;
	uint16_t	LOG_STATS_FREQ_SEC 		= 1;

	uint16_t	NO_OF_NIC_INTERFACE 	= 0;
	uint16_t	NO_OF_SOLAR_INTERFACE 	= 0;
	uint16_t 	NO_OF_INTERFACES 		= 0;

	bool		TIMER_PROCESSING	= false;

	string 		ETHERNET_INTERFACES[MAX_INTERFACE_SUPPORT] 		= {"","","","","","","",""};
	string 		SOLAR_INTERFACES[MAX_INTERFACE_SUPPORT] 		= {"","","","","","","",""};
	string 		PNAME[MAX_INTERFACE_SUPPORT] = {"","","","","","","",""};

	uint16_t	TIME_INDEX = 10;
	uint32_t 	PPS_PER_INTERFACE[MAX_INTERFACE_SUPPORT] 		= {500000,500000,500000,500000,500000,500000,500000,500000};
	uint16_t	PPS_CAP_PERCENTAGE[MAX_INTERFACE_SUPPORT]		= {50,50,50,50,50,50,50,50};
	uint16_t 	MAX_BW_INTERFACE[MAX_INTERFACE_SUPPORT]			= {0,0,0,0,0,0,0,0};

	uint16_t	SOLARFLARE_HW_TIMESTAMP = 0;
	bool		PACKET_PROCESSING[MAX_INTERFACE_SUPPORT] = {false};

	uint32_t	DISCARD_PKT_CNT[MAX_INTERFACE_SUPPORT]	= {0};
	uint32_t 	PKT_RATE_INTF[MAX_INTERFACE_SUPPORT] 	= {0};
	uint64_t 	PKTS_TOTAL_INTF[MAX_INTERFACE_SUPPORT]	= {0};
	uint64_t 	BW_MBPS_INTF[MAX_INTERFACE_SUPPORT]		= {0};

    uint64_t 	discarded_packets_i_0;
    uint64_t	discarded_packets_i_1;
    uint64_t 	discarded_packets_i_2;
    uint64_t 	discarded_packets_i_3;
    uint64_t 	discarded_packets_i_4;
    uint64_t 	discarded_packets_i_5;
    uint64_t 	discarded_packets_i_6;
    uint64_t 	discarded_packets_i_7;

	string		ADMIN_PORT;
	bool		ADMIN_FLAG = false;

	uint16_t	MAX_PKT_LEN_PER_INTERFACE[MAX_INTERFACE_SUPPORT] = {0};
	uint64_t	AGENT_PACKET_RECEIVED[MAX_AGENT_SUPPORT] = {0};

	uint32_t	GANDHINAGAR[MAX_PEERING_IP][2] = {0};
	uint16_t	GANDHINAGAR_COUNT = 0;

	uint32_t	JUNAGADH[MAX_PEERING_IP][2] = {0};
	uint16_t	JUNAGADH_COUNT = 0;

	uint32_t	NADIAD[MAX_PEERING_IP][2] = {0};
	uint16_t	NADIAD_COUNT = 0;

	uint32_t	AHMEDABAD[MAX_PEERING_IP][2] = {0};
	uint16_t	AHMEDABAD_COUNT = 0;

	uint32_t	ANAND[MAX_PEERING_IP][2] = {0};
	uint16_t	ANAND_COUNT = 0;

	uint32_t	ANKLESHWAR[MAX_PEERING_IP][2] = {0};
	uint16_t	ANKLESHWAR_COUNT = 0;

	uint32_t	BARDOLI[MAX_PEERING_IP][2] = {0};
	uint16_t	BARDOLI_COUNT = 0;

	uint32_t	BARODA[MAX_PEERING_IP][2] = {0};
	uint16_t	BARODA_COUNT = 0;

	uint32_t	BHARUCH[MAX_PEERING_IP][2] = {0};
	uint16_t	BHARUCH_COUNT = 0;

	uint32_t	BHAVNAGAR[MAX_PEERING_IP][2] = {0};
	uint16_t	BHAVNAGAR_COUNT = 0;

	uint32_t	BILIMORA[MAX_PEERING_IP][2] = {0};
	uint16_t	BILIMORA_COUNT = 0;

	uint32_t	HALOL[MAX_PEERING_IP][2] = {0};
	uint16_t	HALOL_COUNT = 0;

	uint32_t	JAIPUR[MAX_PEERING_IP][2] = {0};
	uint16_t	JAIPUR_COUNT = 0;

	uint32_t	JAMNAGAR[MAX_PEERING_IP][2] = {0};
	uint16_t	JAMNAGAR_COUNT = 0;

	uint32_t	KIM[MAX_PEERING_IP][2] = {0};
	uint16_t	KIM_COUNT = 0;

	uint32_t	MEHSANA[MAX_PEERING_IP][2] = {0};
	uint16_t	MEHSANA_COUNT = 0;

	uint32_t	MODASA[MAX_PEERING_IP][2] = {0};
	uint16_t	MODASA_COUNT = 0;

	uint32_t	MORBI[MAX_PEERING_IP][2] = {0};
	uint16_t	MORBI_COUNT = 0;

	uint32_t	NAVSARI[MAX_PEERING_IP][2] = {0};
	uint16_t	NAVSARI_COUNT = 0;

	uint32_t	PATNA[MAX_PEERING_IP][2] = {0};
	uint16_t	PATNA_COUNT = 0;

	uint32_t	PUNE[MAX_PEERING_IP][2] = {0};
	uint16_t	PUNE_COUNT = 0;

	uint32_t	RAJKOT[MAX_PEERING_IP][2] = {0};
	uint16_t	RAJKOT_COUNT = 0;

	uint32_t	SURAT[MAX_PEERING_IP][2] = {0};
	uint16_t	SURAT_COUNT = 0;

	uint32_t	UNJHA[MAX_PEERING_IP][2] = {0};
	uint16_t	UNJHA_COUNT = 0;

	uint32_t	VAPI[MAX_PEERING_IP][2] = {0};
	uint16_t	VAPI_COUNT = 0;

	uint32_t	VARANASI[MAX_PEERING_IP][2] = {0};
	uint16_t	VARANASI_COUNT = 0;

//	uint32_t	ABU[MAX_PEERING_IP][2] = {0};
//	uint16_t	ABU_COUNT = 0;
//
//	uint32_t	ADIPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	ADIPUR_COUNT = 0;
//
//	uint32_t	AMRELI[MAX_PEERING_IP][2] = {0};
//	uint16_t	AMRELI_COUNT = 0;
//
//	uint32_t	ANJAR[MAX_PEERING_IP][2] = {0};
//	uint16_t	ANJAR_COUNT = 0;
//
//	uint32_t	BHACHAU[MAX_PEERING_IP][2] = {0};
//	uint16_t	BHACHAU_COUNT = 0;
//
//	uint32_t	BHUJ[MAX_PEERING_IP][2] = {0};
//	uint16_t	BHUJ_COUNT = 0;
//
//	uint32_t	BODELI[MAX_PEERING_IP][2] = {0};
//	uint16_t	BODELI_COUNT = 0;
//
//	uint32_t	CHANDRAPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	CHANDRAPUR_COUNT = 0;
//
//	uint32_t	CHIKHALI[MAX_PEERING_IP][2] = {0};
//	uint16_t	CHIKHALI_COUNT = 0;
//
//	uint32_t	DABHOI[MAX_PEERING_IP][2] = {0};
//	uint16_t	DABHOI_COUNT = 0;
//
//	uint32_t	DAHOD[MAX_PEERING_IP][2] = {0};
//	uint16_t	DAHOD_COUNT = 0;
//
//	uint32_t	DEESA[MAX_PEERING_IP][2] = {0};
//	uint16_t	DEESA_COUNT = 0;
//
//	uint32_t	DEHGAM[MAX_PEERING_IP][2] = {0};
//	uint16_t	DEHGAM_COUNT = 0;
//
//	uint32_t	DHANBAD[MAX_PEERING_IP][2] = {0};
//	uint16_t	DHANBAD_COUNT = 0;
//
//	uint32_t	DWARKA[MAX_PEERING_IP][2] = {0};
//	uint16_t	DWARKA_COUNT = 0;
//
//	uint32_t	GANDHIDHAM[MAX_PEERING_IP][2] = {0};
//	uint16_t	GANDHIDHAM_COUNT = 0;
//
//	uint32_t	GODHARA[MAX_PEERING_IP][2] = {0};
//	uint16_t	GODHARA_COUNT = 0;
//
//	uint32_t	GUWAHATI[MAX_PEERING_IP][2] = {0};
//	uint16_t	GUWAHATI_COUNT = 0;
//
//	uint32_t	HIMATNAGAR[MAX_PEERING_IP][2] = {0};
//	uint16_t	HIMATNAGAR_COUNT = 0;
//
//	uint32_t	IDAR[MAX_PEERING_IP][2] = {0};
//	uint16_t	IDAR_COUNT = 0;
//
//	uint32_t	JAMSHEDPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	JAMSHEDPUR_COUNT = 0;
//
//	uint32_t	JODHPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	JODHPUR_COUNT = 0;
//
//	uint32_t	KAALOL[MAX_PEERING_IP][2] = {0};
//	uint16_t	KAALOL_COUNT = 0;
//
//	uint32_t	KADI[MAX_PEERING_IP][2] = {0};
//	uint16_t	KADI_COUNT = 0;
//
//	uint32_t	KALOL[MAX_PEERING_IP][2] = {0};
//	uint16_t	KALOL_COUNT = 0;
//
//	uint32_t	KARJAN[MAX_PEERING_IP][2] = {0};
//	uint16_t	KARJAN_COUNT = 0;
//
//	uint32_t	KESHOD[MAX_PEERING_IP][2] = {0};
//	uint16_t	KESHOD_COUNT = 0;
//
//	uint32_t	KHAMBAT[MAX_PEERING_IP][2] = {0};
//	uint16_t	KHAMBAT_COUNT = 0;
//
//	uint32_t	KHAMBHALIA[MAX_PEERING_IP][2] = {0};
//	uint16_t	KHAMBHALIA_COUNT = 0;
//
//	uint32_t	KHEDA[MAX_PEERING_IP][2] = {0};
//	uint16_t	KHEDA_COUNT = 0;
//
//	uint32_t	KHERALU[MAX_PEERING_IP][2] = {0};
//	uint16_t	KHERALU_COUNT = 0;
//
//	uint32_t	KOLHAPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	KOLHAPUR_COUNT = 0;
//
//	uint32_t	MANGROL_SURAT[MAX_PEERING_IP][2] = {0};
//	uint16_t	MANGROL_SURAT_COUNT = 0;
//
//	uint32_t	MANSA[MAX_PEERING_IP][2] = {0};
//	uint16_t	MANSA_COUNT = 0;
//
//	uint32_t	MUNDRA[MAX_PEERING_IP][2] = {0};
//	uint16_t	MUNDRA_COUNT = 0;
//
//	uint32_t	NAGPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	NAGPUR_COUNT = 0;
//
//	uint32_t	OLPAD[MAX_PEERING_IP][2] = {0};
//	uint16_t	OLPAD_COUNT = 0;
//
//	uint32_t	PALANPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	PALANPUR_COUNT = 0;
//
//	uint32_t	PATAN[MAX_PEERING_IP][2] = {0};
//	uint16_t	PATAN_COUNT = 0;
//
//	uint32_t	PETLAD[MAX_PEERING_IP][2] = {0};
//	uint16_t	PETLAD_COUNT = 0;
//
//	uint32_t	PONDICHERRY[MAX_PEERING_IP][2] = {0};
//	uint16_t	PONDICHERRY_COUNT = 0;
//
//	uint32_t	PORBANDAR[MAX_PEERING_IP][2] = {0};
//	uint16_t	PORBANDAR_COUNT = 0;
//
//	uint32_t	RAJPIPLA[MAX_PEERING_IP][2] = {0};
//	uint16_t	RAJPIPLA_COUNT = 0;
//
//	uint32_t	SANAND[MAX_PEERING_IP][2] = {0};
//	uint16_t	SANAND_COUNT = 0;
//
//	uint32_t	SATARA[MAX_PEERING_IP][2] = {0};
//	uint16_t	SATARA_COUNT = 0;
//
//	uint32_t	SIDHPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	SIDHPUR_COUNT = 0;
//
//	uint32_t	SURENDRANAGAR1[MAX_PEERING_IP][2] = {0};
//	uint16_t	SURENDRANAGAR1_COUNT = 0;
//
//	uint32_t	SURENDRANAGAR2[MAX_PEERING_IP][2] = {0};
//	uint16_t	SURENDRANAGAR2_COUNT = 0;
//
//	uint32_t	TALAJA[MAX_PEERING_IP][2] = {0};
//	uint16_t	TALAJA_COUNT = 0;
//
//	uint32_t	TIRUPATI[MAX_PEERING_IP][2] = {0};
//	uint16_t	TIRUPATI_COUNT = 0;
//
//	uint32_t	UDAIPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	UDAIPUR_COUNT = 0;
//
//	uint32_t	UMRETH[MAX_PEERING_IP][2] = {0};
//	uint16_t	UMRETH_COUNT = 0;
//
//	uint32_t	UNA[MAX_PEERING_IP][2] = {0};
//	uint16_t	UNA_COUNT = 0;
//
//	uint32_t	VALSAD[MAX_PEERING_IP][2] = {0};
//	uint16_t	VALSAD_COUNT = 0;
//
//	uint32_t	VERAVAL[MAX_PEERING_IP][2] = {0};
//	uint16_t	VERAVAL_COUNT = 0;
//
//	uint32_t	VIJAPUR[MAX_PEERING_IP][2] = {0};
//	uint16_t	VIJAPUR_COUNT = 0;
//
//	uint32_t	VIRAMGAM[MAX_PEERING_IP][2] = {0};
//	uint16_t	VIRAMGAM_COUNT = 0;
//
//	uint32_t	VISNAGAR[MAX_PEERING_IP][2] = {0};
//	uint16_t	VISNAGAR_COUNT = 0;
}

namespace PKTStore
{
	std::unordered_map<uint32_t, RawPkt*> pktRepository[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t pktRepoCnt[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	bool pktRepoBusy[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace cFlowSM
{
	std::unordered_map<uint32_t, cFlow**> cFlowSMStore[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t cFlowSMStoreCnt[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10] = {0};
	bool cFlowSMBusy[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace fortiGwSM
{
	std::unordered_map<uint32_t, std::string> fortiGwSMStore[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
	uint32_t fortiGwSMStoreCnt[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10] = {0};
	bool fortiGwSMSMBusy[MAX_AGENT_SUPPORT][MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT][10];
}

namespace FlusherStore
{
	std::unordered_map<uint32_t, udpSession> udpFlStore[MAX_FLUSHER_SUPPORT][MAX_AGENT_SUPPORT][10];
	uint32_t udpFlCnt[MAX_FLUSHER_SUPPORT][MAX_AGENT_SUPPORT][10] = {0};
}
