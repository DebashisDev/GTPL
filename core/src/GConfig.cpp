/*
 * GConfig.cpp
 *
 *  Created on: 26-Jul-2016
 *      Author: Debashis
 */

#include "GConfig.h"
#include "IPGlobal.h"

GConfig::GConfig(char *fileName)
{
	initialize(fileName);
}

GConfig::~GConfig()
{ }

void GConfig::initialize(char *fileName)
{
		printf("\nLoading configurations...\n");
		openConfigFile(fileName);

		while(!fp.eof())
		{
			Key.clear();
			fp >> Key;

			get_probeId(Key);								/* PROBE_ID */
			get_logLevel(Key);								/* LOG_LEVEL */
			get_printStats(Key);							/* PRINT_STATS */
			get_printStatsFrequency(Key);					/* PRINT_STATS_FREQ_SEC */
			get_logStatsFrequency(Key);						/* LOG_STATS_FREQ_SEC */

			get_logDir(Key);								/* LOG_DIR */
			get_xdrDir(Key);								/* XDR_DIR */
			get_ipDir(Key);									/* IP-DATA_DIR */
			get_dataDir(Key);								/* DATA_DIR */

			get_processCflow(Key);							/* PROCESS_CFLOW */
			get_processForti(Key);							/* PROCESS_FORTI */
			get_processDns(Key);							/* PROCESS_DNS */

			get_adminFlag(Key);								/* ADMIN_FLAG */
			get_adminPort(Key);								/* ADMIN_PORT */

			get_ethernetInterface(Key);						/* ETHERNET_INTERFACE */
			get_solarInterface(Key);						/* SOLAR_INTERFACE */
			get_solarTimeStamp(Key);

			get_packetLen(Key);								/* MAX_PKT_LEN_PER_INTERFACE */
			get_PPSPerInterface(Key);						/* PPS_PER_INTERFACE */
			get_PPSCap(Key);								/* PPS_CAP_PERCENTAGE */
			get_routerPerInterface(Key);					/* ROUTER_PER_INTERFACE */
			get_timerCPU(Key);								/* TIMER_CPU_CORE */
			get_interfaceCPU(Key);							/* PKT_LISTENER_CPU_CORE */
			get_routerCPU(Key);								/* PKT_ROUTER_CPU_CORE */

			get_noOfcFlowSM(Key);							/* NO_OF_CFLOW_SM */
			get_cFlowSMCPU(Key);							/* CFLOW_SM_CPU_CORE */

			get_noOffortiSM(Key);							/* NO_OF_FORTI_SM */
			get_fortiSMCPU(Key);							/* FORTI_SM_CPU_CORE */

			get_sessionPktLimit(Key);						/* SESSION_PKT_LIMIT */
			get_sessionTimeLimit(Key);						/* SESSION_TIME_LIMIT */
			get_cleanUpTimeLimit(Key);						/* UDP_CLEAN_UP_TIMEOUT_SEC */

			get_noOfFlusher(Key);							/* NO_OF_FLUSHER */
			get_flusherCPU(Key);							/* FLUSHER_CPU_CORE */

			get_GANDHINAGAR(Key);							/* GANDHINAGAR */
			get_JUNAGADH(Key);								/* JUNAGADH */
			get_NADIAD(Key);								/* NADIAD */
			get_AHMEDABAD(Key);								/* AHMEDABAD */
			get_ANAND(Key);								    /* ANAND */
			get_ANKLESHWAR(Key);							/* ANKLESHWAR*/
			get_BARDOLI(Key);								/* BARDOLI */
			get_BARODA(Key);								/* BARODA */
			get_BHARUCH(Key);								/* BHARUCH */
			get_BHAVNAGAR(Key);								/* BHAVNAGAR  */
			get_BILIMORA(Key);								/* BILIMORA */
			get_HALOL(Key);									/* HALOL */
			get_JAIPUR(Key);								/* JAIPUR */
			get_JAMNAGAR(Key);								/* JAMNAGAR */
			get_KIM(Key);							     	/* KIM */
			get_MEHSANA(Key);								/* MEHSANA */
			get_MODASA(Key);								/* MODASA */
			get_MORBI(Key);								    /* MORBI */
			get_NAVSARI(Key);								/* NAVSARI*/
			get_PATNA(Key);								    /* PATNA */
			get_PUNE(Key);								    /* PUNE */
			get_RAJKOT(Key);								/* RAJKOT*/
			get_SURAT(Key);								    /* SURAT */
			get_UNJHA(Key);								    /* UNJHA */
			get_VAPI(Key);								    /* VAPI */
			get_VARANASI(Key);								/* VARANASI*/

			get_staticIp_GANDHINAGAR(Key);					/* GANDHINAGAR_STATIC */
			get_staticIp_JUNAGADH(Key);						/* GANDHINAGAR_STATIC */
			get_staticIp_NADIAD(Key);						/* NADIAD_STATIC */
			get_staticIp_AHMEDABAD(Key);					/* AHMEDABAD_STATIC */
			get_staticIp_ANAND(Key);						/* ANAND_STATIC */
			get_staticIp_ANKLESHWAR(Key);					/* ANKLESHWAR_STATIC */
			get_staticIp_BARDOLI(Key);						/* BARDOLI_STATIC */
			get_staticIp_BARODA(Key);						/* BARODA_STATIC */
			get_staticIp_BHARUCH(Key);						/* BHARUCH_STATIC */
			get_staticIp_BHAVNAGAR(Key);					/* BHAVNAGAR_STATIC */
			get_staticIp_BILIMORA(Key);						/* BILIMORA_STATIC */
			get_staticIp_HALOL(Key);						/* HALOL_STATIC */
			get_staticIp_JAIPUR(Key);						/* JAIPUR_STATIC */
			get_staticIp_JAMNAGAR(Key);						/* JAMNAGAR_STATIC */
			get_staticIp_KIM(Key);							/* KIM_STATIC */
			get_staticIp_MEHSANA(Key);						/* MEHSANA_STATIC */
			get_staticIp_MODASA(Key);						/* MODASA_STATIC */
			get_staticIp_MORBI(Key);						/* MORBI _STATIC */
			get_staticIp_NAVSARI(Key);						/* NAVSARI _STATIC */
			get_staticIp_PATNA(Key);						/* PATNA_STATIC */
			get_staticIp_PUNE(Key);						    /* PUNE_STATIC */
			get_staticIp_RAJKOT(Key);						/* RAJKOT_STATIC */
			get_staticIp_SURAT(Key);						/* SURAT_STATIC */
			get_staticIp_UNJHA(Key);						/* UNJHA _STATIC */
			get_staticIp_VAPI(Key);						    /* VAPI_STATIC */
			get_staticIp_VARANASI(Key);						/* VARANASI _STATIC */
		}
		closeConfigFile();
}

void GConfig::get_staticIp_GANDHINAGAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("GANDHINAGAR_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 100));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("GANDHINAGAR_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_JUNAGADH(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("JUNAGADH_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 101));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("JUNAGADH_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_NADIAD(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("NADIAD_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 102));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("NADIAD_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_AHMEDABAD(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("AHMEDABAD_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 103));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("AHMEDABAD_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_ANAND(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("ANAND_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 104));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("ANAND_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_ANKLESHWAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("ANKLESHWAR_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 105));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("ANKLESHWAR_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_BARDOLI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BARDOLI_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 106));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("BARDOLI_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_BARODA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BARODA_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 107));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("BARODA_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_BHARUCH(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BHARUCH_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 108));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("BHARUCH_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_BHAVNAGAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BHAVNAGAR_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 109));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("BHAVNAGAR_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_BILIMORA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BILIMORA_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 110));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("BILIMORA_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_HALOL(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("HALOL_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 111));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("HALOL_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_JAIPUR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("JAIPUR_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 112));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("JAIPUR_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_JAMNAGAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("JAMNAGAR_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 113));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("JAMNAGAR_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_KIM(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("KIM_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 114));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("KIM_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_MEHSANA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("MEHSANA_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 115));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("MEHSANA_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_MODASA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("MODASA_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 116));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("MODASA_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_MORBI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("MORBI_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 117));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("MORBI_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_NAVSARI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("NAVSARI_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 118));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("NAVSARI_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_PATNA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("PATNA_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 119));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("PATNA_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_PUNE(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("PUNE_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 120));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("PUNE_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_RAJKOT(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("RAJKOT_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 121));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("RAJKOT_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_SURAT(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("SURAT_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 122));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("SURAT_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_UNJHA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("UNJHA_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 123));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("UNJHA_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_VAPI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("VAPI_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 124));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("VAPI_STATIC = %d\n", cnt);
	}
}
void GConfig::get_staticIp_VARANASI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("VARANASI_STATIC") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			ipToLong(pch, &x);
			initSection::staticIpPoolMap.insert(std::pair<uint32_t, uint16_t>(x, 125));
			pch = strtok (NULL, ",");
			cnt++;
		}
		printf("VARANASI_STATIC = %d\n", cnt);
	}
}

void GConfig::get_GANDHINAGAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("GANDHINAGAR") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::GANDHINAGAR[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::GANDHINAGAR[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::GANDHINAGAR_COUNT = cnt;
		printf("GANDHINAGAR_COUNT = %d\n", IPGlobal::GANDHINAGAR_COUNT);
	}
}
void GConfig::get_JUNAGADH(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("JUNAGADH") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::JUNAGADH[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::JUNAGADH[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::JUNAGADH_COUNT = cnt;
		printf("JUNAGADH_COUNT = %d\n", IPGlobal::JUNAGADH_COUNT);
	}
}
void GConfig::get_NADIAD(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("NADIAD") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::NADIAD[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::NADIAD[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::NADIAD_COUNT = cnt;
		printf("NADIAD_COUNT = %d\n", IPGlobal::NADIAD_COUNT);
	}
}
void GConfig::get_AHMEDABAD(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("AHMEDABAD") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::AHMEDABAD[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::AHMEDABAD[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::AHMEDABAD_COUNT = cnt;
		printf("AHMEDABAD_COUNT = %d\n", IPGlobal::AHMEDABAD_COUNT);
	}
}
void GConfig::get_ANAND(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("ANAND") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::ANAND[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::ANAND[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::ANAND_COUNT = cnt;
		printf("ANAND_COUNT = %d\n", IPGlobal::ANAND_COUNT);
	}
}
void GConfig::get_ANKLESHWAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("ANKLESHWAR") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::ANKLESHWAR[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::ANKLESHWAR[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::ANKLESHWAR_COUNT = cnt;
		printf("ANKLESHWAR_COUNT = %d\n", IPGlobal::ANKLESHWAR_COUNT);
	}
}
void GConfig::get_BARDOLI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BARDOLI") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::BARDOLI[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::BARDOLI[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::BARDOLI_COUNT = cnt;
		printf("BARDOLI_COUNT = %d\n", IPGlobal::BARDOLI_COUNT);
	}
}
void GConfig::get_BARODA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BARODA") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::BARODA[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::BARODA[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::BARODA_COUNT = cnt;
		printf("BARODA_COUNT = %d\n", IPGlobal::BARODA_COUNT);
	}
}
void GConfig::get_BHARUCH(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BHARUCH") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::BHARUCH[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::BHARUCH[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::BHARUCH_COUNT = cnt;
		printf("BHARUCH_COUNT = %d\n", IPGlobal::BHARUCH_COUNT);
	}
}
void GConfig::get_BHAVNAGAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BHAVNAGAR") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::BHAVNAGAR[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::BHAVNAGAR[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::BHAVNAGAR_COUNT = cnt;
		printf("BHAVNAGAR_COUNT = %d\n", IPGlobal::BHAVNAGAR_COUNT);
	}
}
void GConfig::get_BILIMORA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("BILIMORA") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::BILIMORA[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::BILIMORA[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::BILIMORA_COUNT = cnt;
		printf("BILIMORA_COUNT = %d\n", IPGlobal::BILIMORA_COUNT);
	}
}
void GConfig::get_HALOL(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("HALOL") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::HALOL[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::HALOL[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::HALOL_COUNT = cnt;
		printf("HALOL_COUNT = %d\n", IPGlobal::HALOL_COUNT);
	}
}
void GConfig::get_JAIPUR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("JAIPUR") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::JAIPUR[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::JAIPUR[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::JAIPUR_COUNT = cnt;
		printf("JAIPUR_COUNT = %d\n", IPGlobal::JAIPUR_COUNT);
	}
}
void GConfig::get_JAMNAGAR(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("JAMNAGAR") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::JAMNAGAR[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::JAMNAGAR[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::JAMNAGAR_COUNT = cnt;
		printf("JAMNAGAR_COUNT = %d\n", IPGlobal::JAMNAGAR_COUNT);
	}
}
void GConfig::get_KIM(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("KIM") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::KIM[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::KIM[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::KIM_COUNT = cnt;
		printf("KIM_COUNT = %d\n", IPGlobal::KIM_COUNT);
	}
}
void GConfig::get_MEHSANA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("MEHSANA") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::MEHSANA[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::MEHSANA[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::MEHSANA_COUNT = cnt;
		printf("MEHSANA_COUNT = %d\n", IPGlobal::MEHSANA_COUNT);
	}
}
void GConfig::get_MODASA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("MODASA") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::MODASA[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::MODASA[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::MODASA_COUNT = cnt;
		printf("MODASA_COUNT = %d\n", IPGlobal::MODASA_COUNT);
	}
}
void GConfig::get_MORBI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("MORBI") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::MORBI[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::MORBI[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::MORBI_COUNT = cnt;
		printf("MORBI_COUNT = %d\n", IPGlobal::MORBI_COUNT);
	}
}
void GConfig::get_NAVSARI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("NAVSARI") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::NAVSARI[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::NAVSARI[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::NAVSARI_COUNT = cnt;
		printf("NAVSARI_COUNT = %d\n", IPGlobal::NAVSARI_COUNT);
	}
}
void GConfig::get_PATNA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("PATNA") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::PATNA[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::PATNA[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::PATNA_COUNT = cnt;
		printf("PATNA_COUNT = %d\n", IPGlobal::PATNA_COUNT);
	}
}
void GConfig::get_PUNE(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("PUNE") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::PUNE[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::PUNE[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::PUNE_COUNT = cnt;
		printf("PUNE_COUNT = %d\n", IPGlobal::PUNE_COUNT);
	}
}
void GConfig::get_RAJKOT(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("RAJKOT") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::RAJKOT[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::RAJKOT[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::RAJKOT_COUNT = cnt;
		printf("RAJKOT_COUNT = %d\n", IPGlobal::RAJKOT_COUNT);
	}
}
void GConfig::get_SURAT(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("SURAT") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::SURAT[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::SURAT[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::SURAT_COUNT = cnt;
		printf("SURAT_COUNT = %d\n", IPGlobal::SURAT_COUNT);
	}
}
void GConfig::get_UNJHA(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("UNJHA") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::UNJHA[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::UNJHA[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::UNJHA_COUNT = cnt;
		printf("UNJHA_COUNT = %d\n", IPGlobal::UNJHA_COUNT);
	}
}
void GConfig::get_VAPI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("VAPI") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::VAPI[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::VAPI[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::VAPI_COUNT = cnt;
		printf("VAPI_COUNT = %d\n", IPGlobal::VAPI_COUNT);
	}
}
void GConfig::get_VARANASI(std::string& Key)
{
	uint32_t x = 0;
	startIp[0] = endIp[0] = 0;
	Value.clear();

	if(Key.compare("VARANASI") == 0)
	{
		fp >> Value;
		int cnt = 0;

		char *pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			converSubNetToRange(pch, startIp, endIp);

			IPGlobal::VARANASI[cnt][0] = ipToLong(startIp, &x);
			IPGlobal::VARANASI[cnt][1] = ipToLong(endIp, &x);

			pch = strtok (NULL, ",");
			cnt++;
		}
		IPGlobal::VARANASI_COUNT = cnt;
		printf("VARANASI_COUNT = %d\n", IPGlobal::VARANASI_COUNT);
	}
}

void GConfig::openConfigFile(char *fileName)
{
	char probeConfigBaseDir[100];
	char *probeConfigDir;
	char *probeRootEnv;

	probeConfigDir = getenv("PROBE_CONF");

	if(probeConfigDir == NULL || probeRootEnv == NULL)
	{
		printf("\n\n\n  !!! ******* SpectaProbe Environment NOT Set ******* !!! \n\n\n");
		exit(1);
	}
	sprintf(probeConfigBaseDir, "%s/%s", probeConfigDir, fileName);
	fp.open(probeConfigBaseDir);


	if(fp.fail())
	{
		printf("  Error in Opening Configuration File : %s\n", probeConfigBaseDir);
		exit(1);
	}
}

void GConfig::closeConfigFile()
{ fp.close(); }

void GConfig::get_probeId(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROBE_ID") == 0)
	{
		fp >> Value;
		IPGlobal::PROBE_ID = atol(Value.c_str());
		printf("\tPROBE_ID               			:: %d\n", IPGlobal::PROBE_ID);
	}
}

void GConfig::get_logLevel(std::string& Key)
{
	Value.clear();

	if(Key.compare("LOG_LEVEL") == 0)
	{
		fp >> Value;
		IPGlobal::LOG_LEVEL = atoi(Value.c_str());
		printf("\tLOG_LEVEL               		:: %d\n", IPGlobal::LOG_LEVEL);

	}
}

void GConfig::get_printStats(std::string& Key)
{
	Value.clear();

	if(Key.compare("PRINT_STATS") == 0)
	{
		fp >> Value;
		IPGlobal::PRINT_STATS = Value.compare("true") == 0 ? true : false;
		printf("	PRINT_STATS				:: [%d] [%s]\n", IPGlobal::PRINT_STATS, Value.c_str());
	}
}

void GConfig::get_processCflow(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_CFLOW") == 0)
	{
		fp >> Value;
		IPGlobal::PROCESS_CFLOW = Value.compare("true") == 0 ? true : false;
		printf("	PROCESS_CFLOW				:: [%d] [%s]\n", IPGlobal::PROCESS_CFLOW, Value.c_str());
	}
}



void GConfig::get_processForti(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_FORTI") == 0)
	{
		fp >> Value;
		IPGlobal::PROCESS_FORTI = Value.compare("true") == 0 ? true : false;
		printf("	PROCESS_FORTI				:: [%d] [%s]\n", IPGlobal::PROCESS_FORTI, Value.c_str());
	}
}

void GConfig::get_processDns(std::string& Key)
{
	Value.clear();

	if(Key.compare("PROCESS_DNS") == 0)
	{
		fp >> Value;
		IPGlobal::PROCESS_DNS = Value.compare("true") == 0 ? true : false;
		printf("	PROCESS_DNS				:: [%d] [%s]\n", IPGlobal::PROCESS_DNS, Value.c_str());
	}
}

void GConfig::get_printStatsFrequency(std::string& Key)
{
	Value.clear();

	if(Key.compare("PRINT_STATS_FREQ_SEC") == 0)
	{
		fp >> Value;
		IPGlobal::PRINT_STATS_FREQ_SEC = atoi(Value.c_str());
		printf("	PRINT_STATS_FREQ_SEC			:: %d\n", IPGlobal::PRINT_STATS_FREQ_SEC);
	}
}

void GConfig::get_logStatsFrequency(std::string& Key)
{
	Value.clear();

	if(Key.compare("LOG_STATS_FREQ_SEC") == 0)
	{
		fp >> Value;
		IPGlobal::LOG_STATS_FREQ_SEC = atoi(Value.c_str());
		printf("	LOG_STATS_FREQ_SEC			:: %d\n", IPGlobal::LOG_STATS_FREQ_SEC);
	}
}

void GConfig::get_logDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("LOG_DIR") == 0)
	{
		fp >> Value;
		IPGlobal::LOG_DIR = Value;
		printf("\tLOG_DIR               			:: %s\n", IPGlobal::LOG_DIR.c_str());
	}
}

void GConfig::get_xdrDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("XDR_DIR") == 0)
	{
		fp >> Value;
		IPGlobal::XDR_DIR = Value;
		printf("\tXDR_DIR               			:: %s\n", IPGlobal::XDR_DIR.c_str());
	}
}

void GConfig::get_ipDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("IP_DIR") == 0)
	{
		fp >> Value;
		IPGlobal::IP_DIR = Value;
		printf("\tIP_DIR               			:: %s\n", IPGlobal::IP_DIR.c_str());
	}
}

void GConfig::get_dataDir(std::string& Key)
{
	Value.clear();

	if(Key.compare("DATA_DIR") == 0)
	{
		fp >> Value;
		IPGlobal::DATA_DIR = Value;
		printf("\tDATA_DIR               			:: %s\n", IPGlobal::DATA_DIR.c_str());
	}
}

void GConfig::get_adminFlag(std::string& Key)
{
	Value.clear();

	if(Key.compare("ADMIN_FLAG") == 0)
	{
		fp >> Value;
		IPGlobal::ADMIN_FLAG = Value.compare("true") == 0 ? 1 : 0;
		printf("\tADMIN_FLAG\t\t\t\t:: %s\n", Value.c_str());
	}
}

void GConfig::get_adminPort(std::string& Key)
{
	Value.clear();

	if(Key.compare("ADMIN_PORT") == 0)
	{
			fp >> Value;
			IPGlobal::ADMIN_PORT = Value;
			printf("\tADMIN_PORT\t\t\t\t:: %s\n", IPGlobal::ADMIN_PORT.c_str());
	}
}

void GConfig::get_ethernetInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("ETHERNET_INTERFACE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;

		char* pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			IPGlobal::ETHERNET_INTERFACES[cnt] = std::string(pch);
			pch = strtok (NULL, ",");
			printf("\tETHERNET_INTERFACES[%d]     		:: %s\n", cnt, IPGlobal::ETHERNET_INTERFACES[cnt].c_str());
			cnt++;
		}
		IPGlobal::NO_OF_NIC_INTERFACE = cnt;
		printf("\tETHERNET_INTERFACE          		:: %d\n", IPGlobal::NO_OF_NIC_INTERFACE);
	}
}

void GConfig::get_solarInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("SOLAR_INTERFACE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch = strtok((char *)Value.c_str(),",");

		while (pch != NULL)
		{
			IPGlobal::SOLAR_INTERFACES[cnt] = std::string(pch);
			pch = strtok (NULL, ",");
			printf("\tSOLAR_INTERFACES[%d] 			:: %s\n", cnt, IPGlobal::SOLAR_INTERFACES[cnt].c_str());
			cnt++;
		}
		IPGlobal::NO_OF_SOLAR_INTERFACE = cnt;
		printf("\tSOLAR_INTERFACES          		:: %d\n", IPGlobal::NO_OF_SOLAR_INTERFACE);
	}
}

void GConfig::get_solarTimeStamp(std::string& Key)
{
	Value.clear();

	if(Key.compare("SOLARFLARE_HW_TIMESTAMP") == 0)
	{
		fp >> Value;
		IPGlobal::SOLARFLARE_HW_TIMESTAMP = Value.compare("true") == 0 ? 1 : 0;
		printf("\tSOLARFLARE_HW_TIMESTAMP			:: %s\n", Value.c_str());
	}
}

void GConfig::get_packetLen(std::string& Key)
{
	Value.clear();

	if(Key.compare("MAX_PKT_LEN_PER_INTERFACE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::MAX_PKT_LEN_PER_INTERFACE[cnt] = atoi(pch1);
			printf("\tMAX_PKT_LEN_PER_INTERFACE[%d]     	:: %d\n", cnt, IPGlobal::MAX_PKT_LEN_PER_INTERFACE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_PPSPerInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("PPS_PER_INTERFACE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::PPS_PER_INTERFACE[cnt] = atoi(pch1);
			printf("\tPPS_PER_INTERFACE[%d]     		:: %d\n", cnt, IPGlobal::PPS_PER_INTERFACE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_PPSCap(std::string& Key)
{
	Value.clear();

	if(Key.compare("PPS_CAP_PERCENTAGE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::PPS_CAP_PERCENTAGE[cnt] = atoi(pch1);
			printf("\tPPS_CAP_PERCENTAGE[%d]     		:: %d\n", cnt, IPGlobal::PPS_CAP_PERCENTAGE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_routerPerInterface(std::string& Key)
{
	Value.clear();

	if(Key.compare("ROUTER_PER_INTERFACE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::ROUTER_PER_INTERFACE[cnt] = atoi(pch1);
			printf("\tROUTER_PER_INTERFACE[%d]			:: %d\n", cnt, IPGlobal::ROUTER_PER_INTERFACE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}


void GConfig::get_timerCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("TIMER_CPU_CORE") == 0)
	{
		fp >> Value;
		IPGlobal::TIMER_CPU_CORE = atol(Value.c_str());
		printf("	TIMER_CORE				:: %d\n", IPGlobal::TIMER_CPU_CORE);
	}
}

void GConfig::get_interfaceCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("PKT_LISTENER_CPU_CORE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::PKT_LISTENER_CPU_CORE[cnt] = atoi(pch1);
			printf("\tPKT_LISTENER_CPU_CORE[%d]		:: %d\n", cnt, IPGlobal::PKT_LISTENER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_routerCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("ROUTER_CPU_CORE") == 0)
	{
		fp >> Value;
		char *pchHash, *pchComma;
		uint16_t cnt, cnt1;

		cnt = cnt1 = 0;
		size_t pos = 0;
		std::string token;

		while ((pos = Value.find("-")) != std::string::npos)
		{
		    token = Value.substr(0, pos);
		    pchHash = strtok((char *)token.c_str(),",");

		    while (pchHash != NULL)
			{
				IPGlobal::ROUTER_CPU_CORE[cnt1][cnt] = atoi(pchHash);
				printf("\tROUTER_CPU_CORE[%d][%d]		:: %d\n", cnt1, cnt, IPGlobal::ROUTER_CPU_CORE[cnt1][cnt]);
				pchHash = strtok (NULL, ",");
				cnt++;
			}
			cnt1++;
			cnt = 0;
		    Value.erase(0, pos + 1);
		}
		cnt = 0;
		pchComma = strtok((char *)Value.c_str(),",");

		while (pchComma != NULL)
		{
			IPGlobal::ROUTER_CPU_CORE[cnt1][cnt] = atoi(pchComma);
			printf("\tROUTER_CPU_CORE[%d][%d]		:: %d\n", cnt1, cnt, IPGlobal::ROUTER_CPU_CORE[cnt1][cnt]);
			pchComma = strtok (NULL, ",");
			cnt++;
		}
	}
}

void GConfig::get_noOfcFlowSM(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_CFLOW_SM") == 0)
	{
		fp >> Value;
		IPGlobal::NO_OF_CFLOW_SM = atoi(Value.c_str());
		printf("\tNO_OF_CFLOW_SM			:: %d\n", IPGlobal::NO_OF_CFLOW_SM);
	}
}

void GConfig::get_noOffortiSM(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_FORTI_SM") == 0)
	{
		fp >> Value;
		IPGlobal::NO_OF_FORTI_SM = atoi(Value.c_str());
		printf("\tNO_OF_FORTI_SM			:: %d\n", IPGlobal::NO_OF_FORTI_SM);
	}
}

void GConfig::get_cFlowSMCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("CFLOW_SM_CPU_CORE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::CFLOW_SM_CPU_CORE[cnt] = atoi(pch1);
			printf("\tCFLOW_SM_CPU_CORE[%d]		:: %d\n", cnt, IPGlobal::CFLOW_SM_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;

			if(cnt >= IPGlobal::NO_OF_CFLOW_SM) break;
		}
	}
}

void GConfig::get_fortiSMCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("FORTI_SM_CPU_CORE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::FORTI_SM_CPU_CORE[cnt] = atoi(pch1);
			printf("\tFORTI_SM_CPU_CORE[%d]		:: %d\n", cnt, IPGlobal::FORTI_SM_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;

			if(cnt >= IPGlobal::NO_OF_FORTI_SM) break;
		}
	}
}

void GConfig::get_sessionPktLimit(std::string& Key)
{
	Value.clear();

	if(Key.compare("SESSION_PKT_LIMIT") == 0)
	{
		fp >> Value;
		IPGlobal::SESSION_PKT_LIMIT = atoi(Value.c_str());
		printf("\tSESSION_PKT_LIMIT			:: %d\n", IPGlobal::SESSION_PKT_LIMIT);
	}
}

void GConfig::get_sessionTimeLimit(std::string& Key)
{
	Value.clear();

	if(Key.compare("SESSION_TIME_LIMIT") == 0)
	{
		fp >> Value;
		IPGlobal::SESSION_TIME_LIMIT = atoi(Value.c_str());
		printf("\tSESSION_TIME_LIMIT			:: %d\n", IPGlobal::SESSION_TIME_LIMIT);
	}
}

void GConfig::get_cleanUpTimeLimit(std::string& Key)
{
	Value.clear();

	if(Key.compare("UDP_CLEAN_UP_TIMEOUT_SEC") == 0)
	{
		fp >> Value;
		IPGlobal::UDP_CLEAN_UP_TIMEOUT_SEC = atoi(Value.c_str());
		printf("\tUDP_CLEAN_UP_TIMEOUT_SEC		:: %d\n", IPGlobal::UDP_CLEAN_UP_TIMEOUT_SEC);
	}
}

void GConfig::get_noOfFlusher(std::string& Key)
{
	Value.clear();

	if(Key.compare("NO_OF_FLUSHER") == 0)
	{
			fp >> Value;
			IPGlobal::NO_OF_FLUSHER = atoi(Value.c_str());

			if(IPGlobal::NO_OF_FLUSHER > MAX_FLUSHER_SUPPORT)
			{
				printf(" No. Of flusher is Greater than Max [%02d] Flusher\n", IPGlobal::NO_OF_FLUSHER, MAX_FLUSHER_SUPPORT);
				printf(" Setting to Max [%02d] Flusher\n", MAX_FLUSHER_SUPPORT);
				IPGlobal::NO_OF_FLUSHER = MAX_FLUSHER_SUPPORT;
			}
			printf("\tNO_OF_FLUSHER      :: %d\n", IPGlobal::NO_OF_FLUSHER);
	}
}

void GConfig::get_flusherCPU(std::string& Key)
{
	Value.clear();

	if(Key.compare("FLUSHER_CPU_CORE") == 0)
	{
		fp >> Value;
		uint16_t cnt = 0;
		char* pch1 = strtok((char *)Value.c_str(),",");

		while (pch1 != NULL)
		{
			IPGlobal::FLUSHER_CPU_CORE[cnt] = atoi(pch1);
			printf("\tFLUSHER_CPU_CORE[%d]		:: %d\n", cnt, IPGlobal::FLUSHER_CPU_CORE[cnt]);
			pch1 = strtok (NULL, ",");
			cnt++;

			if(cnt >= IPGlobal::NO_OF_FLUSHER) break;
		}
	}
}

void GConfig::converSubNetToRange(char *ipr, char *Start, char *End)
{
	string str1 = "";
	string str2 = "";

	int idx = 0;
	int len = strlen(ipr) - 3;

	while(len--)
	{
		str1 += ipr[idx];
		idx++;
	}

	strcpy(Start, str1.c_str());

	idx++;
	str2 += ipr[idx];
	idx++;
	str2 += ipr[idx];

	strcpy(End, initSection::ipSubNetMap[atoi(str2.c_str())].c_str());
}

uint32_t GConfig::ipToLong(char *ip, uint32_t *plong)
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
