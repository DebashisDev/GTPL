/*
 * GConfig.h
 *
 *  Created on: 26-Jul-2016
 *      Author: Debashis
 */

#ifndef CORE_SRC_GCONFIG_H_
#define CORE_SRC_GCONFIG_H_

#include <string.h>

#include "SpectaTypedef.h"

#define NUM_OCTETTS 4

using namespace std;

class GConfig {
private:
		ifstream fp;
		string Key, Value;
		char 		startIp[16], endIp[16];

		void initialize(char *fileName);
		void openConfigFile(char *fileName);
		void closeConfigFile();

		void 	get_probeId(std::string& Key);
		void 	get_dnsId(std::string& Key);
		void	get_logLevel(std::string& Key);
		void	get_printStats(std::string& Key);
		void	get_printStatsFrequency(std::string& Key);
		void	get_logStatsFrequency(std::string& Key);
		void	get_logDir(std::string& Key);
		void	get_xdrDir(std::string& Key);
		void	get_ipDir(std::string& Key);
		void	get_dataDir(std::string& Key);
		void	get_dnsDir(std::string& Key);

		void	get_processCflow(std::string& Key);
		void	get_processForti(std::string& Key);
		void	get_processDns(std::string& Key);

		void	get_adminFlag(std::string& Key);
		void	get_adminPort(std::string& Key);
		void	get_ethernetInterface(std::string& Key);
		void	get_solarInterface(std::string& Key);
		void	get_solarTimeStamp(std::string& Key);

		void	get_packetLen(std::string& Key);
		void	get_PPSPerInterface(std::string& Key);
		void	get_PPSCap(std::string& Key);
		void	get_routerPerInterface(std::string& Key);
		void	get_timerCPU(std::string& Key);
		void	get_interfaceCPU(std::string& Key);
		void	get_routerCPU(std::string& Key);

		void	get_noOfcFlowSM(std::string& Key);
		void	get_noOffortiSM(std::string& Key);

		void	get_cFlowSMCPU(std::string& Key);
		void	get_noOfFlusher(std::string& Key);
		void	get_flusherCPU(std::string& Key);

		void	get_fortiSMCPU(std::string& Key);

		void 	get_sessionPktLimit(std::string& Key);
		void 	get_sessionTimeLimit(std::string& Key);
		void	get_cleanUpTimeLimit(std::string& Key);

		void 	converSubNetToRange(char *ipr, char *Start, char *End);
		uint32_t ipToLong(char *ip, uint32_t *plong);

		void	get_AHMDNS(std::string& Key);
		void	get_BRODNS(std::string& Key);
		void	get_RAJDNS(std::string& Key);
		void	get_SURDNS(std::string& Key);
		void	get_PATDNS(std::string& Key);
		void	get_HYDDNS(std::string& Key);

		void	get_GANDHINAGAR(std::string& Key);
		void	get_JUNAGADH(std::string& Key);
		void	get_NADIAD(std::string& Key);
		void	get_AHMEDABAD(std::string& Key);
		void	get_ANAND(std::string& Key);
		void	get_ANKLESHWAR(std::string& Key);
		void	get_BARDOLI(std::string& Key);
		void	get_BARODA(std::string& Key);
		void	get_BHARUCH(std::string& Key);
		void	get_BHAVNAGAR(std::string& Key);
		void	get_BILIMORA(std::string& Key);
		void	get_HALOL(std::string& Key);
		void	get_JAIPUR(std::string& Key);
		void	get_JAMNAGAR(std::string& Key);
		void	get_KIM(std::string& Key);
		void	get_MEHSANA(std::string& Key);
		void	get_MODASA(std::string& Key);
		void	get_MORBI(std::string& Key);
		void	get_NAVSARI(std::string& Key);
		void	get_PATNA(std::string& Key);
		void	get_PUNE(std::string& Key);
		void	get_RAJKOT(std::string& Key);
		void	get_SURAT(std::string& Key);
		void	get_UNJHA(std::string& Key);
		void	get_VAPI(std::string& Key);
		void	get_VARANASI(std::string& Key);


		void	get_staticIp_GANDHINAGAR(std::string& Key);
		void	get_staticIp_JUNAGADH(std::string& Key);
		void	get_staticIp_NADIAD(std::string& Key);
		void	get_staticIp_AHMEDABAD(std::string& Key);
		void 	get_staticIp_ANAND(std::string& Key);
		void 	get_staticIp_ANKLESHWAR(std::string& Key);
		void	get_staticIp_BARDOLI(std::string& Key);
		void 	get_staticIp_BARODA(std::string& Key);
		void 	get_staticIp_BHARUCH(std::string& Key);
		void 	get_staticIp_BHAVNAGAR(std::string& Key);
		void 	get_staticIp_BILIMORA(std::string& Key);
		void 	get_staticIp_HALOL(std::string& Key);
		void 	get_staticIp_JAIPUR(std::string& Key);
		void 	get_staticIp_JAMNAGAR(std::string& Key);
		void 	get_staticIp_KIM(std::string& Key);
		void 	get_staticIp_MEHSANA(std::string& Key);
		void 	get_staticIp_MODASA(std::string& Key);
		void 	get_staticIp_MORBI(std::string& Key);
		void 	get_staticIp_NAVSARI(std::string& Key);
		void	get_staticIp_PATNA(std::string& Key);
		void 	get_staticIp_PUNE(std::string& Key);
		void 	get_staticIp_RAJKOT(std::string& Key);
		void 	get_staticIp_SURAT(std::string& Key);
		void 	get_staticIp_UNJHA(std::string& Key);
		void 	get_staticIp_VAPI(std::string& Key);
		void 	get_staticIp_VARANASI(std::string& Key);

public:
	GConfig(char *fileName);
	~GConfig();

	int 				LOG_LEVEL;
	std::string 		XDR_DIR;
	std::string 		LOG_DIR;
	std::string 		DATA_DIR;
	std::string 		TRACE_DIR;
};

#endif /* CORE_SRC_GCONFIG_H_ */
