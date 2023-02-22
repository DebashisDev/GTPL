/*
 * SpectaProbe.h
 *
 *  Created on: 29-Jan-2016
 *      Author: Debashis
 */

#ifndef SRC_SPECTAPROBE_H_
#define SRC_SPECTAPROBE_H_

#include <signal.h>
#include <string.h>
#include <string>
#include <time.h>
#include <sys/time.h>

#include "CflowSM.h"
#include "FortiSM.h"
#include "EthernetSource.h"
#include "SpectaTypedef.h"
#include "EthernetParser.h"
#include "BaseConfig.h"
#include "ProbeStats.h"
#include "ProbeStatsLog.h"
#include "glbTimer.h"
#include "PacketRouter.h"
#include "Log.h"
#include "IPGlobal.h"
#include "UdpFlusher.h"
#include "Initialize.h"
#include "FUtility.h"


#define handle_error_en(en, msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

class SpectaProbe : public BaseConfig
{
	private:
		uint16_t 			caseNo, nicCounter, solCounter, interfaceCounter,currentMin, prevMin, currentHour, prevHour;

		GConfig				*pGConfig;

		glbTimer			*pGlbTimer;
		pthread_t			glbTimerThrId;

		PacketRouter 		*pRouter[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];
		pthread_t 			thPktRouter[MAX_INTERFACE_SUPPORT][MAX_ROUTER_PER_INTERFACE_SUPPORT];

		CflowSM		 		*pCflowSM[MAX_AGENT_SUPPORT];
		pthread_t 			cFlowSMThr[MAX_AGENT_SUPPORT];

		FortiSM		 		*pFortiSM[MAX_AGENT_SUPPORT];
		pthread_t 			fortiSMThr[MAX_AGENT_SUPPORT];

		UdpFlusher		 	*pFlusher[MAX_FLUSHER_SUPPORT];
		pthread_t 			thFlusher[MAX_FLUSHER_SUPPORT];

		EthernetSource 		*ethReader[MAX_INTERFACE_SUPPORT];
		pthread_t 			pktLisThread[MAX_INTERFACE_SUPPORT];

		ProbeStatsLog		*psLog;
		pthread_t 			psLogThread;

		ProbeStats 			*ps;
		pthread_t 			psThread;

		ofstream	 		rIpHandler;
		ofstream    		outFile;

		uint32_t 			dnsIp;

		Initialize			*pInit;

		void	openIPxdrFile();
		void	writeUniqueIP();
		void	closeIPxdrFile();
		void 	initializeLog();
		void 	initialize_pkt_repo();
		void 	spawnTimer(uint16_t no);
		void	packetProcessing(bool flag);
		void	spawnRoutersPerInterface(uint16_t no);
		void	spawncFlowSM(uint16_t no);
		void	spawnFortiSM(uint16_t no);
		void	spawnFlusher(uint16_t no);
		void	initializeNICs(uint16_t no);
		void	printStats(uint16_t no);
		void	writeStats(uint16_t no);
		void 	pinThread(pthread_t th, uint16_t i);

		void	dnsDumpIpv4Data(string dir);
		void	dnsDumpIpv6Data(string dir);

		void 		dnsSubnetDumpData(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year);

	public:
		SpectaProbe(char *fileName);
		~SpectaProbe();
		void start();
};

#endif /* SRC_SPECTAPROBE_H_ */
