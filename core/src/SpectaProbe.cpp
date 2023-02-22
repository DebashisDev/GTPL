/*
 * SpectaProbe.cpp
 *
 *  Created on: 03-Mar-2022
 *      Author: Debashis
 */

#include <signal.h>
#include <unistd.h>
#include <locale.h>


#include "SpectaProbe.h"

void *startTimerThread(void *arg)
{
	glbTimer *ft = (glbTimer *)arg;
	ft->run();
	return NULL;
}

void* startPktRouterThread(void* arg)
{
	int s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	PacketRouter *ft = (PacketRouter*)arg;
	ft->run();
	return NULL;
}

void* startCflowSMThread(void* arg)
{
	int s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	CflowSM *ft = (CflowSM*)arg;
	ft->run();
	return NULL;
}

void* startFortiSMThread(void* arg)
{
	int s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	FortiSM *ft = (FortiSM*)arg;
	ft->run();
	return NULL;
}


void* startFlusherThread(void* arg)
{
	int s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	UdpFlusher *ft = (UdpFlusher*)arg;
	ft->run();
	return NULL;
}

void* ethListenerThread(void* arg)
{
	EthernetSource *ft = (EthernetSource*)arg;
	ft->start();
	return NULL;
}

void* probeStatsLogThread(void* arg)
{
	ProbeStatsLog *ft = (ProbeStatsLog*)arg;
	ft->run();
	return NULL;
}

void* probeStatsThread(void* arg)
{
	ProbeStats *ft = (ProbeStats*)arg;
	ft->run();
	return NULL;
}

SpectaProbe::SpectaProbe(char *fileName)
{
	this->_name = "SpectaProbe";
	this->caseNo = 0;
	this->nicCounter = 0;
	this->solCounter = 0;
	this->interfaceCounter = 0;
	this->currentHour = 0;
	this->prevHour = 0;
	this->currentMin = 0;
	this->prevMin = 0;

	pInit = new Initialize();
	pGConfig = new GConfig(fileName);
	this->setLogLevel(Log::theLog().level());

}

SpectaProbe::~SpectaProbe()
{
	delete(pInit);
	delete(GContainer::config);
}

void SpectaProbe::initializeLog()
{
	char logFile[200];
	logFile[0] = 0;

	mapAAALock::count		= 1;
	mapDnsLock::count		= 1;

	sprintf(logFile, "%s%s_%d.log", IPGlobal::LOG_DIR.c_str(), "cFlow", IPGlobal::PROBE_ID, IPGlobal::CURRENT_DAY, IPGlobal::CURRENT_MONTH, IPGlobal::CURRENT_YEAR);

	Log::theLog().open(logFile);
	Log::theLog().level(IPGlobal::LOG_LEVEL);

	char *probeVer = getenv("PROBE_VER");

	/*
	 *	1.0.0		11-03-2022		First Release
	 */

	printf(" ############################################################\n");
	printf("                                                             \n");
	printf("              Starting SPECTA [%s] Probe Ver : %s            \n", "cFlow", probeVer);
	printf("                                                             \n");
	printf(" ############################################################\n");


	TheLog_nc_v1(Log::Info, name(),"  ############################################################%s","");
	TheLog_nc_v1(Log::Info, name(),"                                                              %s","");
	TheLog_nc_v2(Log::Info, name(),"                     Starting SPECTA [%s] Probe Ver : %s        ", "cFlow", probeVer);
	TheLog_nc_v1(Log::Info, name(),"                                                              %s","");
	TheLog_nc_v1(Log::Info, name(),"  ############################################################%s","");
	TheLog_nc_v1(Log::Info, name(),"  Log file initialized Level - %d", IPGlobal::LOG_LEVEL);
}

void SpectaProbe::start()
{
	IPGlobal::NO_OF_INTERFACES = IPGlobal::NO_OF_SOLAR_INTERFACE + IPGlobal::NO_OF_NIC_INTERFACE;

	initialize_pkt_repo();

	spawnTimer(1); 					/* ---- Start Timer Thread ---- */
	sleep(2);

	initializeLog();                    /* ---- Initialize Log File ---- */

	printf("  *** [%02d] Packet Processing Paused. \n", 2);
	TheLog_nc_v1(Log::Info, name(),"  *** [%02d] Packet Processing Paused. ", 2);
	packetProcessing(false);				/* ---- Pause the incoming Traffic ---- */

	spawnRoutersPerInterface(3);			/* ---- Start Router / Interface Threads ---- */

	if(IPGlobal::PROCESS_CFLOW)
		spawncFlowSM(4);					/* ---- Start cFlow SM Threads ---- */

	if(IPGlobal::PROCESS_FORTI)
		spawnFortiSM(5);					/* ---- Start Forti SM Threads ---- */

	if(IPGlobal::PROCESS_CFLOW)
		spawnFlusher(6);					/* ---- Start Flusher Threads ---- */

	initializeNICs(7);						/* ---- Start NIC Listener Threads ---- */

	printStats(8);							/* ---- Start Probe Log Threads ---- */

	writeStats(9);							/* ---- Start Probe Statistic Threads ---- */

	switch(IPGlobal::DNS_ID)
	 {
	 	case 111:	IPGlobal::DNS_IP = IPGlobal::AHM_DNS;
	 				break;
	 	case 112:	IPGlobal::DNS_IP = IPGlobal::BRO_DNS;
	 				break;
	 	case 113:	IPGlobal::DNS_IP = IPGlobal::RAJ_DNS;
	 				break;
	 	case 114:	IPGlobal::DNS_IP = IPGlobal::SUR_DNS;
	 				break;
	 	case 115:	IPGlobal::DNS_IP = IPGlobal::PAT_DNS;
	 				break;
	 	case 116:	IPGlobal::DNS_IP = IPGlobal::HYD_DNS;
	 				break;
	 	default:
	 		break;
	 }

	sleep(4);							/* ---- Start Processing the data after 10 seconds ---- */

	printf("SpectaProbe Started Successfully.\n");
	TheLog_nc_v1(Log::Info, name(),"  SpectaProbe Started Successfully. %s","");

	packetProcessing(true);				/* ---- Resume the incoming Traffic ---- */

	printf("  *** [%02d] Packet Processing Resumed. \n", 9);
	TheLog_nc_v1(Log::Info, name(),"  *** [%02d] Packet Processing Resumed. ", 9);


	uint16_t today = 0, lastday = 0;

	lastday = today =  IPGlobal::CURRENT_DAY;

	currentHour = prevHour = IPGlobal::CURRENT_HOUR;
	
	currentMin = prevMin = IPGlobal::CURRENT_MIN;

	while(IPGlobal::PROBE_RUNNING_STATUS)
	{
		sleep(1);
		currentHour = IPGlobal::CURRENT_HOUR;
		currentMin = IPGlobal::CURRENT_MIN;

		if(currentMin != prevMin)
		{
			if(IPGlobal::PROCESS_DNS) 
			{ 
				dnsDumpIpv4Data(IPGlobal::XDR_DIR);
				dnsSubnetDumpData(IPGlobal::CURRENT_MIN, IPGlobal::CURRENT_HOUR, IPGlobal::CURRENT_DAY, IPGlobal::CURRENT_MONTH, IPGlobal::CURRENT_YEAR);
			}

			prevMin = currentMin;
		}

//		if(currentHour != prevHour)
//		{
//			/* Do any Hour wise work */
//			writeUniqueIP();
//
//			prevHour = currentHour;
//		}

		today = IPGlobal::CURRENT_DAY;
		if(lastday != today)
		{
			lastday = today;
			TheLog_nc_v1(Log::Info, name(),"  Day Changed .... !!! Initializing Counters....%s", "");
			IPGlobal::discarded_packets_i_0 = 0;
			IPGlobal::discarded_packets_i_1 = 0;
			IPGlobal::discarded_packets_i_2 = 0;
			IPGlobal::discarded_packets_i_3 = 0;
			IPGlobal::discarded_packets_i_4 = 0;
			IPGlobal::discarded_packets_i_5 = 0;
			IPGlobal::discarded_packets_i_6 = 0;
			IPGlobal::discarded_packets_i_7 = 0;
		}
	}
	printf("\n  SpectaProbe Shutdown Complete...\n");
	exit(0);
}

void SpectaProbe::writeUniqueIP()
{
	/* opening XDR FILE */

	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s_%d-%02d-%02d-%02d.csv",
					IPGlobal::IP_DIR.c_str(),
					"ip",
					IPGlobal::CURRENT_YEAR,
					IPGlobal::CURRENT_MONTH,
					IPGlobal::CURRENT_DAY,
					IPGlobal::CURRENT_HOUR);

	rIpHandler.open((char *)filePath);

	filePath[0] = 0;

	/* writing into file */
	char sourceIpv4[16];

	for (auto it = IPGlobal::UniqueSourceIp.cbegin(), next_it = it; it != IPGlobal::UniqueSourceIp.cend(); it = next_it)
	{
		sourceIpv4[0] = 0;
		long2Ip((uint32_t)*it, sourceIpv4);
		rIpHandler << string(sourceIpv4) << endl;

		++next_it;
		IPGlobal::UniqueSourceIp.erase(it);
	}

	/* closing file */
	rIpHandler.close();
}

void SpectaProbe::spawnTimer(uint16_t no)
{
	pGlbTimer = new glbTimer;

	IPGlobal::TIMER_PROCESSING = true;

	pthread_create(&glbTimerThrId, NULL, startTimerThread, pGlbTimer);
	pinThread(glbTimerThrId, IPGlobal::TIMER_CPU_CORE);

	while(!pGlbTimer->isGlbTimerInitialized())
		sleep(1);

	printf("  *** [%02d] Timer Thread Started Successfully. Pinned to CPU Core [%02d]\n", no, IPGlobal::TIMER_CPU_CORE);
	TheLog_nc_v2(Log::Info, name(),"  *** [%02d] Timer Thread Started Successfully. Pinned to CPU Core [%02d]", no, IPGlobal::TIMER_CPU_CORE);
}

void SpectaProbe::packetProcessing(bool flag)
{
	switch(flag)
	{
		case true:
			for(uint16_t infCounter = 0; infCounter < IPGlobal::NO_OF_INTERFACES; infCounter++)
			{
				IPGlobal::PACKET_PROCESSING[infCounter] = true;
				sleep(30);
			}
			break;

		case false:
			for(uint16_t infCounter = 0; infCounter < IPGlobal::NO_OF_INTERFACES; infCounter++)
				IPGlobal::PACKET_PROCESSING[infCounter] = false;

			break;
	}
}

void SpectaProbe::spawnRoutersPerInterface(uint16_t no)
{
	for(int infCounter = 0; infCounter < IPGlobal::NO_OF_INTERFACES; infCounter++)
	{
		for(int routeCounter = 0; routeCounter < IPGlobal::ROUTER_PER_INTERFACE[infCounter]; routeCounter++)
		{
			IPGlobal::ROUTER_RUNNING_STATUS[infCounter][routeCounter] = true;

			pRouter[infCounter][routeCounter] = new PacketRouter(infCounter, routeCounter, IPGlobal::ROUTER_CPU_CORE[infCounter][routeCounter]);
			pthread_create(&thPktRouter[infCounter][routeCounter], NULL, startPktRouterThread, pRouter[infCounter][routeCounter]);

			pinThread(thPktRouter[infCounter][routeCounter], IPGlobal::ROUTER_CPU_CORE[infCounter][routeCounter]);
			printf(" [%02d] PacketRouter [%02d]::[%02d] Pinned to CPU Core [%02d]\n", no, infCounter, routeCounter, IPGlobal::ROUTER_CPU_CORE[infCounter][routeCounter]);

			TheLog_nc_v4(Log::Info, name(),"  [%02d] PacketRouter [%02d][%02d] pinned to CPU Core [%02d]", no, infCounter, routeCounter, IPGlobal::ROUTER_CPU_CORE[infCounter][routeCounter]);
			while(!pRouter[infCounter][routeCounter]->isRepositoryInitialized())
				sleep(1);
		}
	}
}

void SpectaProbe::spawncFlowSM(uint16_t no)
{
	for(uint16_t smCnt = 0; smCnt < IPGlobal::NO_OF_CFLOW_SM; smCnt++)
	{
		IPGlobal::CFLOW_SM_RUNNING_STATUS[smCnt] = true;
		pCflowSM[smCnt] = new CflowSM(smCnt);
		pthread_create(&cFlowSMThr[smCnt], NULL, startCflowSMThread, pCflowSM[smCnt]);
		pinThread(cFlowSMThr[smCnt], IPGlobal::CFLOW_SM_CPU_CORE[smCnt]);

		printf("  *** [%02d] cFlow SM Instance: %02d| Core: %2d\n", no, smCnt, IPGlobal::CFLOW_SM_CPU_CORE[smCnt]);

		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] cFlow SM Instance: %02d| Core: %2d", no, smCnt, IPGlobal::CFLOW_SM_CPU_CORE[smCnt]);

		while(!pCflowSM[smCnt]->isRepositoryInitialized())
			sleep(1);
	}
}

void SpectaProbe::spawnFortiSM(uint16_t no)
{
	for(uint16_t smCnt = 0; smCnt < IPGlobal::NO_OF_FORTI_SM; smCnt++)
	{
		IPGlobal::FORTI_SM_RUNNING_STATUS[smCnt] = true;
		pFortiSM[smCnt] = new FortiSM(smCnt);
		pthread_create(&fortiSMThr[smCnt], NULL, startFortiSMThread, pFortiSM[smCnt]);
		pinThread(fortiSMThr[smCnt], IPGlobal::FORTI_SM_CPU_CORE[smCnt]);

		printf("  *** [%02d] Forti SM Instance: %02d| Core: %2d\n", no, smCnt, IPGlobal::FORTI_SM_CPU_CORE[smCnt]);

		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] Forti SM Instance: %02d| Core: %2d", no, smCnt, IPGlobal::FORTI_SM_CPU_CORE[smCnt]);

		while(!pFortiSM[smCnt]->isRepositoryInitialized())
			sleep(1);
	}
}


void SpectaProbe::spawnFlusher(uint16_t no)
{
	for(uint16_t fCnt = 0; fCnt < IPGlobal::NO_OF_FLUSHER; fCnt++)
	{
		IPGlobal::FLUSHER_RUNNING_STATUS[fCnt] = true;
		pFlusher[fCnt] = new UdpFlusher(fCnt);
		pthread_create(&thFlusher[fCnt], NULL, startFlusherThread, pFlusher[fCnt]);
		pinThread(thFlusher[fCnt], IPGlobal::FLUSHER_CPU_CORE[fCnt]);

		printf("  *** [%02d] Flusher Instance: %02d| Core: %2d\n", no, fCnt, IPGlobal::FLUSHER_CPU_CORE[fCnt]);
		TheLog_nc_v3(Log::Info, name(),"  *** [%02d] Flusher Instance: %02d| Core: %2d", no, fCnt, IPGlobal::FLUSHER_CPU_CORE[fCnt]);

		while(!pFlusher[fCnt]->isUdpFlusherReady())
			sleep(1);
	}
	printf("\n");
}

void SpectaProbe::initializeNICs(uint16_t no)
{
	nicCounter = solCounter = interfaceCounter = 0;
	caseNo = -1;

	if(IPGlobal::NO_OF_NIC_INTERFACE > 0 && IPGlobal::NO_OF_SOLAR_INTERFACE > 0)
		caseNo = 0; /* Both NIC and Solarflare */
	else if(IPGlobal::NO_OF_NIC_INTERFACE > 0 && IPGlobal::NO_OF_SOLAR_INTERFACE == 0)
		caseNo = 1; /* Only NIC */
	else if(IPGlobal::NO_OF_NIC_INTERFACE == 0 && IPGlobal::NO_OF_SOLAR_INTERFACE > 0)
		caseNo = 2; /* Only Solarflare */

	switch(caseNo)
	{
		case 0:		/* Both NIC and Solarflare */
		{
			for(nicCounter = 0; nicCounter < IPGlobal::NO_OF_NIC_INTERFACE; nicCounter++)
			{
				printf("  *** [%02d] Ethernet Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d] \n",
						no, nicCounter, IPGlobal::ETHERNET_INTERFACES[nicCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

			IPGlobal::PNAME[nicCounter] = IPGlobal::ETHERNET_INTERFACES[nicCounter];

			IPGlobal::PKT_LISTENER_RUNNING_STATUS[nicCounter] = true;
			IPGlobal::PKT_LISTENER_DAYCHANGE_INDICATION[nicCounter] = false;

			ethReader[nicCounter] = new EthernetSource(IPGlobal::ROUTER_PER_INTERFACE[nicCounter], nicCounter);
			pthread_create(&pktLisThread[nicCounter], NULL, ethListenerThread, ethReader[nicCounter]);
			pinThread(pktLisThread[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

			TheLog_nc_v5(Log::Info, name(),"  *** [%02d] Ethernet Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d]",
							no, nicCounter, IPGlobal::ETHERNET_INTERFACES[nicCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

			while(!ethReader[nicCounter]->isRepositoryInitialized())
				sleep(1);
			}
#ifdef _SF
			interfaceCounter = nicCounter;
			for(uint16_t solCounter = 0; solCounter < IPGlobal::NO_OF_SOLAR_INTERFACE; solCounter++, interfaceCounter++)
			{
				printf("  *** [%02d] Solarflare Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d] \n",
						no, interfaceCounter, IPGlobal::SOLAR_INTERFACES[solCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[interfaceCounter], IPGlobal::PKT_LISTENER_CPU_CORE[interfaceCounter]);

				IPGlobal::PNAME[interfaceCounter] = IPGlobal::SOLAR_INTERFACES[solCounter];

				IPGlobal::PKT_LISTENER_RUNNING_STATUS[interfaceCounter] = true;
				IPGlobal::PKT_LISTENER_DAYCHANGE_INDICATION[interfaceCounter] = false;

				sfReader[interfaceCounter] = new PacketListener(IPGlobal::ROUTER_PER_INTERFACE[interfaceCounter], solCounter, interfaceCounter);
				pthread_create(&pktLisThread[interfaceCounter], NULL, packetListenerThread, sfReader[interfaceCounter]);
				pinThread(pktLisThread[interfaceCounter], IPGlobal::PKT_LISTENER_CPU_CORE[interfaceCounter]);

				TheLog_nc_v5(Log::Info, name(),"  *** [%02d] Solarflare Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d]",
						no, interfaceCounter, IPGlobal::SOLAR_INTERFACES[solCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[interfaceCounter], IPGlobal::PKT_LISTENER_CPU_CORE[interfaceCounter]);

				while(!sfReader[interfaceCounter]->isRepositoryInitialized())
					sleep(1);
			}
#endif
		}
		break;

		case 1:		/* Only NIC */
		{
			for(nicCounter = 0; nicCounter < IPGlobal::NO_OF_INTERFACES; nicCounter++)
			{
				printf("  *** [%02d] Ethernet Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d] \n",
						no, nicCounter, IPGlobal::ETHERNET_INTERFACES[nicCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

				IPGlobal::PNAME[nicCounter] = IPGlobal::ETHERNET_INTERFACES[nicCounter];

				IPGlobal::PKT_LISTENER_RUNNING_STATUS[nicCounter] = true;
				IPGlobal::PKT_LISTENER_DAYCHANGE_INDICATION[nicCounter] = false;
				ethReader[nicCounter] = new EthernetSource(IPGlobal::ROUTER_PER_INTERFACE[nicCounter], nicCounter);
				pthread_create(&pktLisThread[nicCounter], NULL, ethListenerThread, ethReader[nicCounter]);
				pinThread(pktLisThread[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

				TheLog_nc_v5(Log::Info, name(),"  *** [%02d] Ethernet Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d]",
								no, nicCounter, IPGlobal::ETHERNET_INTERFACES[nicCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

				while(!ethReader[nicCounter]->isRepositoryInitialized())
					sleep(1);
			}
		}
		break;

#ifdef _SF
		case 2:		/* Only Solarflare */
		{
			for(nicCounter = 0; nicCounter < IPGlobal::NO_OF_INTERFACES; nicCounter++)
			{
				printf("  *** [%02d] Solarflare Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d] \n",
						no, nicCounter, IPGlobal::SOLAR_INTERFACES[nicCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

				IPGlobal::PNAME[nicCounter] = IPGlobal::SOLAR_INTERFACES[nicCounter];

				IPGlobal::PKT_LISTENER_RUNNING_STATUS[nicCounter] = true;
				IPGlobal::PKT_LISTENER_DAYCHANGE_INDICATION[nicCounter] = false;
				sfReader[nicCounter] = new PacketListener(IPGlobal::ROUTER_PER_INTERFACE[nicCounter], nicCounter, nicCounter);
				pthread_create(&pktLisThread[nicCounter], NULL, packetListenerThread, sfReader[nicCounter]);
				pinThread(pktLisThread[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

				TheLog_nc_v5(Log::Info, name(),"  *** [%02d] Solarflare Interface [%02d]->[%s] with No of Routers [%02d] Allocated Core [%02d]",
								no, nicCounter, IPGlobal::SOLAR_INTERFACES[nicCounter].c_str(), IPGlobal::ROUTER_PER_INTERFACE[nicCounter], IPGlobal::PKT_LISTENER_CPU_CORE[nicCounter]);

				while(!sfReader[nicCounter]->isRepositoryInitialized())
					sleep(1);
			}
		}
		break;
#endif

	}
}

void SpectaProbe::printStats(uint16_t no)
{
	psLog = new ProbeStatsLog();

	IPGlobal::PROBE_LOG_RUNNING_STATUS = true;
	pthread_create(&psLogThread, NULL, probeStatsLogThread, psLog);

	printf("  *** [%02d] Statistic Thread Started Successfully. \n", no);
	TheLog_nc_v1(Log::Info, name(),"  *** [%02d] Statistic Thread Started Successfully. ", no);
}

void SpectaProbe::writeStats(uint16_t no)
{
	if(IPGlobal::PRINT_STATS)
	{
		ps = new ProbeStats();
		IPGlobal::PROBE_STATS_RUNNING_STATUS = true;

		pthread_create(&psThread, NULL, probeStatsThread, ps);
	}
	printf("  *** [%02d] Log Write Thread Started Successfully. \n", no);
	TheLog_nc_v1(Log::Info, name(),"  *** [%02d] Log Write Thread Started Successfully. ", no);
}



void SpectaProbe::pinThread(pthread_t th, uint16_t i)
{
   /* Set affinity mask to include CPUs 0 to 7 */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(i,&cpuset);

	int s = pthread_setaffinity_np(th, sizeof(cpu_set_t), &cpuset);
	if (s != 0)
		handle_error_en(s, "ERROR!!! pthread_setaffinity_np");

	/* Check the actual affinity mask assigned to the thread */
	s = pthread_getaffinity_np(th, sizeof(cpu_set_t), &cpuset);
	if (s != 0)
		handle_error_en(s, "ERROR!!! pthread_getaffinity_np");

	if (!CPU_ISSET(i, &cpuset)){
		printf("CPU pinning failed at core :: %d\n", i);
		TheLog_nc_v1(Log::Info, name(),"  CPU pinning failed at core :: %d",i);
	}
}

void SpectaProbe::initialize_pkt_repo()
{
	uint32_t maxLen = 0;

	for(uint16_t intf = 0; intf < IPGlobal::NO_OF_INTERFACES; intf++)
	{
		maxLen = IPGlobal::PPS_PER_INTERFACE[intf] / IPGlobal::ROUTER_PER_INTERFACE[intf];

		printf("PKTStore Repository for Interface [%d] Initializing [%'d] per Router x 10 x %d Router RawPkt... ", intf, maxLen, IPGlobal::ROUTER_PER_INTERFACE[intf]);
		TheLog_nc_v3(Log::Info, name(),"  PKTStore Repository for Interface [%d] Initializing [%'d] per Router x 10 x %d Router RawPkt...", intf, maxLen, IPGlobal::ROUTER_PER_INTERFACE[intf]);

		for(uint16_t router = 0; router < IPGlobal::ROUTER_PER_INTERFACE[intf]; router++)
			for(uint16_t ti = 0; ti < 10; ti++)
			{
				PKTStore::pktRepoCnt[intf][router][ti] = 0;
				PKTStore::pktRepoBusy[intf][router][ti] = false;

				for(uint32_t ml = 0; ml < maxLen; ml++)
					PKTStore::pktRepository[intf][router][ti][ml] = new RawPkt(IPGlobal::MAX_PKT_LEN_PER_INTERFACE[intf]);
			}
			printf("Completed for Interface [%d] Initializing [%'d] per Router x 10 x %d Router\n", intf, maxLen, IPGlobal::ROUTER_PER_INTERFACE[intf]);
			TheLog_nc_v3(Log::Info, name(),"  Completed for Interface [%d] Initializing [%'d] per Router x 10 x %d Router RawPkt...Completed", intf, maxLen, IPGlobal::ROUTER_PER_INTERFACE[intf]);
	}
}

void SpectaProbe::dnsDumpIpv4Data(string dir)
{
	char fileName[50], finalFileName[50];
	fileName[0] = 0;
	finalFileName[0] = 0;
	uint32_t recordCount = 0;
	char ipv4[16];

	/* Dumping File Hourly */
	sprintf(fileName, "%s.csv.in", "dnsIpv4data");
	string filePath = dir + string(fileName);

	ofstream fileHandler;

	fileHandler.open(filePath.c_str(), ios :: out);

	if(fileHandler.fail())
	{
		printf(" Error in Dumping Daily IPv4 DNS Lookup Store File : %s\n", filePath.c_str());
		TheLog_nc_v1(Log::Info, name()," Error in dumping Ipv4 DNS data to file [%s]", filePath.c_str());
	}
	else
	{
		for(uint16_t i = 0; i < 10; i ++)
		{
			for(auto elem : DNSGlobal::dnsLookUpMap[i])
			{
				recordCount++;
				ipv4[0] = 0;
				long2Ip(elem.first, ipv4);
				fileHandler << ipv4 << "," << elem.second << endl;
			}
		}

//		for(uint16_t r = 0; r < 8; r++)
//		{
//			for(uint16_t i = 0; i < 26; i ++)
//			{
//				for(auto elem : aaaGlbMap::publicPrivateMap[r][i])
//					fileHandler << i << "," << r << "," << elem.first << "," << elem.second << endl;
//			}
//		}

		fileHandler.close();
		printf(" Dumping [%06u] Records of IPv4 DNS Data to file [%s] Completed.\n", recordCount, filePath.c_str());
		TheLog_nc_v2(Log::Info, name()," Dumping [%06u] Records of IPv4 DNS Data to file [%s] Completed.", recordCount, filePath.c_str());

		sprintf(finalFileName, "%s.csv", "dnsIpv4data");
		string filePath1 = dir + string(finalFileName);

		rename(filePath.c_str(), filePath1.c_str());

		recordCount = 0;
		filePath.clear();
		filePath1.clear();
	}
}

void SpectaProbe::dnsDumpIpv6Data(string dir)
{
	char fileName[50];
	fileName[0] = 0;

	/* Dumping File minute */
	sprintf(fileName, "%s.csv", "dnsIpv6data");
	string filePath = dir + string(fileName);

	printf("SpectaProbe Dumping IPv6 DNS Lookup Store to file [%s]...\n",  filePath.c_str());
	TheLog_nc_v1(Log::Info, name()," Dumping IPv6 DNS Lookup Store to file [%s]...", filePath.c_str());

	ofstream fileHandler;

	fileHandler.open(filePath.c_str(), ios :: out);

	if(fileHandler.fail())
	{
		printf("SpectaProbe Error in Dumping Daily IPv6 DNS Lookup Store File : %s\n", filePath.c_str());
		TheLog_nc_v1(Log::Warn, name(),"  Error in Dumping Daily IPv6 DNS Lookup Store to file [%s]...", filePath.c_str());
	}
	else
	{
		for(auto elem : DNSGlobal::dnsV6LookUpMap)
			fileHandler << elem.first << "," << elem.second << endl;

		fileHandler.close();
		printf("SpectaProbe Dumping Daily IPv6 DNS Lookup Store to file [%s]...Completed\n", filePath.c_str());
		TheLog_nc_v1(Log::Info, name()," SpectaProbe Daily IPv6 DNS Lookup Store to file [%s]...Completed", filePath.c_str());
		filePath.clear();
	}
}

void SpectaProbe::dnsSubnetDumpData(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char dnsFileName[50], dnsFinalFileName[50];
	dnsFileName[0] = 0;
	dnsFinalFileName[0] = 0;

	uint32_t dnsRecordCount = 0;
	char userIp[20], dnsIp[20], uIp[20];

	sprintf(dnsFileName, "%s/%s_%d-%02d-%02d-%02d-%02d.csv.in",
							IPGlobal::DNS_DIR.c_str(),
							"dnsSubnetData",
							year,
							month,
							day,
							hour,
							min);

	string dnsFilePath = string(dnsFileName);

	outFile.open(dnsFileName, ios :: out | ios :: app);

	if(outFile.fail())
	{
		printf(" Error in Dumping Daily IPv4 DNS Lookup Store File : %s\n", dnsFileName);
		TheLog_nc_v1(Log::Info, name()," Error in dumping Ipv4 DNS data to file [%s]", dnsFileName);
	}

	else
	{
		for(auto elem : DNSGlobal::dnsSubnetMap)
		{
			dnsRecordCount++;
			long2Ip(elem.first, userIp);
			long2Ip(elem.second, dnsIp);
			outFile << dnsIp << "," << userIp << "/24" << endl;
		}

		outFile.close();
		printf(" Dumping [%06u] Records of IPv4 DNS Data to file [%s] Completed.\n", dnsRecordCount, dnsFileName);
		TheLog_nc_v2(Log::Info, name()," Dumping [%06u] Records of IPv4 DNS Data to file [%s] Completed.", dnsRecordCount, dnsFileName);

		sprintf(dnsFinalFileName, "%s/%s_%d-%02d-%02d-%02d-%02d.csv",
								IPGlobal::DNS_DIR.c_str(),
								"dnsSubnetData",
								year,
								month,
								day,
								hour,
								min);
		string dsnFileFinalPath = string(dnsFinalFileName);

		rename(dnsFilePath.c_str(), dsnFileFinalPath.c_str());

		dnsRecordCount = 0;
		string(dnsFileName).clear();
		string(dnsFinalFileName).clear();
	}
}
