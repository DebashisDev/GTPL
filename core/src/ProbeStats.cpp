/*
 * ProbeStats.cpp
 *
 *  Created on: Feb 1, 2017
 *      Author: Debashis
 */

#include <ctime>
#include "ProbeStats.h"

ProbeStats::ProbeStats()
{ }

ProbeStats::~ProbeStats()
{ }

void ProbeStats::run()
{
	char buffer[80];
	uint16_t printloopCnt 	= 0;

	long startTime 		= 0;
	long runTime 		= 0;

	int dd = 0, hh = 0, mm = 0, ss = 0;

	gettimeofday(&curTime, NULL);
	startTime = curTime.tv_sec;

	bool isStatsInitialized = false;

	while(IPGlobal::PROBE_STATS_RUNNING_STATUS)
	{
		sleep(1);

		if(IPGlobal::PRINT_STATS_FREQ_SEC > 0 && IPGlobal::PRINT_STATS)
		{
			printloopCnt++;

			gettimeofday(&curTime, NULL);
			now_tm = localtime(&curTime.tv_sec);
			runTime = curTime.tv_sec - startTime;

			dd = (int)(runTime / 84600);
			hh = (int)((runTime - (dd * 84600)) / 3600);
			mm = (int)((runTime - ((dd * 84600) + (hh * 3600))) / 60);
			ss = (int)(runTime - ((dd * 84600) + (hh * 3600) + (mm * 60)));

			sprintf(buffer, "%03d:%02d:%02d",dd,hh,mm);

			if(printloopCnt >= IPGlobal::PRINT_STATS_FREQ_SEC)
			{
				printloopCnt = 0;
				printInterfaceStats(buffer);
				printCflowSMStats();
				printFortiSMStats();
				printFlusherStats();
				printf("\n\n");
			}
		}
	}
	printf("  ProbeStats Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}


void ProbeStats::printInterfaceStats(char *runTime)
{
	uint16_t tIdx = 0, intf = 0, router = 0;

	printf("\n   %s   [%02d:%02d]         PPS       BW                        T0       T1       T2       T3       T4       T5       T6       T7       T8       T9\n", runTime, now_tm->tm_hour,now_tm->tm_min);

	  for(intf = 0; intf < IPGlobal::NO_OF_INTERFACES; intf ++)
	  {
		  printf("         Interface [%6s]   %08d  %06d             ", IPGlobal::PNAME[intf].c_str(), IPGlobal::PKT_RATE_INTF[intf], IPGlobal::BW_MBPS_INTF[intf]);
		  printf("   ");

		  for(router = 0; router < IPGlobal::ROUTER_PER_INTERFACE[intf]; router++)
		  {
			for(tIdx = 0; tIdx < 10; tIdx++)
				printf("  %07d", PKTStore::pktRepoCnt[intf][router][tIdx]);

			printf("\n");
			printf("                                                              ");
		  }
		  printf("\n");
	  }

}

void ProbeStats::printCflowSMStats()
{
	uint16_t tIdx = 0;
	uint32_t t_cnt[10];

	for(uint32_t i = 0; i < 10; i++)
		t_cnt[i] = 0;

	printf(" %s       [CFlow]      sTotal   sScan    sClean                   ");
	printf("\n");

	for(uint16_t aCnt = 0; aCnt < IPGlobal::NO_OF_CFLOW_SM; aCnt++)
	{
		printf("        SM [%2d]      %07u  %07u  %07u                ", aCnt, IPStats::udpV4SessionTotalCnt[aCnt], IPStats::udpV4SessionScanned[aCnt], IPStats::udpV4SessionCleaned[aCnt]);
		for(tIdx = 0; tIdx < 10; tIdx++)
		{
			for(uint16_t iId = 0; iId < IPGlobal::NO_OF_INTERFACES; iId++)
				for(uint16_t rId = 0; rId < IPGlobal::ROUTER_PER_INTERFACE[iId]; rId++)
					t_cnt[tIdx] += cFlowSM::cFlowSMStoreCnt[aCnt][iId][rId][tIdx];

			printf("  %07u",	t_cnt[tIdx]);
			t_cnt[tIdx] = 0;

		}
		printf("\n");
	}
	printf("\n");
}

void ProbeStats::printFortiSMStats()
{
	uint16_t tIdx = 0;
	uint32_t t_cnt[10];

	for(uint32_t i = 0; i < 10; i++)
		t_cnt[i] = 0;

	printf("\n %s   [FortiGate]      sTotal   sScan    sClean            ");
	printf("\n");

	for(uint16_t aCnt = 0; aCnt < IPGlobal::NO_OF_FORTI_SM; aCnt++)
	{
		printf("       SM [%2d]                                                ", aCnt);
		for(tIdx = 0; tIdx < 10; tIdx++)
		{
			for(uint16_t iId = 0; iId < IPGlobal::NO_OF_INTERFACES; iId++)
				for(uint16_t rId = 0; rId < IPGlobal::ROUTER_PER_INTERFACE[iId]; rId++)
					t_cnt[tIdx] += fortiGwSM::fortiGwSMStoreCnt[aCnt][iId][rId][tIdx];

			printf("  %07u",	t_cnt[tIdx]);
			t_cnt[tIdx] = 0;

		}
		printf("\n");
	}
	printf("\n\n");
}

void ProbeStats::printFlusherStats()
{
	uint16_t tIdx = 0;
	uint32_t t_cnt[10];

	for(uint32_t i = 0; i < 10; i++)
		t_cnt[i] = 0;

	for(int fCnt = 0; fCnt < IPGlobal::NO_OF_FLUSHER; fCnt++)
	{
		printf("       FM [%2d]                                                ",fCnt);
		for(tIdx = 0; tIdx < 10; tIdx++)
		{
			for(int aCnt = 0; aCnt < IPGlobal::NO_OF_CFLOW_SM; aCnt++)
				t_cnt[tIdx] += FlusherStore::udpFlCnt[fCnt][aCnt][tIdx];

			printf("  %07u",	t_cnt[tIdx]);
			t_cnt[tIdx] = 0;
		}
		printf("\n");
	}
	printf("\n\n");
}
