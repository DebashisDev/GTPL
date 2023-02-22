/*
 * SpectaProbe.cpp
 *
 *  Created on: 03-Mar-2022
 *      Author: Debashis
 */

#include <signal.h>

#include "SpectaProbe.h"

/* Signal Catcher Function */

void sig_handler(int signo)
{
	uint16_t cnt = 0;

	if (signo == SIGTERM || signo == SIGINT)
	{
		printf("\n  SpectaProbe Shutdown Initiated...\n");

		for(cnt = 0; cnt < IPGlobal::NO_OF_INTERFACES; cnt++)
			IPGlobal::PACKET_PROCESSING[cnt] = false;

		printf("  Traffic Stopped...\n");
	}
}

int main(int argc, char *argv[])
{
	/* Initialize all the Locks */
	mapDnsLock::count 		= 1;

	if (signal(SIGTERM, sig_handler) == SIG_ERR || signal(SIGINT, sig_handler) == SIG_ERR)
		printf("SpectaProbe Can't Received Signal...\n");

	timeval curTime;
	struct tm *now_tm;

	gettimeofday(&curTime, NULL);
	now_tm = localtime(&curTime.tv_sec);
	IPGlobal::CURRENT_SEC 		= now_tm->tm_sec;
	IPGlobal::CURRENT_MIN 		= now_tm->tm_min;
	IPGlobal::CURRENT_HOUR 		= now_tm->tm_hour;
	IPGlobal::CURRENT_DAY 		= now_tm->tm_mday;
	IPGlobal::CURRENT_MONTH 	= 1 + now_tm->tm_mon;
	IPGlobal::CURRENT_YEAR 		= 1900 + now_tm->tm_year;

	IPGlobal::PROBE_RUNNING_STATUS = true;
	SpectaProbe *spectaProbe = new SpectaProbe("probe.config");
	spectaProbe->start();

	printf("  **** SpectaProbe Exiting...Please wait... ***** \n");
}
