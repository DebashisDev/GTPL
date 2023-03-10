/*
 * ProbeStats.h
 *
 *  Created on: Feb 1, 2017
 *      Author: Debashis
 */

#ifndef CORE_SRC_PROBESTATS_H_
#define CORE_SRC_PROBESTATS_H_

#include <unistd.h>
#include <locale.h>
#include <time.h>
#include <sys/time.h>

#include "IPGlobal.h"
#include "SpectaTypedef.h"
#include "Log.h"

class ProbeStats
{
	public:
		ProbeStats();
		~ProbeStats();

		void run();

	private:
		timeval curTime;
		struct tm *now_tm;

		void printInterfaceStats(char *runTime);
		void printCflowSMStats();
		void printFortiSMStats();
		void printFlusherStats();
};

#endif /* CORE_SRC_PROBESTATS_H_ */
