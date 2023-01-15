/*
 * UdpFlusher.cpp
 *
 *  Created on: 18 Mar 2021
 *      Author: Debashis
 */

#include "UdpFlusher.h"

UdpFlusher::UdpFlusher(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "UdpFlusher";
	this->setLogLevel(Log::theLog().level());

	this->readyFlag  	= false;
	this->instanceId 	= id;
	this->lastIndex  	= 0;
	this->curIndex 	 	= 0;
	this->curMin		= 0;
	this->prevMin		= 0;
	this->totalCnt		= 0;
	this->pFlUtility  	= new FUtility();
}

UdpFlusher::~UdpFlusher()
{ delete(pFlUtility); }

bool UdpFlusher::isUdpFlusherReady()
{ return readyFlag; }

void UdpFlusher::run()
{
	readyFlag = true;
	lastIndex = curIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

	curMin = prevMin = IPGlobal::CURRENT_MIN;
	openUdpXdrFile(IPGlobal::CURRENT_MIN, IPGlobal::CURRENT_HOUR, IPGlobal::CURRENT_DAY, IPGlobal::CURRENT_MONTH, IPGlobal::CURRENT_YEAR);

	while(IPGlobal::FLUSHER_RUNNING_STATUS[this->instanceId])
	{
		usleep(IPGlobal::THREAD_SLEEP_TIME);
		curMin = IPGlobal::CURRENT_MIN;

		if(curMin != prevMin && IPGlobal::PROCESS_CFLOW)
		{
			closeUdpXdrFile();
			prevMin = curMin;
			openUdpXdrFile(IPGlobal::CURRENT_MIN, IPGlobal::CURRENT_HOUR, IPGlobal::CURRENT_DAY, IPGlobal::CURRENT_MONTH, IPGlobal::CURRENT_YEAR);
		}

		curIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

		while(lastIndex != curIndex)
		{
			strcpy(udpXdr, "");
			processUdpData(lastIndex);
			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, IPGlobal::TIME_INDEX);
		}
	}
	printf("  Udp [%02d] Flusher Stopped...\n", instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void UdpFlusher::processUdpData(uint16_t idx)
{
	for(uint16_t sm = 0; sm < IPGlobal::NO_OF_CFLOW_SM; sm++)
		flushUdpData(FlusherStore::udpFlCnt[instanceId][sm][idx], FlusherStore::udpFlStore[instanceId][sm][idx]);
}

void UdpFlusher::flushUdpData(uint32_t &flCnt, std::unordered_map<uint32_t, udpSession> &pkt)
{
	totalCnt = flCnt;

	if(totalCnt > 0)
	{
		for (auto it = pkt.cbegin(), next_it = it; it != pkt.cend(); it = next_it)
		{
			if(createUdpXdrData(it->second))
				xdrUdpHandler << std::string(udpXdr) << endl;

			++next_it;
			pkt.erase(it);
			flCnt --;
		}
		flCnt = 0;
	}
}

bool UdpFlusher::createUdpXdrData(udpSession pUdpSession)
{
	if(&pUdpSession == NULL)
		return false;

	udpXdr[0] = 0;
	pFlUtility->buildUdpXdr(&pUdpSession, udpXdr);

	if(strlen(udpXdr) <= 0)
		return false;
	else
		return true;
}

void UdpFlusher::openUdpXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d_%d.csv",
					IPGlobal::XDR_DIR.c_str(),
					"cFlow",
					"cFlow",
					year,
					month,
					day,
					hour,
					min,
					this->instanceId);
	xdrUdpHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void UdpFlusher::closeUdpXdrFile()
{ xdrUdpHandler.close(); }
