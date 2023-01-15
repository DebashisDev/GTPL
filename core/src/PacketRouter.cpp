/*
 * PacketRouter.cpp
 *
 *  Created on: Nov 22, 2016
 *      Author: Debashis
 */

#include <math.h>
#include "PacketRouter.h"

PacketRouter::PacketRouter(uint16_t intfid, uint16_t rid, uint16_t coreid)
{
	this->_name = "PacketRouter   ";
	this->setLogLevel(Log::theLog().level());

	this->intfId 			= intfid;
	this->routerId 			= rid;
	this->coreId 			= coreid;
	this->repoInitStatus	= false;
	this->curMin			= 0;
	this->prevMin			= 0;
	this->curHour			= 0;
	this->prevHour			= 0;
	this->printCnt 			= 0;
	this->tcpAgentId		= 0;
	this->udpAgentId		= 0;

	this->MAX_PKT_LEN 		= IPGlobal::MAX_PKT_LEN_PER_INTERFACE[this->intfId];

	this->ethParser 		= new EthernetParser(intfId, routerId);
	this->hdrInfo 			= new headerInfo();
	this->rawPkt 			= new RawPkt(MAX_PKT_LEN);
}

PacketRouter::~PacketRouter()
{
	delete(this->ethParser);
	delete(this->hdrInfo);
	delete(this->rawPkt);
}

bool PacketRouter::isRepositoryInitialized()
{ return repoInitStatus; }

void PacketRouter::run()
{
	uint16_t lastTIndex, currTIndex;

	curMin = prevMin = IPGlobal::CURRENT_MIN;
	curHour = prevHour = IPGlobal::CURRENT_HOUR;

	lastTIndex = currTIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

	repoInitStatus = true;

	while(IPGlobal::ROUTER_RUNNING_STATUS[intfId][routerId])
	{
		usleep(IPGlobal::THREAD_SLEEP_TIME);

		currTIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC,IPGlobal::TIME_INDEX);

		curMin = IPGlobal::CURRENT_MIN;

		while(lastTIndex != currTIndex)
		{
			processQueue(lastTIndex);
			lastTIndex = PKT_READ_NEXT_TIME_INDEX(lastTIndex, IPGlobal::TIME_INDEX);
		}
	}
	printf("  PacketRouter [%d::%d] Stopped...\n",intfId, routerId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void PacketRouter::processQueue(uint16_t idx)
{ processQueueDecode(PKTStore::pktRepoBusy[intfId][routerId][idx], PKTStore::pktRepoCnt[intfId][routerId][idx], PKTStore::pktRepository[intfId][routerId][idx]); }

void PacketRouter::processQueueDecode(bool &pktRepository_busy, uint32_t &pktRepository_cnt, std::unordered_map<uint32_t, RawPkt*> &pktRepository)
{
	uint32_t recCnt = pktRepository_cnt;
	pktRepository_busy = true;

	if(recCnt > 0)
	{
		for(uint32_t i = 0; i < recCnt; i++)
		{
			decodePacket(pktRepository[i]);
			pktRepository_cnt--;
		}
		pktRepository_cnt = 0;
		recCnt = 0;
	}
	pktRepository_busy = false;
}

void PacketRouter::decodePacket(RawPkt* rawPkt)
{
	if(rawPkt->pkt != NULL)
	{
		hdrInfo->reset();

		hdrInfo->pckLen = rawPkt->len;
	    ethParser->parsePacket(rawPkt->pkt, hdrInfo);
	}
}
