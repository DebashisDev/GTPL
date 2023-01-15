/*
 * Agent.cpp
 *
 *  Created on: 12 Mar 2022
 *      Author: Debashis
 */

#include "CflowSM.h"

CflowSM::CflowSM(uint16_t agentId)
{
	this->smId			= agentId;
	this->lastIndex 		= 0;
	this->curIndex 			= 0;
	this->curMin			= 0;
	this->prevMin			= 0;
	this->flusherId 		= 0;
	this->agentInitStatus 	= false;
	this->curIndexClnUp 	= 0;
	this->lastIndexClnUp 	= 0;
	this->UdpInterface 		= new UdpSMInterface(this->smId);
}

CflowSM::~CflowSM()
{
	delete(this->UdpInterface);
}

bool CflowSM::isRepositoryInitialized()
{ return agentInitStatus; }



void CflowSM::run()
{
	agentInitStatus = true;

	curMin = prevMin = IPGlobal::CURRENT_MIN;

	lastIndex = curIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

	while(IPGlobal::CFLOW_SM_RUNNING_STATUS[smId])
	{
		usleep(IPGlobal::THREAD_SLEEP_TIME);
		curIndexClnUp = IPGlobal::CURRENT_SEC / IPGlobal::SESSION_SCAN_FREQ_SEC;
		curIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC,IPGlobal::TIME_INDEX);

		curMin = IPGlobal::CURRENT_MIN;

		while(lastIndex != curIndex)
		{
			processQueue(lastIndex);
			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, IPGlobal::TIME_INDEX);
		}

		if(curIndexClnUp != lastIndexClnUp)
		{
			UdpInterface->udpTimeOutClean();	// UDP Session Cleanup
			lastIndexClnUp = curIndexClnUp;
		}
	}
	printf("  cFlow SM Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void CflowSM::processQueue(uint16_t tIdx)
{
	for(uint16_t iId = 0; iId < IPGlobal::NO_OF_INTERFACES; iId++)
		for(uint16_t rId = 0; rId < IPGlobal::ROUTER_PER_INTERFACE[iId]; rId++)
			pushToCflowSMInterface(cFlowSM::cFlowSMStoreCnt[smId][iId][rId][tIdx], cFlowSM::cFlowSMStore[smId][iId][rId][tIdx]);

}

void CflowSM::pushToCflowSMInterface(uint32_t &cnt, std::unordered_map<uint32_t, cFlow**> &data)
{
	uint32_t recordCnt = cnt;

	if(recordCnt > 0)
	{
		for (auto it = data.cbegin(), next_it = it; it != data.cend(); it = next_it)
		{
			UdpInterface->UDPPacketEntry(it->second);

			++next_it;
			data.erase(it);
			cnt--;
		}
		cnt = 0;
	}
}
