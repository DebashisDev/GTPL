/*
 * FortiSM.cpp
 *
 *  Created on: 24 Oct 2022
 *      Author: debas
 */

#include "FortiSM.h"

FortiSM::FortiSM(uint16_t smId)
{
	this->instanceId		= smId;
	this->lastIndex 		= 0;
	this->curIndex 			= 0;
	this->curMin			= 0;
	this->prevMin			= 0;
	this->flusherId 		= 0;
	this->agentInitStatus 	= false;
	this->curIndexClnUp 	= 0;
	this->lastIndexClnUp 	= 0;
}

FortiSM::~FortiSM()
{ }

bool FortiSM::isRepositoryInitialized()
{ return agentInitStatus; }

void FortiSM::run()
{
	agentInitStatus = true;

	curMin = prevMin = IPGlobal::CURRENT_MIN;
	lastIndex = curIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC, IPGlobal::TIME_INDEX);

	openFortiXdrFile(IPGlobal::CURRENT_MIN, IPGlobal::CURRENT_HOUR, IPGlobal::CURRENT_DAY, IPGlobal::CURRENT_MONTH, IPGlobal::CURRENT_YEAR);

	while(IPGlobal::FORTI_SM_RUNNING_STATUS[instanceId])
	{
//		usleep(IPGlobal::THREAD_SLEEP_TIME);
		usleep(2500);

		curMin = IPGlobal::CURRENT_MIN;

		if(curMin != prevMin && IPGlobal::PROCESS_FORTI)
		{
			closeFortiXdrFile();
			prevMin = curMin;
			openFortiXdrFile(IPGlobal::CURRENT_MIN, IPGlobal::CURRENT_HOUR, IPGlobal::CURRENT_DAY, IPGlobal::CURRENT_MONTH, IPGlobal::CURRENT_YEAR);
		}

		curIndex = PKT_READ_TIME_INDEX(IPGlobal::CURRENT_EPOCH_SEC,IPGlobal::TIME_INDEX);


		while(lastIndex != curIndex)
		{
			processQueue(lastIndex);
			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, IPGlobal::TIME_INDEX);
		}
	}
	printf("  Forti SM Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void FortiSM::processQueue(uint16_t tIdx)
{
	for(uint16_t iId = 0; iId < IPGlobal::NO_OF_INTERFACES; iId++)
		for(uint16_t rId = 0; rId < IPGlobal::ROUTER_PER_INTERFACE[iId]; rId++)
			writeXDR(fortiGwSM::fortiGwSMStoreCnt[instanceId][iId][rId][tIdx], fortiGwSM::fortiGwSMStore[instanceId][iId][rId][tIdx]);
}

void FortiSM::writeXDR(uint32_t &cnt, std::unordered_map<uint32_t, string> &data)
{
	uint32_t recCnt = cnt;

	if(recCnt > 0)
	{
		for (auto it = data.cbegin(), next_it = it; it != data.cend(); it = next_it)
		{
			decodeFortiGate(it->second);
			++next_it;
			data.erase(it);
			cnt --;
		}
		cnt = 0;
	}
}

void FortiSM::decodeFortiGate(string data)
{
	vector<string> queue;
	uint8_t find = 0, index = 0;
	fortiGate t_array;
	std::stringstream ss;
	string lan = "LAN";
	uint32_t ipLong = 0;
	uint32_t noOfSecPerDay = 86400;

	first.clear();
	second.clear();
	temp.clear();
	t_array.reset();

	std::stringstream tok(data);

	while(getline(tok, temp, ' '))
		queue.push_back(temp);

	try
	{
		for (auto& it : queue)
		{
			index = it.find("=");
			first = it.substr(0, index);

			if((first.compare("timestamp")) == 0)
				t_array.sEpochSec = it.substr(index+1, it.length());

			if(first.compare("subtype") == 0)
			{
				t_array.subType = it.substr(index+1, it.length());
				find = t_array.subType.find("ward");
			}

			if((first.compare("devname")) == 0)
			{
				second = it.substr(index+1, it.length());
				index = second.find("_");

				t_array.location = second.substr(0, index);
				t_array.location.erase(0, 1);
			}

			if((first.compare("srcip")) == 0)
				t_array.srcIpv6 = it.substr(index+1, it.length());

			if((first.compare("srcport")) == 0)
				t_array.srcPort = it.substr(index+1, it.length());

			if((first.compare("srcintf")) == 0) {
				t_array.srcintf = it.substr(index+1, it.length());
				t_array.srcintf.erase(0, 1);
				t_array.srcintf.erase(t_array.srcintf.size() - 1);
			}

			if((first.compare("dstip")) == 0)
				t_array.dstIpv6 = it.substr(index+1, it.length());

			if((first.compare("dstport")) == 0)
				t_array.dstPort = it.substr(index+1, it.length());

			if((first.compare("dstintf")) == 0) {
				t_array.dstintf = it.substr(index+1, it.length());
				t_array.dstintf.erase(0, 1);
				t_array.dstintf.erase(t_array.dstintf.size() - 1);
			}
//			if((first.compare("sessionid")) == 0)
//				t_array.sessionId = it.substr(index+1, it.length());

			if((first.compare("proto")) == 0)
					t_array.protocol = it.substr(index+1, it.length());

			if((first.compare("transip")) == 0)
				t_array.transIp = it.substr(index+1, it.length());

			if((first.compare("duration")) == 0)
				t_array.duration = it.substr(index+1, it.length());

			if((first.compare("rcvdbyte")) == 0)
				t_array.recByte = it.substr(index+1, it.length());

			if((first.compare("sentbyte")) == 0)
				t_array.sendByte = it.substr(index+1, it.length());
		}

		// -----  in cFlow
		//   Direction is 0 -> DstAddr is the User IP


		//  Consider the packet having srcintf="LAN" or dstintf="LAN"
		//  if srcintf="LAN" do nothing.
		//  if dstintf="LAN" then swap Source IP with Dest IP, Source Port with Dest port, and sendByte to recvByte

		if(find == 0) // if subtype is "forward" the process or ignore.
		{ return; }

		if(t_array.duration.length() == 0)
		{ return; }

		if(atoi(t_array.recByte.c_str()) == 0 && atoi(t_array.sendByte.c_str()) == 0)
		{ return; }

		index =  t_array.location.find("-");
		t_array.location = t_array.location.substr(0, index);

		if(t_array.location.compare("GTPL") == 0 || t_array.location.compare("FortiGate") == 0)
		{ return; }


		// If Transip is there then transip, srource Ip needs to be replayed with transip.
		if(t_array.transIp.length() > 0)
		{
			ipToLong((char *)t_array.transIp.c_str(), &ipLong);

			if(checkStaticIP(&ipLong))
				t_array.srcIpv6 = t_array.transIp;
		}
		else if(t_array.srcintf.find(lan) == 0)
		{
			// Process The Packet
		}
		else
		{
			return;
		}

		/* ------------------------------------------------------ */
		/* Calculate No. of Days */

		uint32_t sendByte = 0, recvByte = 0;
		uint32_t days = atol(t_array.duration.c_str()) / noOfSecPerDay;

		uint32_t startTime = (stol(t_array.sEpochSec, nullptr, 10) - atol(t_array.duration.c_str()));

		if(days >= 1)
		{
			sendByte =  atol(t_array.sendByte.c_str()) / days;
			recvByte =  atol(t_array.recByte.c_str()) / days;

			for(uint16_t day = 0; day < days; day++)
			{
				ss << startTime << "," << t_array.location << "," << t_array.srcIpv6 << "," << t_array.srcPort << ","
				   << t_array.dstIpv6 << "," << t_array.dstPort << "," << recvByte << "," << sendByte << "," << t_array.protocol << "," << t_array.duration;

				startTime = startTime + noOfSecPerDay;

				std::string xdr = ss.str();
				xdrFortiHandler << xdr << endl;
				ss.clear();
				ss.str("");
			}
		}
		else
		{
//			sendByte =  atol(t_array.sendByte.c_str());
//			recvByte =  atol(t_array.recByte.c_str());

//			if(sendByte < 100 && recvByte < 100)
//			{ return; }

			ss << startTime << "," << t_array.location << "," << t_array.srcIpv6 << "," << t_array.srcPort << ","
					<< t_array.dstIpv6 << "," << t_array.dstPort << "," << t_array.recByte << "," << t_array.sendByte << "," << t_array.protocol << "," << t_array.duration;

			std::string xdr = ss.str();
			xdrFortiHandler << xdr << endl;
		}
	}
	catch(...)
	{
		return;
	}
}

bool FortiSM::checkStaticIP(uint32_t *ip)
{
	std::map<uint32_t, uint16_t>::iterator it1 = initSection::staticIpPoolMap.find(*ip);
	if(it1 != initSection::staticIpPoolMap.end())
	{
		return true;
	}
	return false;
}

uint32_t FortiSM::ipToLong(char *ip, uint32_t *plong)
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



void FortiSM::openFortiXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d_%d.csv",
					IPGlobal::XDR_DIR.c_str(),
					"forti",
					"forti",
					year,
					month,
					day,
					hour,
					min,
					this->instanceId);
	xdrFortiHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void FortiSM::closeFortiXdrFile()
{ xdrFortiHandler.close(); }


//		else if(t_array.srcintf.find(valid) == 0  || t_array.dstintf.find(valid) == 0)
//		{
//
//			if(t_array.dstintf.find(valid) == 0) // Swap the Source and Destination values
//			{
//				string ip = t_array.srcIpv6;
//				string port = t_array.srcPort;
//				string byte = t_array.sendByte;
//
//				t_array.srcIpv6 = t_array.dstIpv6;
//				t_array.srcPort = t_array.dstPort;
//
//				t_array.dstIpv6 = ip;
//				t_array.dstPort = port;
//
//				t_array.sendByte = t_array.recByte;
//				t_array.recByte = byte;
//			}
//		}
