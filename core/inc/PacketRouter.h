/*
 * PacketRouter.h
 *
 *  Created on: Nov 22, 2016
 *      Author: Debashis
 */

#ifndef CORE_SRC_PACKETROUTER_H_
#define CORE_SRC_PACKETROUTER_H_

#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "SpectaTypedef.h"

#include "EthernetParser.h"
#include "BaseConfig.h"
#include "IPGlobal.h"
#include "Log.h"

struct pcapPkthdr
{
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

class PacketRouter : public BaseConfig
{
	public:

		PacketRouter(uint16_t intfid, uint16_t rid, uint16_t coreid);
		~PacketRouter();

		bool isRepositoryInitialized();
		void run();

	private:

		uint16_t 	intfId, routerId, coreId, tcpAgentId, udpAgentId;
		uint16_t	curMin, prevMin, curHour, prevHour, printCnt;
		uint16_t 	MAX_PKT_LEN;
		bool 		repoInitStatus;

		headerInfo*	hdrInfo;
		RawPkt*		rawPkt;

		EthernetParser*	ethParser;

		void processQueue(uint16_t t_index);

		void processQueueDecode(bool &pktRepository_busy, uint32_t &pktRepository_cnt, std::unordered_map<uint32_t, RawPkt*> &pktRepository);

		void 	decodePacket(RawPkt* rawPkt);
		void 	pushUdpToAgentQueue(headerInfo *hdrInfo);
};

#endif /* CORE_SRC_PACKETROUTER_H_ */
