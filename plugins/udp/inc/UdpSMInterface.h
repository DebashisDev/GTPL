/*
 * UdpSMInterface.h
 *
 *  Created on: 18 Mar 2021
 *      Author: Debashis
 */

#ifndef PLUGINS_UDP_SRC_UDPSMINTERFACE_H_
#define PLUGINS_UDP_SRC_UDPSMINTERFACE_H_

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <string>

#include "IPGlobal.h"
#include "SmGlobal.h"
#include "SpectaTypedef.h"
#include "Log.h"
#include "BaseConfig.h"
#include "Initialize.h"
#include "FUtility.h"

#define 	UP		1
#define		DOWN	0

using namespace std;

class UdpSMInterface : BaseConfig
{
	private:

			bool vpsFlag = true;
			std::string ipV6Key;
			uint16_t flusherNo = 0;
			uint16_t instanceId = 0, location = 0;
			FUtility	*pFUtility;

			uint32_t udpFreeBitPos  = 0;
			uint32_t udpFreeBitPosMax = 0;
			std::bitset<UDP_SESSION_POOL_ARRAY_ELEMENTS> udpBitFlagsSession[UDP_SESSION_POOL_ARRAY_SIZE];
			std::map<uint32_t, udpSession*> udpSessionPoolMap[UDP_SESSION_POOL_ARRAY_SIZE];
			uint32_t 	udpGetFreeIndex();
			void 	udpReleaseIndex(uint32_t idx);
			void 	udpInitializeSessionPool();
			udpSession* udpGetSessionFromPool(uint32_t idx);
			uint32_t sessionCleanCnt;

			std::map<uint64_t, uint32_t> udpV4SessionMap[UDP_SESSION_POOL_ARRAY_ELEMENTS];
			std::map<std::string, uint32_t> udpV6SessionMap[UDP_SESSION_POOL_ARRAY_ELEMENTS];

			udpSession* 	udpGetSession(cFlow *pcFlow, bool *found, bool create);

			uint16_t 		checkSanityDestIp(udpSession *pUdpSession);
			bool 			IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask);

			void 			udpEraseSession(udpSession *pUdpSession);

			void 			udpFlushSession(udpSession *pUdpSession, bool erase);
			void 			udpStoreSession(uint16_t index, udpSession *pUdpSession);

			void 			udpCleanSession(udpSession *pUdpSession);

			void			timeStampArrivalPacket(udpSession *pUdpSession, uint64_t epochSec);
			void			updateTime(udpSession *pUdpSession, int id);

			uint32_t		getMapIndexAndSessionKey(cFlow *pcFlow, uint64_t *sessionKey);

			void 			initializeUdpSession(udpSession *pUdpSession, cFlow *pcFlow);
			void			updateUdpSession(udpSession *pUdpSession, cFlow *pcFlow);

			void 			checkStaticIP(udpSession *pUdpSession);

	public:
			UdpSMInterface(uint16_t id);
			~UdpSMInterface();

			void 	UDPPacketEntry(cFlow **pcFlow);

			void 	udpTimeOutClean();
			void 	udpV4SessionCount();
			void 	udpV6SessionCount();
};

#endif /* PLUGINS_UDP_SRC_UDPSMINTERFACE_H_ */
