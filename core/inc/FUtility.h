/*
 * FlusherUtility.h
 *
 *  Created on: 18 Mar 2021
 *      Author: Debashis
 */

#ifndef CORE_SRC_FLUSHERUTILITY_H_
#define CORE_SRC_FLUSHERUTILITY_H_

#include <unistd.h>

#include "IPGlobal.h"

#define IPV6_PREFIX_LAN		19

using namespace std;

class FUtility
{
	private:
			char 		userIp[IPV6_ADDR_LEN];
			char		userIdChar[IPV6_ADDR_LEN];

			void 		lockDnsMap();
			void 		unLockDnsMap();

			void 		lockAAAMap();
			void 		unLockAAAMap();

			void 		formateIPv6(char *buffer);

			bool 		someUdpChecks(udpSession *pUdpSession);

			void		swap3(uint64_t *a, uint64_t *b, uint64_t *c);
			void		swap4(uint64_t *a, uint64_t *b, uint64_t *c,  uint64_t *d);

			string 		getURLLookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap);
			string		findDns(uint32_t dIp);

			void		getPrivateIP(udpSession *pUdpSession);
	public:
			FUtility();
			~FUtility();

			void 		buildUdpXdr(udpSession *pUdpSession, char *csvXDR);
			void 		buildDnsXdr(dnsSession *pDnsSession, char *csvXDR);

			bool 		checkNewLine(char *s);

			string		getResolvedIp4(uint32_t dIp);
			void		buildAaaXdr(aaaSession *pRadiusSession, char *xdr, bool *errorXdr);
			uint32_t 	getV4UserId(uint32_t &sourceIP, char* userId);
			void		tcpGetV6UserId(char *sourceIp, char *destIp, char* userId, char* userPlan, char* userProfile, char* userMac, char* userOlt);
};

#endif /* CORE_SRC_FLUSHERUTILITY_H_ */
