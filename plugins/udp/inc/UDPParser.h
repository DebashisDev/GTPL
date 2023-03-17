/*
 * PUDP.h
 *
 *  Created on: Nov 29, 2015
 *      Author: Debashis
 */

#ifndef INC_UDPPROBE_H_
#define INC_UDPPROBE_H_

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "IPGlobal.h"
#include "Log.h"
#include "time.h"
#include "DnsData.h"
#include "SpectaTypedef.h"

#define DIRECTION_LEN	1
#define PORT_LEN		2
#define IPv4_LEN		4
#define IPv6_LEN		16
#define AS_LEN			4
#define PLOAD_LEN		8
#define DURATION_LEN	8

#define A				1
#define AAAA			28

using namespace std;

class UDPParser : public DnsData
{
	private:
		uint16_t 	iId, rId, cFlowSm, fortiSm, valueLoop, locationId;
		uint32_t 	timeStamp, publicIpLong, privateIpLong, dnsIp;
		uint16_t 	len, lenToProcess, lenProcessed, flowSetId, noOfFlowId, flowSetLen;
		BYTE 		buffer;
		uint8_t 	noOffGateFlows = 1;
		std::string first, second, data, temp;
		std::string privateIp;
		ofstream    outFile;
		char 		dnsFilePath[300];


		void		decodeNetFlow(const BYTE packet, headerInfo *hdrObj);
		uint16_t 	decodeFlowSet(const BYTE packet);
		void 		hexDump(const void* pv, uint16_t len);

		void		decodeForti(const BYTE packet, headerInfo *hdrObj);
		void		parseMapping(const BYTE packet, headerInfo *hdrObj, uint16_t *locator);
		uint32_t 	ipToLong(char *ip, uint32_t *plong);
		void		updatedns(uint32_t sIp,uint32_t dIp);
		uint32_t 	longToIp(uint32_t sIp , char *ipAddress);

		void		decordFlowId(const BYTE packet, uint16_t* noOfFlows, uint8_t version);
		uint16_t 	extractValues(const BYTE packet, uint8_t protocol, uint16_t *count, cFlow** t_array);

		uint16_t 	ExtractIP4Address(const BYTE packet, uint32_t *ip, uint16_t *offset);
		static uint16_t	ExtractIP6Address(const BYTE packet, char *ipBuffer, uint16_t *loc);

		uint16_t	getOctets(const BYTE packet, uint32_t *payLoad, uint16_t *offset);
		uint16_t	getDuration(const BYTE packet, double *duration, uint16_t *offset);
		uint16_t	getPort(const BYTE packet, uint16_t *port, uint16_t *offset);
		uint16_t	getDirection(const BYTE packet, uint8_t *direction, uint16_t *offset);
		uint16_t	getAS(const BYTE packet, uint32_t *as, uint16_t *offset);
		void 		display(cFlow** t_array);

		uint32_t 	HextoDigits(char *hexadecimal);

		void		pushToXdrAgentV4(cFlow** t_array);
		void 		copyMsgObj(uint32_t &cnt, std::unordered_map<uint32_t, cFlow> &msg, cFlow *msgObj);

		void		pushToFortiGWAgent(string xdr);

//		char 		URL[50];
		static bool	parsePacketDNSQueries(uint32_t, uint32_t, const BYTE, uint16_t *retPos, uint16_t dnsLen, char* URL);
		static string 	read_rr_name(const uint8_t *packet, uint32_t *packet_p, uint32_t id_pos, uint16_t len);
		static void	parsePacketDNSAnswers(uint16_t pos, const BYTE packet, uint16_t ancount, char* URL);
		bool 	IsIPInRange(uint32_t ip, uint32_t network, uint32_t mask);

	public:

		UDPParser(uint16_t intfId, uint16_t routerId);
		~UDPParser();

		void		parseUDPPacket(const BYTE packet, headerInfo *hdrObj);
		void		parseFortiPacket(const BYTE packet, headerInfo *hdrObj);
		uint64_t 	parsePacketDNS(const BYTE packet, uint16_t dnsLen, dnsHdrIp *info);
		void		parseMappingPacket(const BYTE packet, headerInfo *hdrObj, uint16_t *locator);

		static void	lockDnsMap();
		static void	unLockDnsMap();
};

#endif	/* INC_UDPPROBE_H_ */
