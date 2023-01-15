/*
 * FortiSM.h
 *
 *  Created on: 24 Oct 2022
 *      Author: debas
 */

#ifndef PLUGINS_UDP_SRC_FORTISM_H_
#define PLUGINS_UDP_SRC_FORTISM_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <iterator>

#include "SpectaTypedef.h"
#include "IPGlobal.h"
#include "BaseConfig.h"
#include <sstream>

class FortiSM
{
	private:
		bool		agentInitStatus;
		uint16_t 	instanceId, lastIndex, curIndex, flusherId;
		uint16_t 	curIndexClnUp, lastIndexClnUp;
		uint16_t	curMin;
		uint16_t	prevMin;
		std::string first, second, temp;
		fstream		xdrFortiHandler;

		uint32_t 	ipToLong(char *ip, uint32_t *plong);
		bool 		checkStaticIP(uint32_t *ip);

		void		processQueue(uint16_t tIdx);
		void 		decodeFortiGate(string data);
		void		writeXDR(uint32_t &cnt, std::unordered_map<uint32_t, string> &data);

		void 		openFortiXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year);
		void 		closeFortiXdrFile();


	public:
		FortiSM(uint16_t agentId);
		~FortiSM();

		bool 	isRepositoryInitialized();
		void 	run();
};

#endif /* PLUGINS_UDP_SRC_FORTISM_H_ */
