/*
 * Agent.h
 *
 *  Created on: 12 Mar 2022
 *      Author: debas
 */

#ifndef PLUGINS_UDP_SRC_AGENT_H_
#define PLUGINS_UDP_SRC_AGENT_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include "SpectaTypedef.h"
#include "IPGlobal.h"
#include "BaseConfig.h"
#include <sstream>
#include "UdpSMInterface.h"

class CflowSM
{
	private:
		bool		agentInitStatus;
		uint16_t 	smId, lastIndex, curIndex, flusherId;
		uint16_t 	curIndexClnUp, lastIndexClnUp;

		UdpSMInterface	*UdpInterface;

		stringstream 	ss;

		uint16_t	curMin;
		uint16_t	prevMin;

		void		processQueue(uint16_t tIdx);
		void		pushToCflowSMInterface(uint32_t &cnt, std::unordered_map<uint32_t, cFlow**> &data);

	public:
		CflowSM(uint16_t agentId);
		~CflowSM();

		bool 	isRepositoryInitialized();
		void 	run();
};

#endif /* PLUGINS_UDP_SRC_AGENT_H_ */
