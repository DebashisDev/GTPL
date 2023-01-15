#########################################################################
#																		#
# SCRIPT NAME	: probe.mk												#
# DESCRIPTION	: Include script for SpectaProbe						#
# DATE 			: 19-02-2016										    #
# AUTHOR		: Debashis.											    #
#																		#
# Copyright (c) 2016, Pinnacle Digital (P) Ltd. New-Delhi				# 
#########################################################################

#GCC = g++ -g -std=c++11 -Wall -Wno-deprecated -O1 -w

GCC = g++ -g -O0 -g3 -Wall -std=c++11 -fPIC -Wno-deprecated -w

ifeq ($(SF), NO)
	CFLAGS = -D_MT_SAFE -D_REENTRANT -D_POSIX_THREAD_SAFE_FUNCTIONS -D_GNU_SOURCE -D_PTHREADS -D_POSIX_PTHREAD_SEMANTICS -D_POSIX_C_SOURCE=199506L -D__EXTENSIONS__	
else
	CFLAGS = -D_SF -D_MT_SAFE -D_REENTRANT -D_POSIX_THREAD_SAFE_FUNCTIONS -D_GNU_SOURCE -D_PTHREADS -D_POSIX_PTHREAD_SEMANTICS -D_POSIX_C_SOURCE=199506L -D__EXTENSIONS__	
endif

AR 			= ar
ARFLAGS 	= -r
RM 			= rm 
MAKE 		= make

PROBE_BIN	= ${PROBE_ROOT}/bin

# SpectaProbe Directory

CORE_ROOT		= ${PROBE_ROOT}/core
CORE_INC		= ${CORE_ROOT}/inc
CORE_SRC		= ${CORE_ROOT}/src

UDP_ROOT		= ${PROBE_ROOT}/plugins/udp
UDP_INC			= ${UDP_ROOT}/inc
UDP_SRC			= ${UDP_ROOT}/src

TCP_ROOT		= ${PROBE_ROOT}/plugins/tcp
TCP_INC			= ${TCP_ROOT}/inc
TCP_SRC			= ${TCP_ROOT}/src

LOG_ROOT		= ${PROBE_ROOT}/utility/log
LOG_SRC			= ${LOG_ROOT}/src
LOG_INC			= ${LOG_ROOT}/inc

ETH_ROOT		= ${PROBE_ROOT}/packetsource/ethernet
ETH_SRC			= ${ETH_ROOT}/src
ETH_INC			= ${ETH_ROOT}/inc

PCAP_ROOT		= ${PROBE_ROOT}/packetsource/pcap
PCAP_SRC		= ${PCAP_ROOT}/src
PCAP_INC		= ${PCAP_ROOT}/inc

SF_ROOT			= ${PROBE_ROOT}/packetsource/solarflare
SF_SRC			= ${SF_ROOT}/src
SF_INC			= ${SF_ROOT}/inc/solar
SFS_INC			= ${SF_ROOT}/inc/specta

ifeq ($(SF), YES)
	PROBE_INCLUDE 	= \
					-I${CORE_INC} 	\
					-I${LOG_INC} 	\
					-I${ETH_INC} 	\
					-I${PCAP_INC} 	\
					-I${UDP_INC} 	\
					-I${SF_INC}		\
					-I${SFS_INC}
else
	PROBE_INCLUDE 	= \
					-I${CORE_INC} 	\
					-I${LOG_INC} 	\
					-I${ETH_INC} 	\
					-I${PCAP_INC} 	\
					-I${UDP_INC}	\
					-I${TCP_INC}
endif
