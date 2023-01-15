#########################################################################
#																		#
# SCRIPT NAME	: Makefile												#
# DESCRIPTION	: To build the SpectaProbe along with user librarys		#
# DATE 			: 19-02-2016										    #
# AUTHOR		: Debashis.											    #
#																		#
# To make GN probe : make gnclean; make gnprobe 						#
# To make FL probe : make flclean; make flprobe 						#
# Copyright (c) 2016, Pinnacle Digital (P) Ltd. New-Delhi.				# 
#########################################################################

# Include all the header directories.
include ${PROBE_ROOT}/probe.mk

ifeq ($(SF), YES)
	PROBE_DIRS = 	\
		${CORE_SRC} \
		${LOG_SRC} 	\
		${SF_SRC} 	\
		${ETH_SRC} 	\
		${UDP_SRC}
else
	PROBE_DIRS = 	\
		${CORE_SRC} \
		${LOG_SRC} 	\
		${ETH_SRC} 	\
		${UDP_SRC}	\
		${TCP_SRC}
endif		

#########################################################################
# SCP Platform and Platform Library File Name							#
#########################################################################
PROBE_TARGET = ${PROBE_BIN}/spectaProbe

#System Library
PCAPLIB 	= pcap
THRLIB 		= pthread
ZMQLIB 		= zmq
SOLARLIB	= ${PROBE_ROOT}/lib/libciul.so

LIBS 		= -lm -ldl -l$(PCAPLIB) -l$(THRLIB)

#########################################################################
# For SpectaProbe
#########################################################################
probe:
	echo ${PROBE_DIRS}
	for i in ${PROBE_DIRS}; \
	do \
		(cd $$i; \
		echo "*******" $$i; \
		${MAKE} all \
		); \
	done

ifeq ($(SF), YES)
	${GCC} -o ${PROBE_TARGET} ${SOLARLIB}	\
				${CORE_SRC}/*.o 	\
				${LOG_SRC}/*.o 		\
				${SF_SRC}/*.o 		\
				${ETH_SRC}/*.o 		\
				${UDP_SRC}/*.o 		\
				${LIBS}
else
	${GCC} -o ${PROBE_TARGET}		\
				${CORE_SRC}/*.o 	\
				${LOG_SRC}/*.o 		\
				${ETH_SRC}/*.o 		\
				${UDP_SRC}/*.o 		\
				${TCP_SRC}/*.o 		\
				${LIBS}
endif

#########################################################################

clean:
	for i in ${PROBE_DIRS}; \
	do \
		(cd $$i; \
		echo $$i; \
		${MAKE} clean \
		); \
	done

	${RM} ${PROBE_TARGET}
	
