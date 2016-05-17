#ifndef _ATTACK_H_
#define _ATTACK_H_



#include "dnsattack_base.h"

struct attackM_st
{
	char *attackIp;
	char *attackPort;
	int pthread_id;
	ddosConfig *ddosc;
};

int newthread(struct attackM_st attackM);


/********************************************************************************/
/* 获得各线程发送包数之和                                                       */
/* 返回:包数总和                                                                */
/********************************************************************************/
unsigned long getSendPackageNum(int startThreadNumber);

/********************************************************************************/
/* 获得各线程发送Byte之和                                                       */
/* 返回:流量Byte总和                                                            */
/********************************************************************************/
unsigned long getSendByte(int startThreadNumber);

#endif

